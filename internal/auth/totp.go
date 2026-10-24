package auth

import (
	"context"
	"crypto/subtle"
	"net/url"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

const totpPeriod = 30

func totpAAD(id uuid.UUID) []byte { return []byte("totp:" + id.String()) }

// BeginTOTP generates and stores a sealed secret (not yet enabled) and returns the otpauth URL.
func (s *Users) BeginTOTP(ctx context.Context, id uuid.UUID) (string, error) {
	u, err := s.ByID(ctx, id)
	if err != nil {
		return "", err
	}
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "secure-exchange", AccountName: u.Email})
	if err != nil {
		return "", err
	}
	sealed, err := s.keys.Seal([]byte(key.Secret()), totpAAD(id))
	if err != nil {
		return "", err
	}
	tag, err := s.pool.Exec(ctx, `UPDATE users SET totp_secret_sealed=$2, totp_last_step=0 WHERE id=$1 AND NOT totp_enabled`, id, sealed)
	if err != nil {
		return "", err
	}
	if tag.RowsAffected() == 0 { // user existed above, so it is enrolled already
		return "", ErrTOTPAlreadyEnabled
	}
	return key.URL(), nil
}

// EnableTOTP turns TOTP on if code is valid for the pending secret.
func (s *Users) EnableTOTP(ctx context.Context, id uuid.UUID, code string) error {
	if !s.CheckTOTP(ctx, id, code) {
		return ErrBadCode
	}
	_, err := s.pool.Exec(ctx, `UPDATE users SET totp_enabled=true WHERE id=$1`, id)
	return err
}

// CheckTOTP accepts a code within ±1 step, once per step (replay-protected).
func (s *Users) CheckTOTP(ctx context.Context, id uuid.UUID, code string) bool {
	var sealed []byte
	if err := s.pool.QueryRow(ctx, `SELECT totp_secret_sealed FROM users WHERE id=$1`, id).Scan(&sealed); err != nil || sealed == nil {
		return false
	}
	secret, err := s.keys.Open(sealed, totpAAD(id))
	if err != nil {
		return false
	}
	now := time.Now().Unix() / totpPeriod
	match := int64(-1)
	for step := now - 1; step <= now+1; step++ {
		want, err := totp.GenerateCodeCustom(string(secret), time.Unix(step*totpPeriod, 0),
			totp.ValidateOpts{Period: totpPeriod, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
		if err == nil && subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			match = step
		}
	}
	if match < 0 {
		return false
	}
	tag, err := s.pool.Exec(ctx, `UPDATE users SET totp_last_step=$2 WHERE id=$1 AND totp_last_step < $2`, id, match)
	return err == nil && tag.RowsAffected() == 1
}

// secretFromURL extracts the secret query parameter of an otpauth URL.
func secretFromURL(u string) string {
	p, err := url.Parse(u)
	if err != nil {
		return ""
	}
	return p.Query().Get("secret")
}
