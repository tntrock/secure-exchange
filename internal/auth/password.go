// Package auth implements users, passwords, TOTP and request-scoped user context.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

var (
	ErrNotFound           = errors.New("auth: not found")
	ErrBadCode            = errors.New("auth: bad code")
	ErrWeakPassword       = errors.New("auth: password too weak")
	ErrEmailTaken         = errors.New("auth: email taken")
	ErrTOTPAlreadyEnabled = errors.New("auth: totp already enabled")
)

const (
	argonTime    = 3
	argonMemory  = 64 * 1024
	argonThreads = 4
	argonKeyLen  = 32
	argonSaltLen = 16
	minPwLen     = 12
)

// HashPassword returns a PHC-format argon2id hash.
func HashPassword(pw string) (string, error) {
	if len([]rune(pw)) < minPwLen {
		return "", ErrWeakPassword
	}
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	h := argon2.IDKey([]byte(pw), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	b64 := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, argonMemory, argonTime, argonThreads,
		b64.EncodeToString(salt), b64.EncodeToString(h)), nil
}

// VerifyPassword checks pw against an encoded hash using the parameters embedded in it.
func VerifyPassword(encoded, pw string) bool {
	p := strings.Split(encoded, "$")
	if len(p) != 6 || p[1] != "argon2id" {
		return false
	}
	var v int
	var m, t uint32
	var th uint8
	if _, err := fmt.Sscanf(p[2], "v=%d", &v); err != nil || v != argon2.Version {
		return false
	}
	if _, err := fmt.Sscanf(p[3], "m=%d,t=%d,p=%d", &m, &t, &th); err != nil {
		return false
	}
	salt, err1 := base64.RawStdEncoding.DecodeString(p[4])
	want, err2 := base64.RawStdEncoding.DecodeString(p[5])
	// bound cost params so a tampered hash cannot force huge work
	if err1 != nil || err2 != nil || len(want) == 0 || m > 1<<20 || t == 0 || t > 20 || th == 0 {
		return false
	}
	got := argon2.IDKey([]byte(pw), salt, t, m, th, uint32(len(want))) //nolint:gosec // G115: len(want) is the stored hash length (32)
	return subtle.ConstantTimeCompare(got, want) == 1
}
