// Package sxcrypto holds the master keyring and envelope-encryption helpers.
package sxcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const keyLen = 32

// Keyring holds master keys by ID; the active one wraps/seals new data.
type Keyring struct {
	keys   map[int]cipher.AEAD
	active int
}

// ParseKeyring parses "1:<base64 32 bytes>,2:<base64>" and selects activeID.
func ParseKeyring(spec string, activeID int) (*Keyring, error) {
	if strings.TrimSpace(spec) == "" {
		return nil, errors.New("keyring: empty spec")
	}
	r := &Keyring{keys: map[int]cipher.AEAD{}, active: activeID}
	for _, part := range strings.Split(spec, ",") {
		idStr, b64, ok := strings.Cut(strings.TrimSpace(part), ":")
		if !ok {
			return nil, errors.New("keyring: entry must be <id>:<base64>")
		}
		id, err := strconv.Atoi(idStr)
		if err != nil || id <= 0 {
			return nil, fmt.Errorf("keyring: invalid key id %q", idStr)
		}
		if _, dup := r.keys[id]; dup {
			return nil, fmt.Errorf("keyring: duplicate key id %d", id)
		}
		raw, err := base64.StdEncoding.DecodeString(b64)
		if err != nil || len(raw) != keyLen {
			return nil, fmt.Errorf("keyring: key %d must be base64 of %d bytes", id, keyLen)
		}
		block, err := aes.NewCipher(raw)
		if err != nil {
			return nil, err
		}
		if r.keys[id], err = cipher.NewGCM(block); err != nil {
			return nil, err
		}
	}
	if _, ok := r.keys[activeID]; !ok {
		return nil, fmt.Errorf("keyring: active key id %d not found", activeID)
	}
	return r, nil
}

func (r *Keyring) ActiveID() int { return r.active }

// seal returns nonce || ciphertext using the given key.
func seal(g cipher.AEAD, plain, aad []byte) ([]byte, error) {
	nonce := make([]byte, g.NonceSize(), g.NonceSize()+len(plain)+g.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return g.Seal(nonce, nonce, plain, aad), nil
}

func open(g cipher.AEAD, sealed, aad []byte) ([]byte, error) {
	if len(sealed) < g.NonceSize()+g.Overhead() {
		return nil, errors.New("sxcrypto: ciphertext too short")
	}
	n := g.NonceSize()
	return g.Open(nil, sealed[:n], sealed[n:], aad)
}

// NewDEK returns a random 32-byte DEK, its wrapping under the active key
// (nonce(12) || ciphertext), and the key ID used.
func (r *Keyring) NewDEK() (dek, wrapped []byte, keyID int, err error) {
	dek = make([]byte, keyLen)
	if _, err = rand.Read(dek); err != nil {
		return nil, nil, 0, err
	}
	wrapped, err = seal(r.keys[r.active], dek, nil)
	if err != nil {
		return nil, nil, 0, err
	}
	return dek, wrapped, r.active, nil
}

func (r *Keyring) UnwrapDEK(wrapped []byte, keyID int) ([]byte, error) {
	g, ok := r.keys[keyID]
	if !ok {
		return nil, fmt.Errorf("keyring: unknown key id %d", keyID)
	}
	return open(g, wrapped, nil)
}

// Seal encrypts a small value: keyID(uint32 BE) || nonce || ct, bound to aad.
func (r *Keyring) Seal(plain, aad []byte) ([]byte, error) {
	body, err := seal(r.keys[r.active], plain, aad)
	if err != nil {
		return nil, err
	}
	return append(binary.BigEndian.AppendUint32(nil, uint32(r.active)), body...), nil
}

func (r *Keyring) Open(sealed, aad []byte) ([]byte, error) {
	if len(sealed) < 4 {
		return nil, errors.New("sxcrypto: sealed value too short")
	}
	id := int(binary.BigEndian.Uint32(sealed))
	g, ok := r.keys[id]
	if !ok {
		return nil, fmt.Errorf("keyring: unknown key id %d", id)
	}
	return open(g, sealed[4:], aad)
}
