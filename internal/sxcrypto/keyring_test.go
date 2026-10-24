package sxcrypto

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func k(b byte) string { return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, 32)) }

func mustRing(t *testing.T, spec string, active int) *Keyring {
	t.Helper()
	r, err := ParseKeyring(spec, active)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestKeyringRoundTrip(t *testing.T) {
	r := mustRing(t, "1:"+k(1), 1)
	dek, wrapped, id, err := r.NewDEK()
	if err != nil || len(dek) != 32 || id != 1 || r.ActiveID() != 1 {
		t.Fatalf("NewDEK: %v len=%d id=%d", err, len(dek), id)
	}
	got, err := r.UnwrapDEK(wrapped, id)
	if err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("unwrap mismatch: %v", err)
	}
}

func TestKeyringRejectsBadSpec(t *testing.T) {
	for _, c := range []struct {
		spec   string
		active int
	}{
		{"", 1}, {"1:short", 1}, {"1:" + k(1) + ",1:" + k(2), 1}, {"1:" + k(1), 9},
		{"x:" + k(1), 1}, {"1" + k(1), 1}, {"0:" + k(1), 0}, {"1:" + k(1) + ",2147483648:" + k(2), 1},
	} {
		if _, err := ParseKeyring(c.spec, c.active); err == nil {
			t.Errorf("spec %q active %d: want error", c.spec, c.active)
		}
	}
}

func TestUnwrapWithOldKey(t *testing.T) {
	a := mustRing(t, "1:"+k(1), 1)
	dek, wrapped, id, _ := a.NewDEK()
	b := mustRing(t, "1:"+k(1)+",2:"+k(2), 2)
	got, err := b.UnwrapDEK(wrapped, id)
	if err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("old key unwrap: %v", err)
	}
	if _, err := b.UnwrapDEK(wrapped, 3); err == nil {
		t.Error("unknown key id should fail")
	}
	_, _, nid, _ := b.NewDEK()
	if nid != 2 {
		t.Errorf("new DEK key id = %d, want 2", nid)
	}
}

func TestSealOpen(t *testing.T) {
	r := mustRing(t, "1:"+k(1), 1)
	s, err := r.Seal([]byte("secret"), []byte("totp:u1"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := r.Open(s, []byte("totp:u1"))
	if err != nil || string(p) != "secret" {
		t.Fatalf("open: %q %v", p, err)
	}
	if _, err := r.Open(s[:3], nil); err == nil {
		t.Error("short input should fail")
	}
}

func TestSealAADMismatch(t *testing.T) {
	r := mustRing(t, "1:"+k(1), 1)
	s, _ := r.Seal([]byte("secret"), []byte("totp:u1"))
	if _, err := r.Open(s, []byte("totp:u2")); err == nil {
		t.Error("aad mismatch should fail")
	}
}

func TestUnwrapTampered(t *testing.T) {
	r := mustRing(t, "1:"+k(1), 1)
	_, w, id, _ := r.NewDEK()
	w[len(w)-1] ^= 1
	if _, err := r.UnwrapDEK(w, id); err == nil {
		t.Error("tampered should fail")
	}
	if _, err := r.UnwrapDEK(w[:5], id); err == nil {
		t.Error("short should fail")
	}
}
