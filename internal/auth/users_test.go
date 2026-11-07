package auth

import (
	"context"
	"testing"
	"time"
)

func TestUserActive(t *testing.T) {
	now := time.Now()
	past, future := now.Add(-time.Second), now.Add(time.Hour)
	tests := []struct {
		name string
		u    User
		want bool
	}{
		{"staff ok", User{Role: "staff", Approval: "approved"}, true},
		{"staff disabled", User{Role: "staff", Approval: "approved", Disabled: true}, false},
		{"staff pending", User{Role: "staff", Approval: "pending"}, false},
		{"staff rejected", User{Role: "staff", Approval: "rejected"}, false},
		{"staff expired", User{Role: "staff", Approval: "approved", ExpiresAt: &past}, false},
		{"staff not yet expired", User{Role: "staff", Approval: "approved", ExpiresAt: &future}, true},
		{"vendor ok", User{Role: "vendor", Approval: "approved", PasswordHash: "h", TOTPEnabled: true, ExpiresAt: &future}, true},
		{"vendor no password", User{Role: "vendor", Approval: "approved", TOTPEnabled: true}, false},
		{"vendor no totp", User{Role: "vendor", Approval: "approved", PasswordHash: "h"}, false},
	}
	for _, tc := range tests {
		if got := tc.u.Active(now); got != tc.want {
			t.Errorf("%s: Active = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestNotifyPrefsRoundTrip(t *testing.T) {
	us := newUsers(t)
	ctx := context.Background()
	u, err := us.Create(ctx, "n@x.com", "", "staff", "password-12345")
	if err != nil {
		t.Fatal(err)
	}
	if p, err := us.NotifyPrefs(ctx, u.ID); err != nil || p != (NotifyPrefs{true, true, true}) {
		t.Fatal(p, err)
	}
	want := NotifyPrefs{FirstOpen: false, Download: true, Upload: false}
	if err := us.SetNotifyPrefs(ctx, u.ID, want); err != nil {
		t.Fatal(err)
	}
	if p, err := us.NotifyPrefs(ctx, u.ID); err != nil || p != want {
		t.Fatal(p, err)
	}
}
