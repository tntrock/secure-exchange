-- +goose Up
ALTER TABLE vendor_invites RENAME TO account_invites;
ALTER INDEX vendor_invites_user RENAME TO account_invites_user;
ALTER TABLE users ADD COLUMN last_login_at timestamptz;
ALTER TABLE site_rules ADD COLUMN force_totp bool NOT NULL DEFAULT false;

-- +goose Down
ALTER TABLE site_rules DROP COLUMN force_totp;
ALTER TABLE users DROP COLUMN last_login_at;
ALTER INDEX account_invites_user RENAME TO vendor_invites_user;
ALTER TABLE account_invites RENAME TO vendor_invites;
