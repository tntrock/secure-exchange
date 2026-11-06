-- +goose Up
CREATE TABLE vendor_orgs (id uuid PRIMARY KEY, name text NOT NULL, created_at timestamptz NOT NULL DEFAULT now());
CREATE UNIQUE INDEX vendor_orgs_name ON vendor_orgs (lower(name));
ALTER TABLE users ADD COLUMN vendor_org_id uuid REFERENCES vendor_orgs, ADD COLUMN created_by uuid REFERENCES users,
  ADD COLUMN expires_at timestamptz,
  ADD COLUMN approval text NOT NULL DEFAULT 'approved' CHECK (approval IN ('pending','approved','rejected'));
CREATE TABLE vendor_invites (
  token_hash bytea PRIMARY KEY, user_id uuid NOT NULL REFERENCES users ON DELETE CASCADE,
  expires_at timestamptz NOT NULL, used_at timestamptz, created_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX vendor_invites_user ON vendor_invites (user_id);
ALTER TABLE share_recipients ADD COLUMN vendor_id uuid REFERENCES users;
CREATE UNIQUE INDEX share_recipients_vendor ON share_recipients (share_id, vendor_id) WHERE vendor_id IS NOT NULL;
CREATE INDEX share_recipients_by_vendor ON share_recipients (vendor_id) WHERE vendor_id IS NOT NULL;
ALTER TABLE uploads ADD COLUMN vendor_id uuid REFERENCES users;
ALTER TABLE files ADD COLUMN vendor_id uuid REFERENCES users;
CREATE TABLE vendor_share_views (
  session_hash bytea NOT NULL, share_id uuid NOT NULL REFERENCES shares ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (session_hash, share_id));
-- phase-5 follow-ups: lookups by request / uploader
CREATE INDEX uploads_request ON uploads (request_id) WHERE request_id IS NOT NULL;
CREATE INDEX request_otps_uploader ON request_otps (uploader_id);
CREATE INDEX request_sessions_uploader ON request_sessions (uploader_id);

-- +goose Down
DROP INDEX request_sessions_uploader, request_otps_uploader, uploads_request;
DROP TABLE vendor_share_views;
ALTER TABLE files DROP COLUMN vendor_id;
ALTER TABLE uploads DROP COLUMN vendor_id;
ALTER TABLE share_recipients DROP COLUMN vendor_id;
DROP TABLE vendor_invites;
ALTER TABLE users DROP COLUMN approval, DROP COLUMN expires_at, DROP COLUMN created_by, DROP COLUMN vendor_org_id;
DROP TABLE vendor_orgs;
