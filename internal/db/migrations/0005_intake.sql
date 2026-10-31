-- +goose Up
CREATE TABLE upload_requests (
  id uuid PRIMARY KEY, owner_id uuid NOT NULL REFERENCES users,
  token_hash bytea NOT NULL UNIQUE, token_sealed bytea NOT NULL, message text NOT NULL DEFAULT '',
  expires_at timestamptz NOT NULL, max_files int NOT NULL CHECK (max_files > 0),
  max_total_bytes bigint NOT NULL CHECK (max_total_bytes > 0), allowed_exts text[] NOT NULL DEFAULT '{}',
  revoked_at timestamptz, created_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX upload_requests_owner ON upload_requests (owner_id, created_at DESC);
CREATE TABLE request_uploaders (
  id uuid PRIMARY KEY, request_id uuid NOT NULL REFERENCES upload_requests ON DELETE CASCADE,
  email text NOT NULL, first_opened_at timestamptz, last_access_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now());
CREATE UNIQUE INDEX request_uploaders_email ON request_uploaders (request_id, lower(email));
CREATE TABLE request_otps (
  id uuid PRIMARY KEY, uploader_id uuid NOT NULL REFERENCES request_uploaders ON DELETE CASCADE,
  code_hash bytea NOT NULL, attempts int NOT NULL DEFAULT 0, used_at timestamptz,
  expires_at timestamptz NOT NULL, created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE request_sessions (
  token_hash bytea PRIMARY KEY, uploader_id uuid NOT NULL REFERENCES request_uploaders ON DELETE CASCADE,
  ip text NOT NULL, user_agent text NOT NULL,
  expires_at timestamptz NOT NULL, created_at timestamptz NOT NULL DEFAULT now());
ALTER TABLE uploads ADD COLUMN request_id uuid REFERENCES upload_requests, ADD COLUMN uploader_id uuid REFERENCES request_uploaders;
ALTER TABLE files ADD COLUMN request_id uuid REFERENCES upload_requests, ADD COLUMN uploader_id uuid REFERENCES request_uploaders,
  ADD COLUMN scan_status text NOT NULL DEFAULT 'none' CHECK (scan_status IN ('none','pending','clean','infected','skipped','error')),
  ADD COLUMN scan_result text NOT NULL DEFAULT '';
CREATE INDEX files_request ON files (request_id) WHERE request_id IS NOT NULL;
CREATE TABLE scan_jobs (
  file_id uuid PRIMARY KEY REFERENCES files ON DELETE CASCADE, attempts int NOT NULL DEFAULT 0,
  lease_until timestamptz, created_at timestamptz NOT NULL DEFAULT now());

-- +goose Down
-- Rolling back drops scan_status, which makes quarantined, pending and error files downloadable again.
-- Delete or quarantine them by hand before rolling back.
DROP TABLE scan_jobs;
ALTER TABLE files DROP COLUMN scan_result, DROP COLUMN scan_status, DROP COLUMN uploader_id, DROP COLUMN request_id;
ALTER TABLE uploads DROP COLUMN uploader_id, DROP COLUMN request_id;
DROP TABLE request_sessions, request_otps, request_uploaders, upload_requests;
