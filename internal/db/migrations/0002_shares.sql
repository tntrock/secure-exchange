-- +goose Up
CREATE TABLE shares (
  id uuid PRIMARY KEY, owner_id uuid NOT NULL REFERENCES users,
  token_hash bytea NOT NULL UNIQUE, token_sealed bytea NOT NULL, message text NOT NULL DEFAULT '',
  allow_download boolean NOT NULL, watermark boolean NOT NULL,
  expires_at timestamptz NOT NULL, max_views int CHECK (max_views > 0), view_count int NOT NULL DEFAULT 0,
  ip_allow cidr[] NOT NULL DEFAULT '{}', revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX shares_owner ON shares (owner_id, created_at DESC);
CREATE TABLE share_files (
  share_id uuid NOT NULL REFERENCES shares ON DELETE CASCADE,
  file_id uuid NOT NULL REFERENCES files, PRIMARY KEY (share_id, file_id));
CREATE TABLE share_recipients (
  id uuid PRIMARY KEY, share_id uuid NOT NULL REFERENCES shares ON DELETE CASCADE,
  email text NOT NULL, revoked_at timestamptz, first_opened_at timestamptz, last_access_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now());
CREATE UNIQUE INDEX share_recipients_email ON share_recipients (share_id, lower(email));
CREATE TABLE share_otps (
  id uuid PRIMARY KEY, recipient_id uuid NOT NULL REFERENCES share_recipients ON DELETE CASCADE,
  code_hash bytea NOT NULL, attempts int NOT NULL DEFAULT 0, used_at timestamptz,
  expires_at timestamptz NOT NULL, created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE share_sessions (
  token_hash bytea PRIMARY KEY, recipient_id uuid NOT NULL REFERENCES share_recipients ON DELETE CASCADE,
  ip text NOT NULL, user_agent text NOT NULL,
  expires_at timestamptz NOT NULL, created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE share_downloads (
  recipient_id uuid NOT NULL REFERENCES share_recipients ON DELETE CASCADE,
  file_id uuid NOT NULL REFERENCES files, first_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (recipient_id, file_id));
CREATE TABLE mail_outbox (
  id uuid PRIMARY KEY, to_addr text NOT NULL, body_sealed bytea NOT NULL,
  attempts int NOT NULL DEFAULT 0, next_attempt_at timestamptz NOT NULL DEFAULT now(),
  sent_at timestamptz, last_error text NOT NULL DEFAULT '', created_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX mail_outbox_due ON mail_outbox (next_attempt_at) WHERE sent_at IS NULL;

-- +goose Down
DROP TABLE mail_outbox, share_downloads, share_sessions, share_otps, share_recipients, share_files, shares;
