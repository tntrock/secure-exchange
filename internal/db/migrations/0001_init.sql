-- +goose Up
CREATE TABLE users (
  id uuid PRIMARY KEY, email text NOT NULL, display_name text NOT NULL DEFAULT '',
  role text NOT NULL CHECK (role IN ('admin','staff','vendor')),
  auth_source text NOT NULL DEFAULT 'local' CHECK (auth_source IN ('local','ldap','oidc')),
  password_hash text, totp_secret_sealed bytea, totp_enabled boolean NOT NULL DEFAULT false,
  totp_last_step bigint NOT NULL DEFAULT 0,
  disabled boolean NOT NULL DEFAULT false, created_at timestamptz NOT NULL DEFAULT now());
CREATE UNIQUE INDEX users_email_lower ON users (lower(email));
CREATE TABLE sessions (
  token_hash bytea PRIMARY KEY, user_id uuid NOT NULL REFERENCES users ON DELETE CASCADE,
  mfa_passed boolean NOT NULL, ip text NOT NULL, user_agent text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz NOT NULL);
CREATE TABLE files (
  id uuid PRIMARY KEY, owner_id uuid NOT NULL REFERENCES users,
  name text NOT NULL, content_type text NOT NULL, size bigint NOT NULL, sha256 bytea NOT NULL,
  wrapped_dek bytea NOT NULL, key_id int NOT NULL, storage_key text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(), deleted_at timestamptz);
CREATE TABLE uploads (
  id uuid PRIMARY KEY, owner_id uuid NOT NULL REFERENCES users,
  name text NOT NULL, content_type text NOT NULL, size bigint NOT NULL, "offset" bigint NOT NULL DEFAULT 0,
  wrapped_dek bytea NOT NULL, key_id int NOT NULL, hash_state bytea NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE audit_log (
  id bigserial PRIMARY KEY, at timestamptz NOT NULL, actor_type text NOT NULL, actor_id text NOT NULL,
  ip text NOT NULL, user_agent text NOT NULL, action text NOT NULL,
  target_type text NOT NULL, target_id text NOT NULL, result text NOT NULL,
  detail jsonb NOT NULL DEFAULT '{}', prev_hash bytea NOT NULL, hash bytea NOT NULL);
CREATE RULE audit_no_update AS ON UPDATE TO audit_log DO INSTEAD NOTHING;
CREATE RULE audit_no_delete AS ON DELETE TO audit_log DO INSTEAD NOTHING;

-- +goose Down
DROP TABLE audit_log, uploads, files, sessions, users;
