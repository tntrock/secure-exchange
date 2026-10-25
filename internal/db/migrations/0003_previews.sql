-- +goose Up
CREATE TABLE file_previews (
  file_id uuid PRIMARY KEY REFERENCES files ON DELETE CASCADE,
  kind text NOT NULL CHECK (kind IN ('pages','image','video','none')),
  status text NOT NULL CHECK (status IN ('pending','ready','failed','unsupported','too_large')),
  page_count int NOT NULL DEFAULT 0, width int NOT NULL DEFAULT 0, height int NOT NULL DEFAULT 0,
  duration_ms bigint NOT NULL DEFAULT 0, error text NOT NULL DEFAULT '',
  updated_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE preview_items (
  id uuid PRIMARY KEY, file_id uuid NOT NULL REFERENCES files ON DELETE CASCADE,
  kind text NOT NULL CHECK (kind IN ('page','image','segment')), idx int NOT NULL,
  storage_key text NOT NULL, size bigint NOT NULL, wrapped_dek bytea NOT NULL, key_id int NOT NULL,
  width int NOT NULL DEFAULT 0, height int NOT NULL DEFAULT 0, duration_ms bigint NOT NULL DEFAULT 0,
  UNIQUE (file_id, kind, idx));
CREATE TABLE render_jobs (
  id uuid PRIMARY KEY, file_id uuid NOT NULL UNIQUE REFERENCES files ON DELETE CASCADE,
  status text NOT NULL CHECK (status IN ('queued','running','done','failed')),
  attempts int NOT NULL DEFAULT 0, lease_until timestamptz, error text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX render_jobs_ready ON render_jobs (created_at) WHERE status = 'queued';
CREATE TABLE view_traces (
  code text PRIMARY KEY, file_id uuid NOT NULL REFERENCES files,
  share_id uuid REFERENCES shares, recipient_id uuid REFERENCES share_recipients,
  session_hash bytea, ip text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (session_hash, file_id));

-- +goose Down
DROP TABLE view_traces, render_jobs, preview_items, file_previews;
