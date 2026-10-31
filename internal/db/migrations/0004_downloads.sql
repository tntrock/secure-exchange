-- +goose Up
CREATE TABLE download_traces (
  code text PRIMARY KEY, file_id uuid NOT NULL REFERENCES files,
  share_id uuid NOT NULL REFERENCES shares, recipient_id uuid NOT NULL REFERENCES share_recipients,
  method text NOT NULL CHECK (method IN ('pdf_pages','pdf_meta','image_visible','image_invisible','ooxml_meta','odf_meta','none')),
  ip text NOT NULL, user_agent text NOT NULL, sha256 bytea, size bigint,
  created_at timestamptz NOT NULL DEFAULT now(), completed_at timestamptz);
CREATE UNIQUE INDEX download_traces_unmarked ON download_traces (recipient_id, file_id) WHERE method = 'none';
CREATE INDEX download_traces_sha ON download_traces (sha256) WHERE sha256 IS NOT NULL;
CREATE INDEX files_sha ON files (sha256);

-- +goose Down
DROP INDEX files_sha;
DROP TABLE download_traces;
