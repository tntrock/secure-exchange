-- +goose Up
CREATE TABLE site_rules (
  id int PRIMARY KEY CHECK (id = 1),
  force_watermark bool NOT NULL DEFAULT false,
  forbid_download bool NOT NULL DEFAULT false,
  share_max_days int NOT NULL DEFAULT 0,
  share_default_days int NOT NULL DEFAULT 7,
  max_file_bytes bigint NOT NULL DEFAULT 0,
  max_share_bytes bigint NOT NULL DEFAULT 0,
  domain_block text[] NOT NULL DEFAULT '{}',
  domain_allow text[] NOT NULL DEFAULT '{}',
  external_ip_allow cidr[] NOT NULL DEFAULT '{}',
  upload_exts text[] NOT NULL DEFAULT '{}',
  upload_max_bytes bigint NOT NULL DEFAULT 0,
  quota_bytes bigint NOT NULL DEFAULT 0,
  retention_days int NOT NULL DEFAULT 0,
  updated_at timestamptz NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE site_rules;
