-- +goose Up
CREATE TABLE syslog_cursor (id int PRIMARY KEY CHECK (id = 1), last_id bigint NOT NULL DEFAULT 0,
  last_ok_at timestamptz, failing_since timestamptz, last_error text NOT NULL DEFAULT '');
INSERT INTO syslog_cursor (id) VALUES (1);
ALTER TABLE users ADD notify_first_open boolean NOT NULL DEFAULT true,
  ADD notify_download boolean NOT NULL DEFAULT true, ADD notify_upload boolean NOT NULL DEFAULT true;
CREATE INDEX audit_log_target ON audit_log (target_id);
CREATE INDEX audit_log_share ON audit_log ((detail->>'share_id'));
CREATE INDEX audit_log_actor ON audit_log (actor_id);
CREATE INDEX audit_log_at ON audit_log (at);
-- +goose Down
DROP INDEX audit_log_target, audit_log_share, audit_log_actor, audit_log_at;
ALTER TABLE users DROP notify_first_open, DROP notify_download, DROP notify_upload;
DROP TABLE syslog_cursor;
