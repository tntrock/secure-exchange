-- +goose Up
ALTER TABLE users ADD external_id text;
CREATE UNIQUE INDEX users_external ON users (auth_source, external_id) WHERE external_id IS NOT NULL;
DROP INDEX users_email_lower;
CREATE UNIQUE INDEX users_email_lower ON users (auth_source, lower(email));
ALTER TABLE sessions ADD checked_at timestamptz NOT NULL DEFAULT now();
-- +goose Down
-- NOTE: this Down fails if a local and an LDAP account share an email (lower(email) must be unique again),
-- and LDAP rows would lose their external_id (they could no longer be matched on login).
ALTER TABLE sessions DROP checked_at;
DROP INDEX users_email_lower;
CREATE UNIQUE INDEX users_email_lower ON users (lower(email));
DROP INDEX users_external;
ALTER TABLE users DROP external_id;
