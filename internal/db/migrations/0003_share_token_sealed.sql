-- +goose Up
ALTER TABLE shares ADD COLUMN token_sealed bytea NOT NULL;

-- +goose Down
ALTER TABLE shares DROP COLUMN token_sealed;
