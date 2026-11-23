-- +goose Up
ALTER TABLE clients ADD COLUMN redirection_uris text[] NOT NULL DEFAULT '{}';

-- +goose Down
ALTER TABLE clients DROP COLUMN redirection_uris;
