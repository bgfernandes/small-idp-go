-- +goose Up
ALTER TABLE clients RENAME COLUMN client_secret_hash TO secret_hash;

-- +goose Down
ALTER TABLE clients RENAME COLUMN secret_hash TO client_secret_hash;