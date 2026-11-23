-- +goose Up
ALTER TABLE clients ALTER COLUMN secret_hash DROP NOT NULL;

-- +goose Down
ALTER TABLE clients ALTER COLUMN secret_hash SET NOT NULL;
