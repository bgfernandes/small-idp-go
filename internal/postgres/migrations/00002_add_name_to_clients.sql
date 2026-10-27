-- +goose Up
-- Assumes that the DB is empty, otherwise the migration will fail.
ALTER TABLE clients ADD COLUMN name text NOT NULL;

-- +goose Down
ALTER TABLE clients DROP COLUMN name;
