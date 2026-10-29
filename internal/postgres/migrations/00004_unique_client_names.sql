-- +goose Up
CREATE UNIQUE INDEX clients_name_key ON clients (lower(name));

-- +goose Down
DROP INDEX clients_name_key;