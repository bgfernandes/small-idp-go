-- +goose Up
CREATE TABLE clients (
    -- RFC 6749 §2.2 defines client_id as a unique string with no format
    id text NOT NULL,
    client_secret_hash text NOT NULL,
    grant_types text[] NOT NULL,
    scopes text[] NOT NULL,
    audiences text[] NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY(id)
);

-- +goose Down
DROP TABLE clients;