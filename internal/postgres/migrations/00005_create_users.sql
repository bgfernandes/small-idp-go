-- +goose Up
CREATE TABLE users (
    id text NOT NULL,
    email text NOT NULL,
    password_hash text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY(id)
);

CREATE UNIQUE INDEX users_email_key ON users (lower(email));

-- +goose Down
DROP INDEX users_email_key;
DROP TABLE users;