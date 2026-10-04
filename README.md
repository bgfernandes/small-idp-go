# small-idp-go

A small OAuth 2.0 / OIDC authorization server in Go, built from the RFCs as a learning project. Not for production use.

## Plan and progress

[`PLAN.md`](PLAN.md) contains the phased checklist, the specs each phase exercises, the Go topics each phase teaches, and the running learning notes. Read it first.

## Local development setup

**Go 1.27** is required. The project is built against the current stable release and uses modern standard-library APIs, so older toolchains are not supported.

The suggested way to manage the Go version is [mise](https://mise.jdx.dev). The repo ships a `mise.toml` that pins Go 1.27, so after cloning:

```sh
mise trust     # allow mise to read this repo's mise.toml
mise install   # installs the pinned Go toolchain
go version     # should report go1.27.x
```

Compile and run the HTTP server locally with:

```sh
go run ./cmd/server # The server listens on :8080 by default
```

Before committing, make sure Go's static checks, formatting and tests pass with:

```sh
go vet ./...        # static checks
go test ./...       # run all tests
go test -race ./... # with the race detector
gofmt -l .          # list unformatted files, empty output means clean
```

## Configuration

The server reads its configuration from environment variables at startup. Every variable has a default, so `go run ./cmd/server` works with no setup. An unset or empty variable falls back to its default.

| Variable          | Default                 | Description                                                                 |
| ----------------- | ----------------------- | --------------------------------------------------------------------------- |
| `SMALLIDP_ISSUER` | `http://localhost:8080` | The issuer identifier: the public URL clients use to reach the server.      |
| `SMALLIDP_ADDR`   | `:8080`                 | The address the HTTP server listens on, in `host:port` form (e.g. `:9000`). |

The two are independent. The issuer is what the server says about itself in tokens and metadata; the address is where it binds. Behind a reverse proxy they differ:

```sh
SMALLIDP_ISSUER=https://idp.example.com SMALLIDP_ADDR=127.0.0.1:9000 go run ./cmd/server
```

The issuer is validated at startup and the server exits with an error if it is invalid. It must:

- use the `http` or `https` scheme. RFC 8414 §2 requires `https`; plain `http` is accepted here for local development only.
- include a host.
- have no query string or fragment (RFC 8414 §2).
- have no trailing slash. A path is allowed, e.g. `https://example.com/idp`.
