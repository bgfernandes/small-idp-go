# small-idp-go

A small OAuth 2.0 / OIDC authorization server in Go, built from the RFCs as a learning project. Not for production use.

## Plan and progress

[`PLAN.md`](PLAN.md) contains the phased checklist, the specs each phase exercises, the Go topics each phase teaches, and the running learning notes. Read it first.

## Local development setup

**Go 1.27** is required. The project is built against the current stable release and uses modern standard-library APIs, so older toolchains are not supported.

The suggested way to manage the Go version is [mise](https://mise.jdx.dev). The repo ships a `mise.toml` that pins Go 1.27 and the [golangci-lint](https://golangci-lint.run) version, so after cloning:

```sh
mise trust     # allow mise to read this repo's mise.toml
mise install   # installs the pinned Go toolchain and golangci-lint
go version     # should report go1.27.x
```

### Editor setup

Integration tests sit behind the `integration` build tag (see [Tests](#tests)). Without that tag the Go tooling treats those files as excluded from the package, so the editor shows no diagnostics or completion in them. `.vscode/settings.json` sets `go.buildTags` to `integration` for Cursor and VS Code with the Go extension; `.golangci.yml` does the same for the linter. For other editors, pass `-tags=integration` to gopls through its `build.buildFlags` setting.

Compile and run the HTTP server locally with:

```sh
go run ./cmd/server # The server listens on :8080 by default
```

Before committing, make sure Go's static checks, linting, formatting and tests pass with:

```sh
go vet ./...                                     # static checks
go vet -tags=integration ./...                   # including the integration test files
golangci-lint run                                # linters, configured in .golangci.yml
go test ./...                                    # unit tests
go test -race ./...                              # with the race detector
go test -race -count=1 -tags=integration ./...   # unit and integration tests, needs the database (see Tests)
gofmt -l .                                       # list unformatted files, empty output means clean
```

## Local infrastructure

The client registry lives in PostgreSQL. `compose.yaml` runs one for local development; it needs [Docker](https://docs.docker.com/get-docker/) with the Compose plugin.

```sh
docker compose up -d --wait # start PostgreSQL in the background and wait until it is healthy
docker compose ps           # check it is running
docker compose down         # stop it, keeping the data
docker compose down -v      # stop it and delete the data volume
```

The database is reachable at:

```
postgres://smallidp:smallidp@localhost:5432/smallidp?sslmode=disable
```

To open a SQL shell inside the container:

```sh
docker compose exec postgres psql -U smallidp -d smallidp
```

The credentials are development defaults and are safe to commit because they only ever apply to this local container.

## Tests

There are two kinds of tests:

- **Unit tests** need nothing but Go. `go test ./...` runs them.
- **Integration tests** need the PostgreSQL instance from [Local infrastructure](#local-infrastructure). Their files start with `//go:build integration`, so `go test ./...` does not compile them; they run only with `-tags=integration`.

Run the integration tests with the database up:

```sh
go test -race -count=1 -tags=integration ./...
```

Details worth knowing:

- The tests connect to the `compose.yaml` database by default, so no configuration is needed locally. `SMALLIDP_TEST_DATABASE_URL` overrides that URL, for example in CI where the database runs on another host. The tests never skip: without a reachable database they fail.
- Each test creates its own database named `smallidp_test_<package>_<random>` and drops it when done, so the development data in `smallidp` is never touched. Databases left behind by a crashed run are dropped the next time the package's tests start.
- `-count=1` disables Go's test result cache. The cache keys on inputs Go can see, which does not include database state, so a cached pass could hide a failure.

## Configuration

The server and the `clients` tool read their configuration from environment variables at startup. Every variable has a default that matches `compose.yaml`, so once the database is running `go run ./cmd/server` works with no further setup. An unset or empty variable falls back to its default. The `clients` tool uses only `SMALLIDP_DATABASE_URL`.

| Variable                | Default                                                   | Description                                                                 |
| ----------------------- | --------------------------------------------------------- | --------------------------------------------------------------------------- |
| `SMALLIDP_ISSUER`       | `http://localhost:8080`                                   | The issuer identifier: the public URL clients use to reach the server.      |
| `SMALLIDP_ADDR`         | `:8080`                                                   | The address the HTTP server listens on, in `host:port` form (e.g. `:9000`). |
| `SMALLIDP_DATABASE_URL` | `postgresql://smallidp:smallidp@localhost:5432/smallidp` | The PostgreSQL connection URL. Pending migrations are applied at startup.   |

The issuer and the address are independent. The issuer is what the server says about itself in tokens and metadata; the address is where it binds. Behind a reverse proxy they differ:

```sh
SMALLIDP_ISSUER=https://idp.example.com SMALLIDP_ADDR=127.0.0.1:9000 go run ./cmd/server
```

The issuer is validated at startup and the server exits with an error if it is invalid. It must:

- use the `http` or `https` scheme. RFC 8414 §2 requires `https`; plain `http` is accepted here for local development only.
- include a host.
- have no query string or fragment (RFC 8414 §2).
- have no trailing slash. A path is allowed, e.g. `https://example.com/idp`.

### Issuer with a path

When the issuer has a path, e.g. `https://example.com/idp`, the server expects to run behind a reverse proxy that strips that path prefix before forwarding. The server's own routes always sit at the root (`/jwks`, `/.well-known/oauth-authorization-server`, ...); the path only changes the URLs it advertises. Those are built from the configured issuer, never from the request's `Host` or `X-Forwarded-*` headers.

Two proxy rules cover it:

| Public URL                                                       | Forwarded to the server as                | Why                                                                                               |
| ---------------------------------------------------------------- | ----------------------------------------- | ------------------------------------------------------------------------------------------------- |
| `https://example.com/idp/*`                                      | `/*`                                      | The prefix rule. Covers every endpoint and the metadata URL formed by appending to the issuer.    |
| `https://example.com/.well-known/oauth-authorization-server/idp` | `/.well-known/oauth-authorization-server` | The metadata URL as RFC 8414 §3.1 defines it: the well-known segment is inserted before the path. |

The second rule is needed because the RFC 8414 §3.1 location sits at the host root, outside the `/idp` prefix, so the first rule never matches it. Without it, clients that follow the RFC strictly get a 404; clients that append `/.well-known/oauth-authorization-server` to the issuer work with the first rule alone. Appending is vendor behaviour, not what RFC 8414 defines: §5 allows it only as a transition measure for the `openid-configuration` suffix. Observed on 2026-10-04, Okta serves both the appended and the inserted location, and two Keycloak-based deployments (Red Hat SSO, CERN) serve only the appended one.

## Creating a client

The token endpoint only serves registered clients. `cmd/clients` creates one directly in the database:

```sh
go run ./cmd/clients create \
  -name billing \
  -grant-type client_credentials \
  -audience https://api.example.com \
  -scope read -scope write
```

`-grant-type`, `-audience` and `-scope` can be repeated. The tool prints the client ID and the secret once; only the SHA-256 hash of the secret is stored, so a lost secret means a new client. Names are unique, compared case-insensitively. The tool connects with `SMALLIDP_DATABASE_URL` and expects the schema to be in place, which the server does at startup.

Exit codes follow the usual convention: 0 on success, 1 when the client was rejected or the database failed, 2 on a usage error. The result goes to stdout, diagnostics go to stderr. `go run ./cmd/clients -h` and `go run ./cmd/clients create -h` print the usage.

This is a local development utility and is deliberately untested. A later phase adds an admin API for managing clients, and the tool will call that API instead of the database, so it can also manage a deployed instance; see [`PLAN.md`](PLAN.md).
