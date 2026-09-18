# Plan

A small OAuth 2.0 / OIDC authorization server in Go, built in phases from the RFCs. This file is the single source of truth for scope, progress, and learning notes. Tick items as they land; add notes at the bottom.

**Why a provider, not a client.** A relying party teaches Go's HTTP stack but little protocol depth. Building the authorization server forces every spec decision to be made explicitly: what goes in each token, who validates what, how keys rotate, what happens on logout.

## Ground rules

- Standard library only for the core: `net/http`, `crypto/ecdsa`, `crypto/rand`, `encoding/json`, `encoding/base64`, `html/template`, `log/slog`, `database/sql` (SQLite from phase 3). No web framework. Hand-roll JWS signing and verification; that is where the learning is. Third-party code only for the SQLite driver and, in phase 4, for the test clients.
- Table-driven tests with `net/http/httptest` from phase 1.
- Not for production use. The README says so.
- Commit small and often. Cite the RFC or OIDC section in code comments and commit messages when a decision comes from the spec.

## Phases

### Phase 1 — Token issuer

Ships a server that can mint verifiable access tokens for machine clients.

- [ ] `go mod init github.com/bgfernandes/small-idp-go`, layout (`cmd/server`, `internal/...`), run instructions in README.
- [ ] EC P-256 signing key generated at startup, with a `kid`.
- [ ] `GET /.well-known/openid-configuration` (OIDC Discovery 1.0, RFC 8414): issuer, endpoints, supported grants, signing algs.
- [ ] `GET /jwks` returning the public key as a JWK Set (RFC 7517).
- [ ] `POST /token` with `grant_type=client_credentials` (RFC 6749 §4.4), client authentication via HTTP Basic (`client_secret_basic`) and form body (`client_secret_post`), in-memory client registry.
- [ ] JWT access token (RFC 7519, RFC 9068 profile): `iss`, `sub`, `aud`, `exp`, `iat`, `jti`, `scope`, `client_id`. Sign with ES256 (RFC 7518), hand-rolled JWS compact serialization (RFC 7515).
- [ ] Error responses per RFC 6749 §5.2 (`invalid_client`, `invalid_grant`, `unsupported_grant_type`), correct status codes and `WWW-Authenticate` on 401.
- [ ] Tests: token endpoint happy path, each error case, signature verification of the minted token against the JWKS.

Go topics: modules and layout, `net/http` handlers and middleware, structs and JSON tags, error-handling conventions, `crypto` packages, table-driven tests, `httptest`.

### Phase 2 — Authorization code with PKCE and OIDC

Ships browser login.

- [ ] Hard-coded user store (username, bcrypt-hashed password) and a minimal HTML login page via `html/template`.
- [ ] `GET /authorize` (RFC 6749 §4.1): validate `client_id`, `redirect_uri` exact match, `response_type=code`, `scope`, `state`; require PKCE `code_challenge` with `S256` (RFC 7636). Reject `plain`.
- [ ] Login and consent pages; consent skippable per client for first-party apps.
- [ ] Authorization code: single-use, short TTL, bound to `client_id`, `redirect_uri`, `code_challenge`, `nonce`.
- [ ] `POST /token` with `grant_type=authorization_code` and `code_verifier` check.
- [ ] ID token (OIDC Core §2, §3.1.3.6): `iss`, `sub`, `aud`, `exp`, `iat`, `auth_time`, `nonce`, `at_hash`, `sid`; `acr` fixed for now.
- [ ] `GET /userinfo` (OIDC Core §5.3) with bearer token; claims filtered by scope (`openid`, `profile`, `email`).
- [ ] Server-side IdP session cookie, `HttpOnly`, `Secure`, `SameSite=Lax`; `prompt=none` and `prompt=login`; `max_age` re-authentication.
- [ ] Tests: full code flow driven with `httptest` and a cookie jar, PKCE failure cases, `nonce` round-trip, single-use code, `redirect_uri` mismatch.

Go topics: `html/template`, cookies and sessions, `context`, `sync.Mutex` or channels for the in-memory stores, `time` handling, `errors.Is` / `errors.As`.

### Phase 3 — Lifecycle

Ships the parts that make a provider operable.

- [ ] Refresh tokens (RFC 6749 §6) with rotation and reuse detection (revoke the family on reuse, per RFC 9700 / OAuth 2.0 Security BCP).
- [ ] `POST /revoke` (RFC 7009) and `POST /introspect` (RFC 7662), with client authentication.
- [ ] Signing-key rotation: two keys live in the JWKS with distinct `kid`s, new tokens use the new key, old key retired after the longest token TTL.
- [ ] Back-channel logout (OIDC Back-Channel Logout 1.0): logout token with `sid`, POSTed to registered client `backchannel_logout_uri`s.
- [ ] Persist clients, users, codes, and tokens in SQLite so restarts do not wipe state.
- [ ] Structured logging with `log/slog`; request IDs.
- [ ] Tests for rotation, reuse detection, introspection of revoked tokens, key rollover.

Go topics: `database/sql`, `log/slog`, goroutines for the logout fan-out with `sync.WaitGroup` and per-request timeouts, graceful shutdown with `signal.NotifyContext`.

### Phase 4 — Verify against real clients

Proves the server speaks the protocol, not just its own tests.

- [ ] A Go relying party in a separate `cmd/` using `github.com/coreos/go-oidc/v3` and `golang.org/x/oauth2`: discovery, login, ID-token verification, userinfo.
- [ ] oauth2-proxy in front of a static site, configured with this server as its OIDC provider.
- [ ] Optional: run a subset of the OpenID Foundation conformance suite locally and record what passes.
- [ ] README section: what was verified, what is deliberately unsupported (`implicit`, `password`, `plain` PKCE, `HS*` signing, wildcard redirect URIs) and the BCP reasoning.

### Phase 5 — SCIM 2.0 server (optional)

- [ ] `/Users` and `/Groups` per RFC 7643 schemas; `/ServiceProviderConfig`, `/Schemas`, `/ResourceTypes`.
- [ ] RFC 7644 operations: `GET` with `filter` (at least `eq`, `and`, `userName`, `emails.value`), `POST`, `PUT`, `PATCH` with `add`/`replace`/`remove`, `DELETE`; pagination with `startIndex` and `count`.
- [ ] Bearer-token auth using the phase-1 client-credentials tokens.
- [ ] Test against a real provisioning client (an Okta developer tenant or Microsoft Entra), pushing users and groups.

## Things worth being able to explain

Add to this list whenever a phase produces a decision worth explaining.

- Why the authorization code is bound to `redirect_uri` and `code_challenge`, and what attack each binding stops.
- What `at_hash` and `nonce` protect against, and why `nonce` matters with the code flow in OIDC.
- Key rotation: why two keys must overlap in the JWKS and how long the old one must stay.
- Refresh-token reuse detection: what "revoke the family" means and its false-positive risk on flaky networks.
- Back-channel logout: why it needs server-side state on the client, and why `sid` rather than `sub` is the right scope.
- What the server deliberately does not implement, and the RFC or BCP that recommends against each.

## Learning notes

Dated, free-form. Things that surprised you about Go, mistakes, idioms picked up, spec details that differed from expectation.

- 2026-09-18 — Repo created. Plan written. No code yet.
