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

- [x] `go mod init github.com/bgfernandes/small-idp-go`, layout (`cmd/server`, `internal/...`), run instructions in README.
- [x] EC P-256 signing key generated at startup, with a `kid`. ES256 first because signing is the issuer's hot path, keys and signatures are a quarter the size of RSA-2048, key generation is instant (matters for rotation and for tests), and the JWS encoding has a real gotcha to learn: Go's `ecdsa.SignASN1` yields DER, but RFC 7518 §3.4 requires raw `R || S`, each left-padded to 32 bytes. RS256 is added in phase 3; see the note there.
- [x] Configuration loaded at startup from environment variables: the issuer and the listen address, as two separate settings (e.g. `SMALLIDP_ISSUER`, `SMALLIDP_ADDR`), since behind a reverse proxy they are unrelated. Defaults keep `go run ./cmd/server` working with no setup. A small config struct loaded in `cmd/server`; the loader takes the lookup function as a parameter (`os.Getenv` in `main`, a map-backed function in tests) rather than calling `os` itself. Issuer validation stays in `httpapi.NewServer`; a bad value fails startup through `run()`. README documents the variables. The client registry's source (hard-coded vs a JSON file) is decided with `POST /token`.
- [x] `GET /.well-known/oauth-authorization-server` (RFC 8414 §2, §3): the only metadata document in this phase, so a resource server verifying RFC 9068 tokens can find `jwks_uri` and the expected `iss` (RFC 9068 §4). Fields: `issuer` (the configured string verbatim; RFC 8414 §3.3 makes clients discard the document if it differs), `token_endpoint`, `jwks_uri`, `grant_types_supported: ["client_credentials"]`, and `token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"]`. The last two must be explicit because their defaults when omitted (`["authorization_code", "implicit"]` and `client_secret_basic` alone) would be false. `authorization_endpoint` is omitted, which §2 allows when no supported grant uses it. `response_types_supported` is REQUIRED by §2, but the server supports no response types and §3.2 says claims with zero elements MUST be omitted; the spec contradicts itself here, so omit the field in this phase and say why in a comment. Neither spec fixes the JWKS path; only the metadata documents are well-known, and the JWKS lives wherever `jwks_uri` says.
  - `GET /.well-known/openid-configuration` is deliberately not served in this phase; it moves to phase 2. OIDC Discovery §3 requires `authorization_endpoint`, `response_types_supported`, `subject_types_supported`, and `id_token_signing_alg_values_supported`, none of which is true of a `client_credentials`-only server, and RFC 9068 §4 offers the OIDC document only to servers "implementing OpenID Connect". Publishing it now would advertise an OpenID Provider that does not exist.
  - [x] Issuer with a path: the mux stays static at the root and never looks at the issuer's path. The deployment model is a reverse proxy that strips the path prefix before forwarding, so the path affects only what the server emits, never what it routes. Every emitted URL or path derives from the configured issuer, never from the request's `Host` or forwarded headers: advertised endpoints via `url.JoinPath`, and from phase 2 redirect `Location` headers, form actions, and the session cookie `Path`. The `issuer` field and the `iss` claim use the configured string verbatim. Metadata locations: the OAuth document, and from phase 2 the OIDC document, are served at the root routes, so the appended forms (`{path}/.well-known/openid-configuration`, OIDC Discovery §4.1, and `{path}/.well-known/oauth-authorization-server`, which is vendor behaviour that RFC 8414 does not define: §5 allows appending only as a transition measure for the `openid-configuration` suffix; observed 2026-10-04 on Okta, which also serves the inserted form, and on two Keycloak-based deployments, Red Hat SSO and CERN, which serve only the appended one) work through the stripping proxy with no application code. The spec-correct RFC 8414 §3.1 inserted form (`/.well-known/oauth-authorization-server{path}`) sits at the host root, outside the stripped prefix, so serving it at both locations means one extra proxy rewrite rule, documented in the README. Tests emulate the proxy with `http.StripPrefix(path, srv.Routes())`, using an issuer like `http://localhost:8080/tenant`.
- [x] `GET /jwks` returning the public key as a JWK Set (RFC 7517).
- [ ] `POST /token` with `grant_type=client_credentials` (RFC 6749 §4.4), client authentication via HTTP Basic (`client_secret_basic`) and form body (`client_secret_post`), in-memory client registry.
- [ ] JWT access token (RFC 7519, RFC 9068 profile): `iss`, `sub`, `aud`, `exp`, `iat`, `jti`, `scope`, `client_id`. Sign with ES256 (RFC 7518), hand-rolled JWS compact serialization (RFC 7515).
- [ ] Error responses per RFC 6749 §5.2 (`invalid_client`, `invalid_grant`, `unsupported_grant_type`), correct status codes and `WWW-Authenticate` on 401.
- [ ] Tests: token endpoint happy path, each error case, signature verification of the minted token against the JWKS.

Go topics: modules and layout, `net/http` handlers and middleware, graceful shutdown with `signal.NotifyContext`, goroutines and channels for the server lifecycle, configuration from the environment (`os.Getenv` / `os.LookupEnv`) with the lookup function injected for tests, structs and JSON tags, error-handling conventions, `crypto` packages, table-driven tests, `httptest`.

### Phase 2 — Authorization code with PKCE and OIDC

Ships browser login.

- [ ] Hard-coded user store (username, bcrypt-hashed password) and a minimal HTML login page via `html/template`.
- [ ] `GET /authorize` (RFC 6749 §4.1): validate `client_id`, `redirect_uri` exact match, `response_type=code`, `scope`, `state`; require PKCE `code_challenge` with `S256` (RFC 7636). Reject `plain`.
- [ ] Login and consent pages; consent skippable per client for first-party apps.
- [ ] Authorization code: single-use, short TTL, bound to `client_id`, `redirect_uri`, `code_challenge`, `nonce`.
- [ ] `POST /token` with `grant_type=authorization_code` and `code_verifier` check.
- [ ] ID token (OIDC Core §2, §3.1.3.6): `iss`, `sub`, `aud`, `exp`, `iat`, `auth_time`, `nonce`, `at_hash`, `sid`; `acr` fixed for now.
- [ ] Client registry entries carry `id_token_signed_response_alg` explicitly, with no zero-value default. Startup validation rejects any value outside the supported set, `{ES256}` until phase 3, with an error naming the client and the supported algorithms. This is a configuration error, so it fails at startup, not on the first login. Reason: OIDC Dynamic Client Registration §2 defaults an omitted field to RS256, and silently defaulting to ES256 instead would deviate from the spec; there is no registration endpoint, so the registry simply never allows the omission.
- [ ] `GET /userinfo` (OIDC Core §5.3) with bearer token; claims filtered by scope (`openid`, `profile`, `email`).
- [ ] `GET /.well-known/openid-configuration` (OIDC Discovery §3, §4), added now that its required fields are true. Same handler and same body as `/.well-known/oauth-authorization-server`: RFC 9068 §4 says the values MUST be consistent across the two publication methods. New fields in both documents: `authorization_endpoint`, `userinfo_endpoint`, `response_types_supported: ["code"]`, `subject_types_supported: ["public"]` (public only for now; pairwise is an optional add-on, see phase 3), `id_token_signing_alg_values_supported`, `scopes_supported` including `openid`, `code_challenge_methods_supported: ["S256"]` (RFC 8414 §2: if omitted, the server does not support PKCE), and `authorization_code` added to `grant_types_supported`. Known gap until phase 3: Discovery §3 says `id_token_signing_alg_values_supported` MUST include RS256, and this phase can only list ES256.
- [ ] Server-side IdP session cookie, `HttpOnly`, `Secure`, `SameSite=Lax`; `prompt=none` and `prompt=login`; `max_age` re-authentication.
- [ ] Tests: full code flow driven with `httptest` and a cookie jar, PKCE failure cases, `nonce` round-trip, single-use code, `redirect_uri` mismatch.

Go topics: `html/template`, cookies and sessions, `context`, `sync.Mutex` or channels for the in-memory stores, `time` handling, `errors.Is` / `errors.As`.

### Phase 3 — Lifecycle

Ships the parts that make a provider operable.

- [ ] Refresh tokens (RFC 6749 §6) with rotation and reuse detection (revoke the family on reuse, per RFC 9700 / OAuth 2.0 Security BCP).
- [ ] `POST /revoke` (RFC 7009) and `POST /introspect` (RFC 7662), with client authentication.
- [ ] Signing-key rotation: two keys live in the JWKS with distinct `kid`s, new tokens use the new key, old key retired after the longest token TTL.
- [ ] RS256 support alongside ES256. OIDC Core §15.1 says an OP MUST support RS256 for ID tokens, OIDC Discovery §3 says `id_token_signing_alg_values_supported` MUST include it (the gap left open in phase 2), and most clients in the wild default to it (Auth0, Okta, Entra, Hydra all issue RS256 by default; vendor behaviour, not spec). Serving two algorithms is the same exercise as serving two keys: each JWKS entry carries its own `kid` and `alg`, discovery lists both under `id_token_signing_alg_values_supported`, and the client's registered `id_token_signed_response_alg` (OIDC Dynamic Client Registration §2) selects one. Registration §2 makes RS256 the default when that field is omitted, so from this phase on a client with no explicit algorithm gets RS256, not ES256; the static registry keeps the field required (see phase 2), and if a registration endpoint is ever added an omitted field defaults to RS256 and an unsupported value returns `invalid_client_metadata` (Registration §3.3). RSA-2048 minimum; use PKCS#1 v1.5 as RFC 7518 §3.3 specifies for RS256. **The verifier chooses the algorithm from the key it looks up by `kid`, never from the token's `alg` header**, or algorithm confusion is back.
- [ ] Optional: pairwise subject identifiers (OIDC Core §8, §8.1). Each client, or each group of clients sharing a sector identifier, sees a different `sub` for the same user, so clients cannot correlate users by comparing `sub` values. Needs a per-client `subject_type` (Registration §2), a sector identifier (the host of the registered `redirect_uri`, or of `sector_identifier_uri` when redirect URIs span several hosts, Registration §5), and a derivation that is stable and not reversible, e.g. the §8.1 example `SHA-256(sector_identifier || local_account_id || salt)` with a server-side secret salt. The same `sub` must then appear in the ID token, `/userinfo`, and the logout token. Discovery lists `pairwise` in `subject_types_supported` only once this lands.
- [ ] Back-channel logout (OIDC Back-Channel Logout 1.0): logout token with `sid`, POSTed to registered client `backchannel_logout_uri`s.
- [ ] Persist clients, users, codes, and tokens in SQLite so restarts do not wipe state.
- [ ] Structured logging with `log/slog`; request IDs.
- [ ] Tests for rotation, reuse detection, introspection of revoked tokens, key rollover, and a token minted under each algorithm verifying only against its own key. `rsa.GenerateKey` at 2048 bits takes on the order of 100 ms versus microseconds for P-256, so generate the RSA test key once per package (`TestMain` or a checked-in PEM fixture), never per table case.

Go topics: `database/sql`, `log/slog`, goroutines for the logout fan-out with `sync.WaitGroup` and per-request timeouts.

### Phase 4 — Verify against real clients

Proves the server speaks the protocol, not just its own tests.

- [ ] A Go relying party in a separate `cmd/` using `github.com/coreos/go-oidc/v3` and `golang.org/x/oauth2`: discovery, login, ID-token verification, userinfo. Run it once against an ES256 client and once against an RS256 client. For the ES256 run, set `SupportedSigningAlgs` on the `go-oidc` verifier config explicitly; its default expects RS256 for the same Registration §2 reason and will reject an ES256 token otherwise.
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
- Metadata location for an issuer with a path: OIDC Discovery §4.1 appends the well-known suffix, RFC 8414 §3.1 inserts it between host and path, and vendors differ: Okta serves both documents appended and also the inserted RFC 8414 form, Keycloak-based deployments append both and 404 on the inserted form, and Entra serves only the OIDC document. RFC 8414 §5 allows appending only as a transition measure for the `openid-configuration` suffix, so an appended `oauth-authorization-server` is outside the spec. Why clients probe several locations, and why the issuer is compared as an exact string (Auth0's trailing slash).
- RFC 8414 metadata vs OIDC Discovery: which fields each requires (`authorization_endpoint` conditional vs REQUIRED, `jwks_uri` OPTIONAL vs REQUIRED, the OIDC-only `subject_types_supported` and `id_token_signing_alg_values_supported`), why a `client_credentials`-only server can publish the first but not the second, why `grant_types_supported` must be explicit, and the RFC 8414 contradiction between a REQUIRED `response_types_supported` and the §3.2 rule that empty claims MUST be omitted.
- Key rotation: why two keys must overlap in the JWKS and how long the old one must stay.
- ES256 vs RS256: what each spec says (RFC 7518 §3.1 treats them as Recommended+/Recommended; OIDC Core §15.1 mandates RS256 for OPs), the size and cost trade-offs (ECDSA signs fast and small, RSA verifies fast), the `R || S` vs DER encoding trap, why Go's hedged ECDSA nonces (1.20+) matter historically, and why a verifier must never take `alg` from the token.
- Refresh-token reuse detection: what "revoke the family" means and its false-positive risk on flaky networks.
- Back-channel logout: why it needs server-side state on the client, and why `sid` rather than `sub` is the right scope.
- What the server deliberately does not implement, and the RFC or BCP that recommends against each.

## Learning notes

Dated, free-form. Things that surprised you about Go, mistakes, idioms picked up, spec details that differed from expectation.

- 2026-09-18 — Repo created. Plan written. No code yet.
- 2026-09-28 — Asked why the plan says ES256 rather than RS256. Answer: ES256 was a pragmatic default (fast signing, small keys, instant keygen, and a JWS encoding lesson), not a spec requirement; OIDC Core §15.1 actually mandates RS256 support for OPs. Plan updated: ES256 stays for phase 1, RS256 added to phase 3 next to key rotation, phase 4 exercises both.
- 2026-10-04 — Compared the required metadata in RFC 8414 §2 and OIDC Discovery §3 before writing the handler. A `client_credentials`-only server satisfies the first but not the second, so phase 1 serves only `/.well-known/oauth-authorization-server` and `/.well-known/openid-configuration` moves to phase 2. Also added `golangci-lint` (all staticcheck checks, matching gopls) to the pre-commit checks.
