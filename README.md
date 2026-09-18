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
