# Changelog

## Unreleased

## 0.2.1 - 2026-10-02

- Container-first distribution: configuration through `LOGPIT_*` environment variables
  (`LOGPIT_HTTP_TOKEN_FILE` for secrets), `logpit --healthcheck` and an image
  `HEALTHCHECK`, compose and Podman Quadlet examples, and a README that starts from the
  container. The release workflow now smoke-tests the image (healthcheck, auth, syslog
  ingestion, read-only filesystem, all capabilities dropped) before publishing it.
- Image fix: `/data` is now writable by the non-root user. The 0.2.0 image could not create its
  database and did not start; use 0.2.1 or later.

## 0.2.0 - 2026-10-02

- CEF parsing: UniFi (and other CEF) events are split into structured fields, indexed for
  full-text search and filterable with `f=key:value`. Schema migration to v2 (rebuilds the
  search index); older builds cannot open a migrated database.
- JSON ingestion accepts an optional `fields` object.
- Web UI: shows fields under each message (click one to filter), adds a `field:value`
  filter, and displays the server's reason on request errors.

## 0.1.1 - 2026-10-02

- Web UI: show a clear message and focus the token field when the API answers 401, and submit with Enter from the token field.

## 0.1.0 - 2026-10-01

- Initial version: syslog (UDP/TCP, RFC 5424/3164), JSON/journald ingestion over HTTP,
  SQLite + FTS5 storage with batching and retention, search API, minimal web UI, `/metrics`.
