# Changelog

## Unreleased

## 0.8.0 - 2026-10-03

- OpenTelemetry: `POST /v1/logs` accepts OTLP/HTTP logs (protobuf or JSON, with or without gzip) from the
  OpenTelemetry Collector and SDK exporters. Resource and record attributes, the scope and the trace and
  span ids become fields; the severity comes from `severityNumber` or the text. OTLP over gRPC is not
  supported.
- gzip and zlib: request bodies may now be compressed for Loki (gzip), GELF over HTTP (gzip, deflate) and
  OTLP, and GELF over UDP and TCP accepts gzip- and zlib-compressed messages (chunked UDP is still refused).
  Decompression is capped and checks the gzip checksum and length. Adds the pure-Rust `miniz_oxide` crate;
  Snappy, protobuf and gzip framing are decoded by small built-in readers.

- Saved views: `GET/POST /api/views` and `DELETE /api/views/{id}` keep named searches (the web UI's query
  string) on the server, and the UI gets a *Views* menu with *Save view* and *Delete*, shared by everyone
  who uses the instance. Stored in an extra table that leaves the schema version unchanged.

- Shipper: `logpit ship` follows the systemd journal and/or log files (rotation, truncation and resume
  handled) and sends them to a LogPit server through a disk spool, so nothing is lost while the server is
  down or the shipper restarts (at-least-once). Failed batches are retried by status (token refused and
  server errors wait; invalid batches are set aside). `contrib/logpit-ship.service` is an example unit.

- Top values: `GET /api/top?field=` returns the most frequent values of a host, app, severity or structured
  field (CEF, logfmt, JSON) among the entries matching the filters, with how many entries have it, how many
  distinct values there are and how many fall outside the list. `GET /api/fields` lists the fields present.
  The web UI gets a *Top values* panel with a field selector, bars, and click-to-filter.

## 0.7.0 - 2026-10-03

- Loki and GELF input: `POST /loki/api/v1/push` accepts Loki's JSON and snappy-compressed protobuf (Promtail,
  Grafana Alloy, Vector…), authenticating with the write token as bearer token or basic-auth password;
  labels map to host, app, level and fields. GELF is accepted at `POST /gelf` and on optional UDP and TCP
  listeners (`[gelf]` / `LOGPIT_GELF_*`); compressed and chunked GELF is refused with an explanation.
  Snappy and protobuf are decoded by small built-in readers, with no new dependency.

- Reload on `SIGHUP`: ingestion rules, alerts, rate limits, structured parsing, silence thresholds and
  webhook, API tokens and secret files, and the syslog TLS certificate files are applied without a restart
  or dropping connections. The reload is all-or-nothing (a typo, bad regex or unreadable certificate leaves
  the running settings untouched), unchanged parts keep their state, and settings that need a restart
  (storage, listen addresses) are reported. `contrib/logpit.service` gets `ExecReload`. New metrics
  `logpit_config_reloads_total` and `logpit_config_reload_failures_total`.

- Rate limiting: `[ingest.rate_limit]` (or `LOGPIT_RATE_LIMIT_*`) caps entries per second per host, with a
  burst allowance, and across all hosts, so one runaway sender cannot drown the others. Hosts beyond 4096
  share a bucket. Limited hosts still count as alive for silence alerts. New metrics
  `logpit_rate_limited_total` and `logpit_rate_limited_host_total{host}`.

- Pattern alerts: `[[alerts]]` notify when `count` entries matching a regex, host, app and/or severity arrive
  within `window_secs` (per host if asked), with a cooldown. They use the webhook configured under
  `[silence]` and the log, count entries after ingestion rules, and keep at most `count` timestamps per
  host. New metric `logpit_alerts_fired_total{rule}`.

## 0.6.0 - 2026-10-03

- Alert webhooks: `https://` URLs are supported (certificates are verified against the built-in Mozilla
  root list), with `webhook_format` (`json`, `slack`, `discord`, `ntfy`, `text`) and `webhook_headers`
  for tokens. Host names are clipped and escaped for the target (no `<!channel>`/mention pings, no header
  injection), and neither the URL nor the headers are logged. Adds the `webpki-roots` crate.

- Context: `GET /api/logs/{id}/context` returns an entry with up to 100 entries on each side, for the same
  host or all hosts. In the web UI, clicking a line's timestamp opens its context below it, with buttons for
  more lines, this host or all hosts, and close.

- Ingestion rules: `[[ingest.rules]]` drop noisy entries (by host, app, severity and/or a regex) and mask
  secrets (regex replacement in the message and in field values) before anything is stored, tailed or
  exported. Invalid rules stop startup with the rule's name; `logpit_rule_hits_total{rule,action}` counts
  what each rule did. Dropped entries still count as activity for silence alerts. Adds the `regex` crate.

- Structured data in messages: JSON objects and `key=value` (logfmt) pairs found in the message text are
  extracted into fields, so they can be filtered (`f=`), grouped in statistics (`group_by=field:`),
  searched and clicked in the UI like CEF fields. The message is kept as received. On by default;
  disable with `LOGPIT_PARSE_STRUCTURED=false`.

## 0.5.0 - 2026-10-03

- Syslog over TLS (RFC 5425): `syslog.tls_listen`, `tls_cert`, `tls_key` (or the `LOGPIT_SYSLOG_TLS_*`
  variables) enable a TLS 1.2/1.3 listener, and `tls_client_ca` requires client certificates. Built on
  rustls with the `ring` provider (no OpenSSL; the binary grows by about 1 MB). Certificates are loaded at
  startup and a bad one stops LogPit with a clear error. New metric `logpit_tls_handshake_failures_total`.
- Syslog over TCP and TLS now accepts octet-counted frames (`<length> <message>`) as well as
  newline-delimited lines, detected per message. Blank lines between messages are ignored.

## 0.4.9 - 2026-10-03

- Search text: `q` now supports `OR`, `-word` / `NOT word` exclusions, `"phrases"` and `prefix*`
  (everything is still compiled to quoted FTS5 strings, so input is never interpreted as FTS syntax).
  Plain words keep working as before. It applies to search, stats, hosts, export and the live tail.
- Paging: `GET /api/logs` accepts `before=<ts>:<id>` and returns an `X-Next-Cursor` header when a page is
  full. The web UI gets a *Load more* button, and a hint about the search syntax on the search box.

## 0.4.8 - 2026-10-03

- Export: `GET /api/export` streams the entries matching the search filters as NDJSON (re-ingestable
  through `/ingest`) or CSV, oldest first, with an optional `limit`. The web UI gets *Export* buttons
  (up to 100,000 entries).
- Backup: `logpit --backup <file>` writes a consistent, verified copy of the database with
  `VACUUM INTO`, safe while LogPit is running. The upgrade instructions now use it.

## 0.4.7 - 2026-10-02

- Web UI: the last search (filters, time range or zoomed window, chart grouping) is kept in the URL, so
  views can be shared and bookmarked and survive a reload. Each search is a history entry, so Back undoes
  it, including a zoom. The token is never put in the URL.

## 0.4.6 - 2026-10-02

- `GET /api/hosts` accepts `sort` and `order`, and applies `limit` after sorting. The *Hosts* panel now
  sorts on the server instead of in the browser, so a column sort covers every host and not only the
  200 busiest.

## 0.4.5 - 2026-10-02

- Web UI: the *Hosts* panel columns are sortable (click a header, again to reverse). The sort is remembered
  and keyboard accessible.

## 0.4.4 - 2026-10-02

- Per-host summary: `GET /api/hosts` returns entries, errors, warnings, last activity and silence state
  per host for the current filters, and the web UI shows it in a collapsible *Hosts* panel (click a host
  to filter on it).

## 0.4.3 - 2026-10-02

- Web UI: clicking a histogram bar zooms to its time bucket. The window is fixed and shown as an extra
  entry in the time-range selector; choosing another range leaves it. Live is switched off while zoomed.

## 0.4.2 - 2026-10-02

- Web UI: with *Live* on, the histogram is refreshed every 5 s (paused while the tab is hidden) and its
  time window slides with the clock. It keeps the filters of the last search even if the inputs are
  edited afterwards.

## 0.4.1 - 2026-10-02

- Web UI: the histogram can be stacked by severity, host or app, with a legend showing per-group
  totals; clicking a host or app in the legend filters on it.

## 0.4.0 - 2026-10-02

- Statistics: `GET /api/stats` counts entries per time bucket with the search filters, optionally
  grouped by host, app, severity or a structured field, and the web UI shows it as a histogram
  stacked by severity above the log table.

- Disk size cap: `storage.max_db_size_mb` / `LOGPIT_MAX_DB_SIZE_MB` evicts the oldest entries when the
  data in the database exceeds the cap (checked every minute, down to 90%). New metrics
  `logpit_db_used_bytes` and `logpit_size_evicted_total`. The retention task now always runs.

- Retention by severity: `[storage.retention_by_severity]` / `LOGPIT_RETENTION_BY_SEVERITY` override
  `retention_days` per severity (0 keeps a severity forever), e.g. 2 days of debug but 90 of errors.

- Token scopes: `LOGPIT_HTTP_TOKEN_WRITE` / `LOGPIT_HTTP_TOKEN_READ` (and `_FILE` variants) and
  `[[http.tokens]]` define tokens limited to ingestion or to search/tail. A token without the needed
  scope gets `403`. `http.token` is unchanged and keeps both scopes.

- Silence alerts: per-host detection of hosts that stop sending logs, configured with `[silence]`
  or `LOGPIT_SILENCE_AFTER_SECS`. Notifies an `http://` webhook (with retries) on alert and recovery
  and exposes `logpit_host_silent{host}` on `/metrics`.

## 0.3.0 - 2026-10-02

- Live tail: `GET /api/tail` streams newly ingested entries as server-sent events, with the same
  filters as search. The web UI's *Live* toggle now uses it instead of polling.
- Quadlet example: `HealthCmd` must use the exec form (`CMD /logpit --healthcheck`); the shell form
  made Podman report the container as unhealthy because the image has no shell.

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
