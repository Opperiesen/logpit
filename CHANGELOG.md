# Changelog

## Unreleased

## 0.19.0 - 2026-10-05

- Web UI: a *Traces* view (`/traces`): the spread of the traces' durations and the latest traces with
  their operation, service, duration, spans, errors and services, filtered by service, host, operation,
  minimum duration, range and errors; and each trace as a waterfall (`/traces/<id>`) of its spans on one
  time line, by parent, coloured by service, failures in red, keyboard-navigable, with the selected span's
  timing, status, attributes, events and log lines. The search page's *trace* panel links to it.

- `GET /api/traces` lists the latest traces (root span, start, duration, span and error counts, services
  and hosts), filtered by window, service, host, a word of a span's name, minimum duration and errors;
  `GET /api/traces/<id>` gives a trace's spans. Tokens limited to some hosts or apps see only what they
  may read.

- OpenTelemetry traces: `POST /v1/traces` (protobuf or JSON) and gRPC `TraceService/Export` store spans
  (ids and parent, name, kind, timing, status, service, host, attributes and events, bounded), once each
  even when sent again, purged with the logs' retention; `logpit_spans_stored_total` and
  `logpit_spans_rejected_total` count them. The spans table does not change the schema version: an older
  LogPit still opens the database and ignores it.

## 0.18.0 - 2026-10-05

- Web UI host page: its latest twelve lines on top, which arrive live through the tail, with *Pause*.

- Web UI admin: a *Storage* section with the database's size (and its cap), entries, oldest entry and
  last day's arrivals, where its size is heading at that pace, and each host's share of the entries;
  `GET /api/storage` (admin scope) gives the figures.

- Pattern alerts can be put on mute: *Mute 1 h* on a notification in the page or on a rule under
  `/admin`, or `GET`/`POST /api/mutes` (admin scope). A muted rule's alerts are still logged and recorded,
  marked *muted*, without telling the webhook or e-mail; mutes live in memory, at most a week.

- Web UI admin: an alert rule can be edited in place (name, lines, window, quiet period, per host),
  keeping its pattern and other conditions.

- Web UI: *Notify me of new alerts* under Settings. A new alert shows in the page with a *Show* button
  that zooms to it, and, while the tab is in the background, as a system notification once the browser
  allows it (over HTTPS or `localhost` only); alerts are then checked every minute even in the background.

- Alerts from the web UI: a bell on each message pattern creates a pattern alert (so many lines like it
  within so many minutes, per host or overall) that runs at once beside the configuration's
  `[[alerts]]`; `/admin` lists and deletes them. They are kept in the database and managed through
  `GET`/`POST /api/alert-rules` and `DELETE /api/alert-rules/<id>` (admin scope). The new table does not
  change the schema version: an older LogPit still opens the database and ignores it.

- Web UI views: in local time, times read `01:08:02` today, `yesterday 01:09:02`, then `Fri, Oct 2
  01:09:02` (with the year when it differs), instead of a full date on every line.

- Web UI: the *Host* and *App* filters suggest the names of the current time window; picking one
  searches.

- Web UI board: the states read *Silent*, *Failing*, *Degraded* and *Healthy* (formerly *Cancelled*,
  *Disrupted*, *Delayed* and *On time*), and the command palette names it *Board of the hosts*.

## 0.17.0 - 2026-10-05

- Web UI redesign of the search page, a live match centre for the homelab: a command bar with a Live
  pill that pulses, a host rail where each host has a dot that pulses while it talks, its recent form as
  five marks calibrated on its own window, its counts and a volume bar; a momentum curve (errors pushed
  below the line) that morphs between refreshes, with a tooltip, a *now* edge and an alert timeline;
  dragging across it dims the lines outside the range before zooming. Live lines slide in, counts roll
  to their new value, a line's context is prefetched on hover. New night-stadium dark and pitch-side
  light themes; violet is kept for your focus (selection, active filters).

- Web UI: the board, host, admin and compare views join the same world: the command bar with a view
  switcher, hairline tables, forms on a panel, the host's week as a momentum curve, and on the board a
  pulse dot, the recent form and rolling counts per host, with each state as a tinted pill.

- `GET /api/hosts` takes `form=N` (1 to 24): with a `since`, each host gets its `form`, the window cut in
  N slices with their entries, errors and warnings.

- Web UI: structured fields follow the message on its line instead of taking a line of their own,
  nearly twice as many entries per screen; past the first three, a `+N` shows them all. The Hosts
  panel starts open on a wide screen, and stays closed once closed.

## 0.16.1 - 2026-10-04

- UniFi CEF events take their time from `UNIFIutcTime`, which is UTC with milliseconds, instead of
  the syslog stamp, which has neither: they are right whatever `syslog.timezone` says.

## 0.16.0 - 2026-10-04

- `syslog.timezone` accepts a zone name such as `Europe/Paris`, read from `/usr/share/zoneinfo` (mount
  it into the `scratch` image), or the POSIX rule it stands for (`CET-1CEST,M3.5.0,M10.5.0/3`), which
  needs no file: RFC 3164 stamps then follow daylight saving time, which a fixed offset cannot.

- GELF over UDP accepts chunked messages, which Docker's GELF driver sends for anything over
  about 1.4 KB once compressed and which were refused until now. Chunks are reassembled in any order
  within five seconds, with at most 8 MiB held by incomplete messages; what is given up is counted as
  rejected.

- Statistics: `bucket` accepts the same durations as the Loki API (`1h30m`, `1.5h`, `1w`),
  still at least one second.

## 0.15.0 - 2026-10-04

- Web UI views: a departure board of the hosts for a wall screen (`/board`), a page per host
  (`/host/<name>`), an administration page for maintenance windows, tokens and the audit trail (`/admin`,
  admin scope) and a comparison of two time windows (`/compare`). They are one more embedded page sharing
  the main page's theme (`src/web/theme.css`), served minified and gzipped with the same headers; each view names its
  browser tab, and the board keeps the keyboard focus on the same host across its refreshes.

- Web UI: alerts as ticks under the chart, maintenance windows shading it (admin scope), *Copy as CLI*
  for the current search, trace lines placed on a time bar, and a welcome with ready-made commands on a
  server that has received nothing yet.

- Web UI: keyboard shortcuts (`/` search, `L` live, `J`/`K` move between lines, `Enter` context, `Esc`
  close), the active filters of the last search as removable chips under the header, and the access
  token moved into a *Settings* panel (formerly *Display*) that opens on its own when a token is needed.

- Web UI: the Hosts panel sorts by errors by default, silent hosts first; the hour scale under the chart
  scrolls the list to an hour (or zooms to it when it is not loaded); in Live mode, reading further down
  keeps its place while lines arrive, with a *new lines above* pill.

- Web UI: a **?** popover with the search syntax and clickable examples; *copy*, *JSON* and *link*
  actions on the hovered or current line (with a fallback for plain HTTP, where the clipboard API is
  unavailable); an empty result offers a wider time range and to remove the filters.

- Web UI: saving and deleting a view ask in place instead of through browser dialogs, and the relative
  ages in the side panels refresh every 30 seconds.

- Web UI: the side rail sits beside the list from 1000px wide (300px, 340px from 1280px) and comes after
  the list for the keyboard; the hour scale is one tab stop walked with the arrow keys. A test keeps the
  page under 32 KiB compressed.

- Web UI: search words and regex matches are highlighted in messages; a severity in the chart legend
  sets the minimum level; a structured field value can be excluded (Alt-click, or − in *Top values*);
  unread alerts are counted on the Alerts title and in the tab title, with error lines that arrive while
  the tab is hidden; the list marks where the previous visit stopped; a *Custom…* time range with two
  date-times and a *Zoom out* button; a command palette on Ctrl+K / Cmd+K.

- The web UI is served without its indentation and comments and gzipped when the browser accepts it
  (`Content-Encoding: gzip`, `Vary: Accept-Encoding`): about 27 KB on the wire instead of 110 KB. Its
  size budget now applies to what is served. The chart legend is one tab stop walked with the arrow
  keys, and choosing *Custom…* from the keyboard no longer moves the focus into the form.

- Web UI redesign: the log stream is set like a railway timetable, grouped under hour bands that state the
  hour once with their entry, error and warning counts and stay pinned while scrolling; each line leads with
  its minutes and seconds. Light theme in timetable paper, dark theme in departure-board navy, system fonts
  only. Hosts, top values, message patterns and alerts move to a left rail on wide screens; on phones the
  secondary filters fold behind a *Filters* button and each line stacks so the message gets the full width.
  The chart gets an hour scale. Severity colors meet WCAG AA contrast in both themes, every clickable value
  works from the keyboard, and live lines are inserted in batches and highlighted for three seconds.

- Trace correlation: `trace_id` and `span_id` are normalized on every ingestion path (OTLP, `traceId`
  and similar fields in JSON logs, Loki labels, a W3C `traceparent`) and lower-cased when hexadecimal.
  `trace=<id>` searches a trace across hosts (API, export, live tail, `logpit search --trace`), and the web
  UI shows a **trace** link on lines that have one, listing the whole trace with the time since its
  first entry. `key=value` extraction now falls back to the first line of a multi-line message.

- Multi-line events in `logpit ship`: `--multiline-start REGEX` joins the lines that follow a matching
  line (stack traces, wrapped output) into one entry, with `--multiline-wait-ms` and
  `--multiline-max-lines`.

- Maintenance windows (`[[maintenance]]`, `/api/maintenance`): notifications about the hosts a one-off or
  recurring (daily or weekly, UTC) window covers are held back from the webhook and e-mail, and recorded
  in the alert history as muted. Windows can also be started and ended through the admin API.

- Ingestion quotas per token (`events_per_sec`, `events_per_day` in `[[http.tokens]]`): a write token over
  its budget gets `429` with `Retry-After`; `logpit_quota_rejected_total{token}` counts the refusals.

## 0.14.0 - 2026-10-03

- OTLP over gRPC: `LogsService/Export` is served on the HTTP port (HTTP/2, `h2c` without TLS and ALPN `h2`
  with HTTPS), with the write token as `authorization` metadata, gzip message compression and the same
  mapping as OTLP/HTTP. Adds the `h2` crate through axum's `http2` feature.

- E-mail notifications (`[email]`): the alerts LogPit raises can be sent over SMTP (STARTTLS, implicit TLS
  or plain, `AUTH PLAIN`/`LOGIN`) to a list of recipients, filtered by kind and limited per hour, beside
  the webhook. The alert history shows the e-mail outcome and `/metrics` counts sent, failed and
  suppressed messages; applied by `SIGHUP`.

- Web UI display preferences (the cog in the header, kept in the browser): light, dark or system theme,
  local time, UTC or ISO 8601 times, compact density, wrapped or single-line messages, and which columns
  (time, level, host, app, fields) are shown.

- Retention rules (`[[retention]]`: `host`, `app`, `severity`, `days`): entries are kept for the time of
  the first rule they match (patterns with `*` and `?`, `days = 0` for ever), in front of the
  per-severity retention, with the cold archive honoured. Token restrictions on `apps` now take patterns
  like `hosts` do.

## 0.13.0 - 2026-10-03

- HTTPS: `http.tls_cert` and `http.tls_key` (and optional `http.tls_client_ca` for mutual TLS) serve the
  web UI and API over TLS. Handshakes run concurrently with a timeout, `SIGHUP` reads the certificate files
  again, `logpit --healthcheck` follows the configuration, and failed handshakes are counted with the syslog
  TLS ones.

- Alert history: every notification (silence, pattern alerts, new patterns and surges, volume) is
  recorded with its kind, host, message and whether the webhook took it, kept for `silence.history_days`
  (default 30, `0` = last 200 in memory) and served by `GET /api/alerts` (filters `kind`, `host`,
  `since`, `until`, `limit`; limited tokens only see their hosts) and a new *Alerts* panel in the web UI.

- Scheduled backups (`[backup]`: `dir`, `every_hours`, `keep`): LogPit writes a consistent copy of the
  database (`logpit-YYYYMMDDTHHMMSSZ.db`) on a schedule, keeps the newest few and never touches other
  files, with `logpit_backups_total`, `logpit_backup_errors_total` and last-success gauges.

- RFC 3164 syslog timestamps: `syslog.timezone` (`reception` by default, `utc`, `local` or a fixed offset
  such as `+02:00`) reads the year-less, zone-less `Oct  3 14:00:00` stamp in the sender's zone, taking
  the current year unless that is more than a day ahead. Impossible dates fall back to the arrival time;
  applied by `SIGHUP`.

## 0.12.1 - 2026-10-03

- Fix: shutdown no longer hangs while a syslog TCP connection, a live tail or any other HTTP
  connection is open (`docker stop` used to end in a `SIGKILL` that lost the last batch); the
  entries already queued are still written.
- Fix: a batch the writer could not store because the database was busy (a long purge, a backup) is
  kept and retried instead of being dropped, and retention deletes expired entries a chunk at a time,
  so the writer never waits on one huge transaction.
- Fix: a NUL byte in the search text made the search fail with a server error.
- Fix: extreme `since`/`until` values could overflow in `/api/stats`; time bounds are now clamped.
- Host and app names longer than 255 bytes are cut on ingestion.
- The web UI is served with a Content-Security-Policy, `X-Frame-Options: DENY`, `nosniff` and
  `Referrer-Policy: no-referrer`.
- Internal simplifications (shared helpers, chrono's RFC 3339 parser for Loki times); API server
  errors now read `<operation> failed`.
- Tests: end-to-end HTTP API tests (scopes, restricted tokens, audit, limits) and a deterministic
  fuzz smoke test of every parser that reads untrusted input.

## 0.12.0 - 2026-10-03

- Command line: `logpit search` prints the entries matching the usual filters (text, host, app, level,
  field comparisons, regex, tag, time range) oldest first, paging through up to a million of them, and
  `logpit tail` prints the last few and follows new ones, with text, JSON or NDJSON output, a token from a
  file or the environment, and reconnection. Both are in the same binary as the server.

- Volume alerts (`[volume]`, off by default): a webhook notification when a host sends several times
  more, or a fraction of, its usual number of entries per window (zero included), against a moving
  baseline seeded from the stored history. Cooldown per host, a minimum baseline for small hosts,
  Prometheus counters and `SIGHUP` reloading.

- Host tags (`[[tags]]`): names for sets of hosts, written as exact names or `*`/`?` patterns, resolved
  when a query runs. `tag=` filters every search endpoint and the live tail, `GET /api/tags` lists them,
  `GET /api/hosts` shows each host's tags, metric rules can use a `tag` label, and tokens can be limited
  with `tags = [...]` (their `hosts` now accept patterns too). The web UI gets a tag selector and a
  Tags column in the Hosts panel.

- Regex parsers (`[[parsers]]`): the named groups of a regular expression become structured fields,
  and special groups can set the host, app, level, message and timestamp (`rfc3339`, `unix`, `unix_ms` or
  a strftime pattern). First match wins, filters by host, app and severity, linear-time regexes, a
  `logpit_parser_matched_total` counter and `SIGHUP` reloading.

## 0.11.0 - 2026-10-03

- Cold archive (`storage.archive_dir`): entries removed by retention or the size cap are first appended
  to daily gzip NDJSON files (`YYYY/MM/logpit-YYYY-MM-DD.ndjson.gz`, readable with `gunzip -c`), deleted
  only after they are synced, with `logpit_archived_total` and `logpit_archive_errors_total`. New
  `logpit restore` subcommand loads archive files (or any `/ingest` NDJSON) into a server.

- Forwarding (`[[forward]]`): a filtered copy of the stored entries goes to an HTTP endpoint as NDJSON
  (the `/ingest` format, with headers for a token) or to a syslog server over UDP or TCP (RFC 5424,
  structured fields as structured data). Each target has a bounded queue, retries failed batches
  five times, and exposes sent, dropped and failed counters. Needs a restart to change.

- Deduplication (`[ingest.dedup]`, off by default): runs of identical messages (same host, app,
  severity and text) are stored once, the repeats within `window_secs` are counted, and one summary
  entry (`… [repeated N more times over Ds]`, field `repeats`) replaces them. Alerts, metrics and rate
  limits still see every entry. Summaries are flushed at shutdown; applied by `SIGHUP`.

- Metrics from logs: `[[metrics]]` rules count the entries that match a regex, host, app or severity as
  Prometheus counters on `/metrics` (`logpit_log_<name>_total`), per `host`, `app`, `level` or structured
  field labels with a series cap, and can sum a numeric field. Applied by `SIGHUP`.

## 0.10.0 - 2026-10-03

- Loki query API for Grafana: `query_range`, `query`, `labels`, `label/<name>/values` and `series` under
  `/loki/api/v1/`, answering a LogQL subset (stream selectors, line filters, `| json`/`| logfmt`, label
  filters, `count_over_time` and `rate` with `sum by`). Streams are labelled `host`, `app` and `level`,
  other labels are structured fields; the `read` scope and read restrictions apply.

- New-pattern alerts (`[new_patterns]`, off by default): a webhook notification when a message template
  never seen before appears, and optionally when a known template surges to several times its usual
  count per window. Learns the templates of stored entries at startup and stays quiet for `learn_secs`,
  throttled by `max_per_minute`, ignorable by regex, with Prometheus counters; applied by `SIGHUP`.

- Search: `f=` accepts comparisons on structured fields (`status>=500`, `duration<2.5`, `act!=block`,
  `src~^10\.`) and the new `re=` filters the message with a regular expression (linear-time engine, size
  bounded). They work in every search endpoint, saved views, the live tail and the web UI, which gets a
  *Regex on message* box.

- The audit trail is now stored in the database (`http.audit_retention_days`, default 30, purged hourly),
  survives restarts and can be filtered on `/api/audit` with `since`, `until`, `token` and `refused`.
  `audit_retention_days = 0` keeps the previous in-memory behaviour.

## 0.9.0 - 2026-10-03

- Access control: `[[http.tokens]]` entries can be named, given the new `admin` scope and limited to some
  `hosts` and `apps` for reading; every read endpoint (search, context, live tail, statistics, hosts, top
  values, patterns, export) keeps to what the token may see, and saved views are refused to a limited token.
  `GET /api/audit` (the last 1000 refused requests and reads, also logged as `logpit::audit`) and
  `GET /api/tokens` (names, scopes and limits, never secrets) need `admin`. `LOGPIT_HTTP_TOKEN` is named
  `admin` and has every scope.
- Message patterns: `GET /api/patterns` groups the matching entries by message template (numbers and ids
  masked), with counts, hosts, the most severe level, an example and the count in each half of the window
  as a trend, plus a *Message patterns* panel in the web UI.
- Web UI: dragging across the histogram zooms to the selected time range.

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
