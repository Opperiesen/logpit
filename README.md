# LogPit

A small, self-contained log aggregator written in Rust, shipped as a container.
One static binary in a `scratch` image, a single SQLite file, a few MB of RAM — a
lightweight alternative to Graylog or ELK for homelabs and small servers
(Proxmox, routers, LXC containers…).

## Features

- **Ingestion**: OpenTelemetry (OTLP over HTTP and gRPC), the Loki push API (Promtail, Alloy…), GELF, syslog over UDP, TCP and TLS (RFC 5424 and RFC 3164, newline or octet-counted
  framing, optional client certificates), and HTTP
  (`POST /ingest`) accepting NDJSON or a JSON array, including raw
  `journalctl -o json` output.
- **Host tags**: `[[tags]]` name sets of hosts (`prod`, `dmz`…), to filter on, label metrics with and restrict
  tokens to.
- **Regex parsers**: `[[parsers]]` turn the named groups of a regular expression into fields (and host,
  level, timestamp), for access logs, sshd, firewalls and other plain-text formats.
- **Structured fields**: CEF events (e.g. UniFi's SIEM export) are parsed into
  key/value fields, which are indexed for search and filterable by exact match.
- **Storage**: SQLite (WAL) with FTS5 full-text search, batched writes,
  automatic retention.
- **Export and backup**: stream matching entries as NDJSON or CSV, and take consistent database
  backups while LogPit runs.
- **Search**: `GET /api/logs`, volume statistics per time bucket (`GET /api/stats`) and per host (`GET /api/hosts`), a live tail (`GET /api/tail`, server-sent events) and a
  minimal built-in web UI at `/` with a *Live* toggle.
- **Robustness**: bounded queue with drop counters (no unbounded memory),
  message size limits, TCP connection limits and idle timeouts, graceful
  shutdown that flushes pending writes, parser tested against malformed input.
- **Container-native**: multi-arch image (amd64, arm64), non-root, runs read-only
  with all capabilities dropped, configured through environment variables,
  built-in healthcheck, token via secret file.
- **Grafana**: the Loki query API (`/loki/api/v1/query_range`, `labels`…), so Grafana's Loki data source can
  browse and chart LogPit with a LogQL subset.
- **Message patterns**: `GET /api/patterns` folds messages that differ only by numbers or ids into one
  template with counts and trend, to see what is noisy or growing.
- **Access control**: named tokens with `read`, `write` and `admin` scopes, optional limits to some hosts or
  apps for reading, and an audit trail of refused requests and reads.
- **New-pattern alerts**: get notified when a message pattern never seen before appears, or a known one
  suddenly surges.
- **Command line**: `logpit search` and `logpit tail` query a server from the terminal, with the same filters
  as the API, and text, JSON or NDJSON output.
- **Volume alerts**: get notified when a host sends far more or far fewer logs than it usually does.
- **HTTPS**: the web UI and API can be served over TLS directly, with certificate reload and optional client
  certificates.
- **E-mail notifications**: the alerts can also go out over SMTP (STARTTLS, TLS, authentication).
- **Alert history**: every notification LogPit raises is kept and listed in `GET /api/alerts` and the web UI,
  with whether the webhook took it.
- **Silence alerts**: get notified (webhook + Prometheus gauge) when a host stops sending logs.
- **Forwarding**: `[[forward]]` sends a filtered copy of the entries to another LogPit, a collector or a SIEM,
  over HTTP (NDJSON) or syslog (RFC 5424, UDP or TCP).
- **Ingestion quotas**: per-token limits on events per second and per day, answered `429` beyond them.
- **Maintenance windows**: hold the notifications about some hosts back during planned work, from the
  configuration or the API.
- **Multi-line events**: `logpit ship` joins stack traces and wrapped output into one entry.
- **Trace correlation**: `trace_id` and `span_id` are normalized from OpenTelemetry, JSON logs and
  `traceparent`, and one search or one click shows a request across hosts.
- **Retention rules**: `[[retention]]` keeps entries of some hosts, apps or severities for a different time.
- **Cold archive**: entries leaving through retention or the size cap are first written to daily gzip files,
  readable with `zcat` and reloadable with `logpit restore`.
- **Deduplication**: runs of identical messages are stored once, with a summary entry for the repeats.
- **Observability**: Prometheus metrics at `/metrics`, health at `/healthz`, and counters derived from the
  logs themselves (`[[metrics]]`).

## Quick start

```sh
TOKEN=$(openssl rand -base64 24 | tr -d '=+/\n')
podman run -d --name logpit --restart always \
  -p 514:5514/udp -p 514:5514/tcp -p 8080:8080 \
  -e LOGPIT_HTTP_TOKEN="$TOKEN" \
  -v logpit-data:/data \
  ghcr.io/opperiesen/logpit:0.17.0
echo "$TOKEN"
```

(`docker` works the same.) Open <http://localhost:8080> and enter the token (the *Settings* panel opens on its own when one is needed).
Pin a version tag in production; `latest` follows the newest release.

### Compose and Quadlet

Ready-to-use files live in [`contrib/`](contrib/):

- [`contrib/compose.yaml`](contrib/compose.yaml) — `docker compose` / `podman compose`.
- [`contrib/quadlet/logpit.container`](contrib/quadlet/logpit.container) — a Podman
  Quadlet unit (systemd-managed container). The token is a Podman secret, and
  upgrading means editing the image tag and restarting the unit.

### Upgrading and rolling back

Change the image tag and recreate the container; the data volume is kept. Read the
[changelog](CHANGELOG.md) first: some releases migrate the database schema, and a
migrated database cannot be opened by older versions, so **back up the database
before upgrading** (see [Export and backup](#export-and-backup)). Rolling back means
restoring that backup and the previous tag.

## Configuration

Environment variables win over the config file. All are optional.

| Variable | Default (in the image) | Meaning |
|---|---|---|
| `LOGPIT_HTTP_TOKEN` | *(none)* | Full-access token (read and write) for `/ingest` and `/api/*`. **Set a token.** |
| `LOGPIT_HTTP_TOKEN_FILE` | | Read the token from a file (container secret). Not with `LOGPIT_HTTP_TOKEN`. |
| `LOGPIT_HTTP_TOKEN_WRITE`, `_FILE` | | Token that may only ingest (`POST /ingest`); for log shippers |
| `LOGPIT_HTTP_TOKEN_READ`, `_FILE` | | Token that may only search and tail (`/api/logs`, `/api/tail`); for the UI and dashboards |
| `LOGPIT_HTTP_LISTEN` | `0.0.0.0:8080` | Web UI and API address |
| `LOGPIT_HTTP_TLS_CERT`, `LOGPIT_HTTP_TLS_KEY` | | PEM certificate chain and private key: serve the web UI and API over [HTTPS](#https) (both or neither) |
| `LOGPIT_HTTP_TLS_CLIENT_CA` | | PEM CA file: HTTPS clients must present a certificate issued by it |
| `LOGPIT_SYSLOG_UDP_LISTEN` | `0.0.0.0:5514` | Empty string disables UDP syslog |
| `LOGPIT_SYSLOG_TCP_LISTEN` | `0.0.0.0:5514` | Empty string disables TCP syslog |
| `LOGPIT_GELF_UDP_LISTEN`, `LOGPIT_GELF_TCP_LISTEN` | *(off)* | GELF listeners, e.g. `0.0.0.0:12201` (see [Loki and GELF](#loki-and-gelf)) |
| `LOGPIT_SYSLOG_TIMEZONE` | `reception` | How RFC 3164 timestamps are read: `reception`, `utc`, `local`, an offset like `+02:00`, a zone like `Europe/Paris` or a POSIX rule (see [RFC 3164 timestamps](#rfc-3164-timestamps)) |
| `LOGPIT_SYSLOG_TLS_LISTEN` | *(off)* | Address of the syslog-over-TLS listener, e.g. `0.0.0.0:6514`; needs the next two |
| `LOGPIT_SYSLOG_TLS_CERT`, `LOGPIT_SYSLOG_TLS_KEY` | | PEM certificate chain and private key for the TLS listener |
| `LOGPIT_SYSLOG_TLS_CLIENT_CA` | | PEM CA file: clients must then present a certificate issued by it |
| `LOGPIT_STORAGE_PATH` | `/data/logpit.db` | SQLite file |
| `LOGPIT_RETENTION_DAYS` | `14` | `0` disables purging |
| `LOGPIT_RATE_LIMIT_PER_HOST`, `_BURST`, `_GLOBAL` | `0` (off) | Rate limits, see [Rate limiting](#rate-limiting) |
| `LOGPIT_PARSE_STRUCTURED` | `true` | Extract JSON and `key=value` data from messages into fields |
| `LOGPIT_ARCHIVE_DIR` | | Directory for the [cold archive](#cold-archive): entries are written there before retention or the size cap removes them |
| `LOGPIT_MAX_DB_SIZE_MB` | `0` | Soft cap on the database size; the oldest entries are evicted beyond it. `0` = off (see below) |
| `LOGPIT_RETENTION_BY_SEVERITY` | | Per-severity retention, e.g. `debug=2,info=7,err=90` (see below) |
| `LOGPIT_SILENCE_AFTER_SECS` | `0` | Alert when any host is silent this long; `0` disables |
| `LOGPIT_SILENCE_WEBHOOK_URL` | | `http://` URL notified on alerts and recoveries |
| `LOGPIT_CONFIG` | `/etc/logpit/logpit.toml` | TOML file with the same settings |

For more settings (batching, queue size, message limit) mount your own TOML over
`/etc/logpit/logpit.toml`; see [`logpit.example.toml`](logpit.example.toml). Unknown
keys are rejected at startup.

The image runs as an unprivileged user, so syslog listens on 5514 inside the
container and you map it to 514 when publishing. With a bind mount instead of a
named volume, make the directory writable by uid 65532.

### Token scopes

Give each client the least access it needs, so a compromised shipper cannot read your logs:

```sh
podman run … \
  -e LOGPIT_HTTP_TOKEN_WRITE_FILE=/run/secrets/ship \
  -e LOGPIT_HTTP_TOKEN_READ_FILE=/run/secrets/view …
```

A write token can only use the ingestion endpoints (`/ingest`, Loki, GELF, OTLP), a read token only the
search and statistics endpoints (`/api/logs`, `/api/tail`, `/api/stats`…); the wrong scope gets `403`
(a missing or unknown token gets `401`). `LOGPIT_HTTP_TOKEN` keeps every scope (it is named `admin`),
and any token turns authentication on. Further tokens can be added in the TOML file with
`[[http.tokens]]` entries. `/healthz` and `/metrics` stay open.

### Named tokens, restrictions and audit

A `[[http.tokens]]` entry can be named, given the `admin` scope, and limited to some hosts or apps:

```toml
[[http.tokens]]
token = "…"
name = "web-team"            # shown in the audit trail; default token-1, token-2… by position
scopes = ["read"]
hosts = ["web1", "web*"]     # only these hosts (names or * and ? patterns); empty or absent: every host
tags = ["dmz"]               # and the hosts of these [[tags]]
apps = ["nginx*"]            # and only these apps (names or patterns); hosts/tags and apps apply together

[[http.tokens]]
token = "…"
name = "ops"
scopes = ["read", "admin"]
```

Names use letters, digits, `_`, `-` and `.`, and each is unique (`LOGPIT_HTTP_TOKEN` is `admin`, the
`LOGPIT_HTTP_TOKEN_READ`/`_WRITE` tokens are `env-read` and `env-write`). A token with `hosts` or `apps`
needs the `read` scope, since it limits reading only: every read endpoint (search, context, live tail,
statistics, hosts, top values, patterns, export) keeps to the allowed entries whatever filters are asked
for, an entry outside them is answered `404`, and the context of an entry never shows neighbours outside
them. Saved views are shared by everyone and can name hosts or search text, so they answer `403` to a
limited token (the web UI then hides the *Views* menu). Counts such as `distinct` and the totals of the
Hosts panel only cover what the token may read. `GET /api/stats` still starts at the oldest entry of the
whole database when `since` is absent. Restrictions are exact names, not patterns, and are reloaded
by `SIGHUP` with the tokens.

The `admin` scope opens the audit and token lists below, and the [maintenance windows](#maintenance-windows) API:

```sh
curl -s -H "Authorization: Bearer $ADMIN" 'http://localhost:8080/api/audit?limit=50&refused=true'
# [{"ts":1791024064467,"token":"web-team","method":"GET","path":"/api/logs","query":"host=db1","status":200,"peer":"10.0.0.8:51234"}, …]
curl -s -H "Authorization: Bearer $ADMIN" http://localhost:8080/api/tokens
# [{"name":"web-team","scopes":["read"],"hosts":["web1","web2"],"apps":["nginx"]}, …]   (never the secrets; a token's
#  events_per_sec and events_per_day appear when set)
```

The audit trail is stored in the database for `http.audit_retention_days` (default 30; env
`LOGPIT_AUDIT_RETENTION_DAYS`; changing it needs a restart), so it survives restarts and is part of
`logpit --backup`; `0` keeps only the last 1000 events in memory instead. Each event is also written to
the log (target `logpit::audit`). `/api/audit` takes `limit` (default 100, at most 10 000, or 1000 in
memory), `since` and `until` (Unix ms), `token` (a token name) and `refused=true` for the refusals only.
Events are written by a background thread, so requests never wait for the database, and are dropped
(with a warning in the log) if it falls 4096 events behind. It records every refused request (`401` and `403`, with the token's name when
the token is known but lacks the scope), and the requests that read entries or change shared data: search,
context, export, live tail, saved views being added or deleted, and the audit and token lists
themselves. Ingestion and the web page's background refreshes (statistics, hosts, top values, patterns)
are left out, or they would drown the rest. `query` is the query string, which includes the search
text, shortened to 200 characters; `peer` is the address of the connection, which is a reverse proxy's
behind one. Nothing is recorded while authentication is off. Old events are purged at startup and
every hour; they are not touched by the size cap or by log retention.

### Ingestion quotas

A token that writes can be capped, so one noisy shipper cannot fill the database or push the others out:

```toml
[[http.tokens]]
token = "…"
name = "shipper-web"
scopes = ["write"]
events_per_sec = 200      # sustained rate; a burst of ten seconds' worth is allowed
events_per_day = 5000000  # per UTC day
```

Both are optional (at least 1, and the token needs the `write` scope). Every ingestion endpoint counts
(`/ingest`, `/loki/api/v1/push`, `/gelf`, OTLP over HTTP and gRPC): entries are counted once a request has
run, so a request can go over a limit by its own size, and the next ones get `429 Too Many Requests`
with a `Retry-After` header (seconds until the rate recovers, or until midnight UTC for the daily total).
Shippers such as `logpit ship` treat `429` as a reason to retry later, and gRPC clients see `UNAVAILABLE`.
Counters live in memory and start again from zero after a restart; the limits themselves are reloaded by
`SIGHUP` with the tokens. `/metrics` has `logpit_quota_rejected_total{token}` and `GET /api/tokens` shows
each token's limits. Syslog and GELF over UDP or TCP have no token, so use the
[rate limits](#rate-limiting) there.

## HTTPS

LogPit can serve the web UI and the API over TLS itself, so a token never crosses the network in clear
text and a reverse proxy is optional:

```toml
[http]
tls_cert = "/etc/logpit/tls/fullchain.pem"   # PEM, the server certificate first, then intermediates
tls_key = "/etc/logpit/tls/privkey.pem"      # env: LOGPIT_HTTP_TLS_CERT, LOGPIT_HTTP_TLS_KEY
# tls_client_ca = "/etc/logpit/tls/clients-ca.pem"   # also require client certificates (mutual TLS)
```

```sh
podman run … -v /etc/letsencrypt/live/logs.example.com:/tls:ro \
  -e LOGPIT_HTTP_TLS_CERT=/tls/fullchain.pem -e LOGPIT_HTTP_TLS_KEY=/tls/privkey.pem …
curl https://logs.example.com:8080/healthz
```

- **Both or neither.** `tls_cert` and `tls_key` are set together; `tls_client_ca` needs them. The files are
  read at startup and a bad path, an unreadable key or a certificate that does not match it stops LogPit with a
  message. The port then speaks **only** TLS (TLS 1.2 and 1.3): a plain-HTTP client is refused, so ingest
  clients, Grafana, `logpit ship` and the rest must use `https://`.
- **Renewing.** `SIGHUP` reads the certificate and key files again (`systemctl reload logpit`, or
  `podman kill --signal HUP logpit`): connections made afterwards use the new certificate, open ones keep the
  old one, and a reload that cannot read them changes nothing. So a Let's Encrypt renewal hook only has to
  send `HUP` to the process. Turning HTTPS on or off, or changing the client CA, needs a restart (a reload
  says so).
- **Client certificates.** With `tls_client_ca`, a client that cannot present a certificate issued by one of
  those CAs is refused at the handshake, before any token is looked at; tokens still apply on top.
- **Handshakes** are completed concurrently and give up after 10 s, at most 256 at once, so a stalled or
  hostile client cannot keep the others out. Failed handshakes (scanners, plain HTTP, untrusted clients) are
  counted in `logpit_tls_handshake_failures_total`, together with those of the syslog TLS listener.
- **Health check.** `logpit --healthcheck` (the container's `HEALTHCHECK`) reads the same configuration: over
  TLS it talks TLS to its own server without verifying the certificate, since it is issued for your public
  name, not for `localhost`; with `tls_client_ca` it can only check that connections are accepted.
- **Audit and logs** record the client's address as for plain HTTP. There is no HSTS header and no redirect
  from a plain port (the port is TLS-only): add those at a proxy if you need them. Certificate names are not
  checked by LogPit itself, only by its clients; Let's Encrypt needs a reachable name and ACME on port 80
  or DNS, which LogPit does not do.

## Sending logs

Syslog (rsyslog, on any Linux host or router):

```
*.* @@logpit-host:514      # TCP; use a single @ for UDP
```

### Loki, GELF and OpenTelemetry

Existing log shippers can send to LogPit without a script.

**Loki push API** (`POST /loki/api/v1/push`, JSON or snappy-compressed protobuf, so Promtail,
Grafana Alloy, Vector, Fluent Bit and Docker's Loki driver work). It needs the `write` token as a
bearer token, or as the **password** of HTTP basic auth (the user name is ignored), which is how
Loki clients usually authenticate:

```yaml
# Promtail
clients:
  - url: http://logpit-host:8080/loki/api/v1/push
    basic_auth: { username: promtail, password: <write token> }
```

```
// Grafana Alloy
loki.write "logpit" {
  endpoint {
    url        = "http://logpit-host:8080/loki/api/v1/push"
    basic_auth { username = "alloy"  password = sys.env("LOGPIT_WRITE_TOKEN") }
  }
}
```

Labels become LogPit's fields: the first of `host`, `hostname`, `nodename`, `node_name`,
`instance` is the host; the first of `app`, `service_name`, `service`, `job`, `container`, `unit`,
`syslog_identifier` is the app; `level`, `severity`, `detected_level` or `log_level` sets the severity
(`debug`, `info`, `warn`, `error`, `fatal`… or 0-7; info by default); every other label, and
Loki's structured metadata, is kept as a filterable field. JSON or `key=value` inside a line is
extracted too (see [structured fields](#structured-fields)), with labels winning on a clash. A
missing host is `unknown`. Answers `204`. A body may be gzip-compressed (`Content-Encoding: gzip`, as
Fluent Bit sends JSON). Tenants are not supported (`X-Scope-OrgID` is ignored); to query
LogPit from Grafana, see [Grafana and the Loki query API](#grafana-and-the-loki-query-api).

**GELF** (Graylog's JSON format): `POST /gelf` on the HTTP port (needs the write token, answers
`202`), plus optional listeners:

```sh
-e LOGPIT_GELF_UDP_LISTEN=0.0.0.0:12201 -e LOGPIT_GELF_TCP_LISTEN=0.0.0.0:12202
docker run --log-driver gelf --log-opt gelf-address=udp://logpit-host:12201 …
```

`host`, `level` (0-7), `timestamp` (seconds, fractions allowed), `short_message` (required) and
`full_message` (appended on a new line) map to the entry, `_app`/`_facility`… name the app, and
other `_custom` fields become fields (`_id` is reserved). TCP messages end with a NUL byte or a
newline. Messages may be gzip- or zlib-compressed, which is what Docker's GELF driver and most
libraries do by default (over HTTP use `Content-Encoding: gzip` or `deflate`). Over UDP, a message
too large for one datagram may come in chunks (Docker's GELF driver chunks anything over about 1.4 KB
once compressed): they are put back together, in any order, if all of them arrive within five
seconds. An incomplete message is then dropped and counted in `logpit_rejected_total`, as is a chunk
that would make incomplete messages hold more than 8 MiB together. The UDP and TCP listeners are
unauthenticated like syslog; keep them on a
trusted network, or use `POST /gelf` with a token.

**OpenTelemetry (OTLP/HTTP and gRPC)**: `POST /v1/logs` accepts the protobuf (`application/x-protobuf`) and
JSON encodings, with or without gzip, with the write token as a bearer token. In the OpenTelemetry
Collector:

```yaml
exporters:
  otlphttp/logpit:
    endpoint: http://logpit-host:8080        # the exporter adds /v1/logs
    headers: { Authorization: "Bearer <write token>" }
service:
  pipelines:
    logs: { receivers: [otlp], exporters: [otlphttp/logpit] }
```

Resource attributes are mapped as `host.name` (then `k8s.node.name`, `k8s.pod.name`,
`service.instance.id`) to the host and `service.name` (then `k8s.container.name`,
`process.executable.name`) to the app; every other resource attribute, the instrumentation scope
(as `scope`), the record's attributes and the trace and span ids (`trace_id`, `span_id`) are
filterable fields, with dots kept in the names (`f=http.status_code:500`). The severity comes from
`severityNumber` (trace and debug 7, info 6, warn 4, error 3, fatal 2) or, without it, from the
severity text. The body is the message (a structured body is shown as JSON), and JSON or
`key=value` in a text body is extracted too. The time is `timeUnixNano`, else
`observedTimeUnixNano`, else the arrival time. Answers `200` with an empty export response.

**OTLP over gRPC** is accepted on the same port, for the SDKs and Collector exporters that only speak
gRPC (the default of most of them). It is HTTP/2, so there is no extra listener: point the exporter at the
HTTP port.

```yaml
exporters:
  otlp/logpit:
    endpoint: logpit-host:8080
    tls: { insecure: true }                  # not needed with HTTPS (see below)
    headers: { authorization: "Bearer <write token>" }
    compression: gzip                        # optional
service:
  pipelines:
    logs: { receivers: [otlp], exporters: [otlp/logpit] }
```

```sh
OTEL_EXPORTER_OTLP_LOGS_ENDPOINT=http://logpit-host:8080 OTEL_EXPORTER_OTLP_LOGS_PROTOCOL=grpc \
OTEL_EXPORTER_OTLP_LOGS_HEADERS="authorization=Bearer <write token>"
```

- **What is served.** `opentelemetry.proto.collector.logs.v1.LogsService/Export` (unary), with the same
  mapping and write-token rules as OTLP/HTTP; the token goes in the `authorization` metadata. The
  `application/grpc` and `application/grpc+proto` content types are accepted, with `gzip` message
  compression (other encodings answer `UNIMPLEMENTED`). Metrics and traces are not served.
- **Statuses.** A missing or wrong token is refused before the call with HTTP `401` or `403`, which gRPC
  clients report as `UNAUTHENTICATED` or `PERMISSION_DENIED`. A message that cannot be read answers
  `INVALID_ARGUMENT` with a reason, a message over 32 MiB `RESOURCE_EXHAUSTED`. On success the response is
  an empty `ExportLogsServiceResponse` and `grpc-status: 0` in the trailers.
- **TLS.** With [HTTPS](#https) the same port negotiates HTTP/2 through ALPN, so gRPC over TLS works
  with an ordinary certificate (and `tls_client_ca` for mutual TLS). Without TLS the port speaks HTTP/2
  with prior knowledge (`h2c`), which is what an `insecure` gRPC channel does, next to HTTP/1.1.
- **Limits.** Only unary `Export` calls: no streaming, no gRPC reflection or health service, and one
  message per call (clients batch). Entries pass through the usual pipeline, so rate limits, rules and
  alerts apply. Verified against a `grpcio` client; not against every SDK.

### Syslog over TLS

Plain syslog is readable and forgeable on the network. For logs that leave a trusted LAN, enable
the TLS listener (RFC 5425, conventionally port 6514). It needs a certificate, which can be
self-signed when you control the senders:

```sh
openssl req -x509 -newkey rsa:3072 -nodes -days 825 -keyout logpit.key -out logpit.pem \
  -subj "/CN=logpit-host" -addext "subjectAltName=DNS:logpit-host"
podman run … -p 6514:6514/tcp \
  -e LOGPIT_SYSLOG_TLS_LISTEN=0.0.0.0:6514 \
  -e LOGPIT_SYSLOG_TLS_CERT=/certs/logpit.pem -e LOGPIT_SYSLOG_TLS_KEY=/certs/logpit.key \
  -v ./certs:/certs:ro …
```

The key must be readable by uid 65532 inside the container, and the certificate's name must
match what senders connect to. Senders then trust `logpit.pem` (or its CA), for example with
rsyslog (the `rsyslog-gnutls` package):

```
global(DefaultNetstreamDriver="gtls" DefaultNetstreamDriverCAFile="/etc/rsyslog.d/logpit.pem")
*.* action(type="omfwd" target="logpit-host" port="6514" protocol="tcp"
           StreamDriver="gtls" StreamDriverMode="1" StreamDriverAuthMode="x509/name"
           StreamDriverPermittedPeers="logpit-host" TCP_Framing="octet-counted")
```

To also **authenticate the senders**, set `LOGPIT_SYSLOG_TLS_CLIENT_CA` (or `syslog.tls_client_ca`)
to a PEM file of the CAs that issue your client certificates: a client without a valid
certificate is refused during the handshake (add `DefaultNetstreamDriverCertFile` and
`DefaultNetstreamDriverKeyFile` on the sender side). Without it, any client that can reach the
port may send.

TLS 1.2 and 1.3 are accepted. Both framings work on one connection and are detected per message:
octet counting (`<length> <message>`, which RFC 5425 requires) and newline-delimited lines. Plain
TCP syslog understands both too. Failed handshakes are counted in
`logpit_tls_handshake_failures_total`. Certificates are read at startup, so replacing them
means restarting LogPit; a bad path or key stops it immediately with an explanation.

### RFC 3164 timestamps

Old-style (BSD) syslog messages carry `Oct  3 14:00:00`: no year and no time zone. By default LogPit
ignores it and stamps the entry with the time it **arrived**, which is always plausible (and the right
answer when the sender and LogPit are in the same room). When the delay matters (a device that buffers
and replays, or logs that arrive in bursts) or the entries come from several time zones, tell LogPit
how to read the sender's clock:

```toml
[syslog]
timezone = "Europe/Paris"   # or: reception (default), utc, local, +02:00, a POSIX rule; env LOGPIT_SYSLOG_TIMEZONE
```

- **`utc`** and **a fixed offset** (`+02:00`, `-0530`, `+2`) read the stamp as wall-clock time in that
  zone. **`local`** uses this machine's own zone, DST included, from `TZ` or the system (a minimal
  container has no zone data and then means UTC).
- **A zone name** (`Europe/Paris`, `America/New_York`) follows that zone's DST rule. LogPit carries no
  zone database: it reads `/usr/share/zoneinfo/<name>` when the setting is loaded, so the official
  image (built `FROM scratch`) needs `-v /usr/share/zoneinfo:/usr/share/zoneinfo:ro`. Without the
  mount, give the rule itself in POSIX form, as found at the end of the zone file
  (`tail -n1 /usr/share/zoneinfo/Europe/Paris`): `CET-1CEST,M3.5.0,M10.5.0/3`. Only the zone's current
  rule is used, which is right for any recent stamp. A POSIX rule must include its DST dates (`GMT+1`
  is refused: POSIX counts hours west, so it means UTC−1; write `-01:00`). During the hour repeated
  when DST ends, the earlier time is taken.
- **The year** is the current one, or the previous one when that would make the message more than a
  day later than now (a message stamped `Dec 31` read in early January). A stamp that cannot exist
  (`Feb 30`, or `Feb 29` in a year that is not a leap year, a DST gap) falls back to the arrival time.
- It only concerns RFC 3164 messages. RFC 5424 messages carry their own zone-aware time and are read
  as before, and a message with no stamp keeps the arrival time. The setting applies to every syslog
  listener (UDP, TCP, TLS) and to the next messages after a reload.
- A sender with a wrong clock now writes wrong times into your history, and an entry older than the
  retention period is purged at the next pass: that is why `reception` is the default.

Other sources:

**`logpit ship`** is a small shipper built into the same binary, for the systemd journal (Proxmox,
any Linux host) and plain log files. It keeps a disk spool, so entries are not lost when the server
is down or the shipper restarts:

```sh
# the journal, as a service (see contrib/logpit-ship.service)
logpit ship --url http://logpit-host:8080 --journal --token-file /etc/logpit/ship-token

# log files, surviving rotation; shipped lines carry the machine's name and the file's name
logpit ship --url https://logpit.example.com --file /var/log/nginx/error.log --file /var/log/app.log \
  --app web --token-file /etc/logpit/ship-token --spool /var/lib/logpit-ship
```

- **Sources.** `--journal` follows `journalctl -o json` (extra `journalctl` arguments with
  `--journal-arg`, e.g. `--journal-arg -u --journal-arg sshd`). `--file` follows a file like
  `tail -F`: it survives rotation (the old file is finished first) and truncation, resumes where it
  stopped, and holds a line back until it ends. By default only entries that arrive after the shipper
  starts are sent; `--journal-from-start` and `--from-start` also send what is already there, and a file
  that appears later is read from its start.
- **No loss.** Each batch is written to the spool directory (`--spool`, default `./logpit-spool`)
  before the read position is saved, and stays there until the server accepts it. While the server is
  unreachable, refuses the token (401/403) or fails (5xx), batches wait and are retried with a growing
  delay; `--spool-max-mb` (256 by default) drops the oldest ones if the outage outlasts it. A batch
  the server calls invalid (400, 413, 415, 422) is set aside in `spool/rejected/` instead of blocking the
  rest. Delivery is **at least once**: a crash between writing a batch and saving the position can send
  a few entries twice.
- **Server side.** Journal entries are sent as they are and mapped by LogPit (`_HOSTNAME`,
  `SYSLOG_IDENTIFIER`, `PRIORITY`, the journal timestamp); file lines become entries with the shipper's
  `--host` and `--app`, stamped when read, and JSON or `key=value` in them is extracted as usual.
- **Options.** `--batch-lines` (500) and `--batch-ms` (1000) set when a batch is cut; `--host` and `--app`
  override the names. The token is read from `--token-file`, `LOGPIT_SHIP_TOKEN_FILE` or
  `LOGPIT_SHIP_TOKEN`, never from the command line, where it would show in `ps`. `logpit ship --help` lists
  everything. It needs a `write` token.
- **Multi-line events.** `--multiline-start REGEX` makes a file line that matches the expression start an
  event, and the lines after it (a stack trace, wrapped output) part of the same event, joined with
  newlines: `--multiline-start '^\d{4}-\d{2}-\d{2}'` for logs that begin with a date, `'^\S'` for
  traces indented under their first line. An event is sent when the next one starts, or after
  `--multiline-wait-ms` (1000) without a new line, and is cut at `--multiline-max-lines` (500) or 64 KiB.
  Lines before the first match form an event of their own. The read position saved is that of the last
  line sent, so a restart re-reads an event that was still being assembled. It applies to `--file`, not
  to the journal (its entries are already whole).
- Lines longer than 64 KiB are cut, and a file truncated and refilled beyond its old size between two
  checks (every 250 ms) cannot be told from one that was appended to.

Or, without it, run this from a systemd timer or cron on the node (`--cursor-file` remembers where the
last run stopped; if the POST fails, that batch is not retried because the cursor has already moved):

```sh
journalctl -o json --no-pager --cursor-file=/var/lib/logpit-shipper.cursor \
  | curl -fsS -H "Authorization: Bearer $TOKEN" -X POST --data-binary @- \
      http://logpit-host:8080/ingest
```

Plain JSON:

```sh
curl -H "Authorization: Bearer $TOKEN" -X POST http://localhost:8080/ingest \
  -d '{"host":"nas","app":"backup","severity":4,"message":"job slow"}'
```

UniFi: *Settings → CyberSecure → Traffic Logging → Activity Logging → SIEM Server*,
with LogPit's address and port 514.

## Retention by severity

`LOGPIT_RETENTION_DAYS` applies to every entry unless a severity has its own value, so noisy
levels can be dropped early while errors are kept longer:

```sh
-e LOGPIT_RETENTION_DAYS=14 -e LOGPIT_RETENTION_BY_SEVERITY=debug=2,info=7,err=90
```

Severities are `emerg`, `alert`, `crit`, `err`, `warn`, `notice`, `info`, `debug` (or `0`–`7`),
and a value of `0` keeps that severity forever. In the TOML file this is the
`[storage.retention_by_severity]` table. Purging runs at startup and then hourly.

### Rules per host and app

`[[retention]]` rules keep some entries for a different time than their severity says: firewall chatter
for three days, the audit app for ever, the production web servers for ninety:

```toml
[storage]
retention_days = 14                 # what no rule below matches

[[retention]]
host = "fw*"                        # host name or pattern (* and ?)
days = 3

[[retention]]
app = "audit"                       # app name or pattern
days = 0                            # 0 = keep for ever

[[retention]]
host = "web*"
severity = ["err", "crit"]          # names or numbers; all conditions of a rule must match
days = 90
```

- **First match wins.** Rules are tried in file order and an entry is judged by the first one it
  matches, whichever keeps it longer or shorter: above, a firewall's audit entry follows the first rule
  (3 days). Entries that match no rule use `retention_days` and `retention_by_severity`, as before. A
  rule needs at least one of `host`, `app` and `severity`; `days = 0` also shields what it matches from
  the rules below it.
- **Same pass.** Rules run in the hourly purge with the severity retention, in chunks that never hold
  the database for long, and the [cold archive](#cold-archive) (if any) receives what they remove. The
  [size cap](#disk-size-cap) still evicts the oldest entries whatever the rules say, so `days = 0` is
  "never by age", not "never".
- **Changing them** needs a restart (a reload says so); the next purge applies the new rules to
  everything stored, including entries older than before.

## Disk size cap

`LOGPIT_MAX_DB_SIZE_MB=2048` (or `storage.max_db_size_mb`; minimum 16) keeps the database from
growing without bound when logs arrive faster than the retention period expects. Every minute
LogPit measures the pages of `logpit.db` that hold data; above the cap it deletes the **oldest
entries first**, whatever their severity, until usage is back to 90% of the cap. Age-based
retention still applies on top of it.

It is a soft cap: SQLite reuses freed pages but never shrinks the file, so `logpit.db` stays at
its high-water mark (roughly the cap plus what arrives within a minute), and the `-wal` file is
extra. To give space back to the filesystem, stop LogPit and run `sqlite3 logpit.db VACUUM`.
Because part of the search index is reclaimed lazily, a purge can remove a bit more than the
strict minimum. `/metrics` exposes `logpit_db_used_bytes` and `logpit_size_evicted_total`; evictions
are also logged as warnings, which usually means the cap is too low for your log volume.

## Cold archive

With `storage.archive_dir` (or `LOGPIT_ARCHIVE_DIR`) set, retention and the size cap no longer just
delete: entries are first appended to one gzip file per UTC day, so the database stays small while
nothing that expires is lost.

```toml
[storage]
retention_days = 14
archive_dir = "/var/lib/logpit/archive"   # created at startup; LogPit refuses to start if it is not writable
```

```
/var/lib/logpit/archive/2026/09/logpit-2026-09-30.ndjson.gz
```

- **Format.** Each file is a series of gzip members (one per batch written, at most 8 MiB of text each)
  of NDJSON in the [`/ingest` format](#sending-logs): `ts`, `host`, `app`, `severity`, `message` and
  `fields`. Standard tools read it as one stream: `gunzip -c logpit-2026-09-30.ndjson.gz | grep timeout`
  (on macOS use `gunzip -c`, `zcat` wants `.Z`), and `gzip -t` checks it. Entries land in the file of the
  UTC day of their own timestamp, so a day's file grows over several purges.
- **Safety.** Entries are deleted in chunks of 5000 only after their chunk was written and synced. If
  the archive cannot be written (disk full, permissions), nothing more is deleted, the error is logged,
  `logpit_archive_errors_total` goes up and the database keeps growing until you fix it: archiving is
  never skipped silently. A crash between writing and deleting can archive some entries twice, and a
  reload does not change the archive directory (restart for that).
- **What is archived.** Everything that retention (every hour, per severity) or the size cap removes.
  `logpit_archived_total` counts them. [Audit events](#named-tokens-restrictions-and-audit) and saved
  views are not archived. Enabling it on an existing database archives what is already past
  retention at the first purge.
- **Disk.** Log text compresses well, but nothing prunes the archive: delete or move old
  files yourself (they are independent, so `find … -mtime +365 -delete` or a copy to object storage
  is fine). Keep it out of `backup` of the database if it is backed up elsewhere.

### Restoring

`logpit restore` reads archive files (or any NDJSON in `/ingest` format) and sends them to a server:

```sh
logpit restore --url http://scratch:8080 --token-file /etc/logpit/write-token /var/lib/logpit/archive
logpit restore --url http://scratch:8080 --token-file tok --from 2026-09-01 --to 2026-09-30 archive/2026/09
logpit restore --dry-run archive        # count what would be sent
```

Directories are searched recursively, `--from` and `--to` select files by the UTC day in their name
(a file named explicitly is always read), `--batch-lines` sets the request size (default 1000), and
the token comes from `--token-file`, `LOGPIT_RESTORE_TOKEN` or `LOGPIT_RESTORE_TOKEN_FILE`, never the
command line. Entries keep their original timestamps, severities and fields; unreadable lines are
counted and skipped, a refused token or a server that stays down stops the run with a message, and
server errors are retried three times.

Restore into a **scratch instance** (retention off, or a throw-away database) rather than the live
one: the server applies its usual pipeline, so its rate limits, rules and alerts see old entries as new
ones, and its own retention would purge them again within the hour and archive them a second time.
`logpit --backup` is the tool for copying the database itself.

## Host tags

`[[tags]]` give names to sets of hosts, so you can ask for *the production web servers* without
listing them:

```toml
[[tags]]
name = "prod"
hosts = ["web*", "db1", "db2"]     # exact names, or patterns: * (any run of characters) and ? (one)

[[tags]]
name = "dmz"
hosts = ["proxy?", "bastion"]
```

- **Filtering.** `tag=prod` on every search endpoint (`/api/logs`, `/api/stats`, `/api/hosts`,
  `/api/top`, `/api/patterns`, `/api/export`, the live tail, saved views): `GET /api/logs?tag=prod&level=3`.
  Repeat it to take the union (`tag=prod&tag=dmz`); an unknown tag is a `400` that lists the known ones.
  `GET /api/tags` lists the tags (with their patterns, except for tokens limited to some hosts or apps,
  which only get the names), and `GET /api/hosts` gives each host its `tags`. The web UI shows a *tag*
  selector among the filters once tags exist, the tags under each host in the Hosts panel and filters on a click.
- **Resolved at query time.** A tag is its patterns matched against host names when the query runs,
  using the configuration then in force, so editing a tag (and `SIGHUP`) applies to everything already
  stored; nothing is written on entries. A host can have several tags, and patterns are case-sensitive
  and match the whole name.
- **Metrics.** `labels = ["tag"]` on a [metric rule](#metrics-from-logs) labels it with the *first* tag
  (in file order) the host belongs to, empty when none. A change to the tags restarts the counters of
  all `[[metrics]]` rules, since their labels may have changed.
- **Token restrictions.** A token's `hosts` now takes the same patterns, and `tags = ["web"]` limits it
  to the hosts of those tags (together with its own `hosts`, a union); `apps` still narrows further. A
  token's restriction always applies, and a `tag=` filter it asks for can only narrow the result
  inside it. The tags of a token must exist, and it needs the `read` scope. In a token's `hosts`, a
  host whose name literally contains `*` or `?` is read as a pattern.
- Not available: a `tag` label in the [Loki query API](#grafana-and-the-loki-query-api) (use `host`
  patterns there), and tags on audit events or saved view names.

## Searching

```sh
curl -H "Authorization: Bearer $TOKEN" \
  'http://localhost:8080/api/logs?q=disk+error&host=pve&level=3&since=1700000000000&limit=50'
```

| Parameter | Meaning |
|---|---|
| `q` | Search text over the message and its fields, see below |
| `host`, `app` | Exact match |
| `level` | Maximum severity number: 0 emergency … 3 error … 6 info … 7 debug |
| `f` | Condition on a structured field: `key:value` exact match, or a [comparison](#field-comparisons-and-regular-expressions); repeat to combine (e.g. `f=act:blocked&f=proto:TCP`) |
| `re` | Regular expression the message must match, see [below](#field-comparisons-and-regular-expressions) |
| `tag` | Only the hosts that have this [host tag](#host-tags); repeat for several (any of them) |
| `trace` | Only the entries of this [trace](#trace-correlation) (its `trace_id`, any case) |
| `since`, `until` | Unix timestamps in milliseconds |
| `limit` | 1–1000, default 100 |
| `before` | Paging cursor `<ts>:<id>`: only entries older than that one, as given by the `X-Next-Cursor` header |

### Field comparisons and regular expressions

`f` also takes comparisons, to answer things the exact match cannot, and `re` filters on the message
with a regular expression:

| Expression | Keeps entries whose field `key`… |
|---|---|
| `key:value` (or `key=value`) | equals `value` |
| `key!=value` | is present and differs from `value` |
| `key>N`, `key>=N`, `key<N`, `key<=N` | is a number in that relation to `N` (`503`, `2.5`, `-1`, `1e3`) |
| `key~regex` | matches the regular expression (anywhere in the value; anchor with `^` and `$`) |

```sh
curl -s -H "Authorization: Bearer $TOKEN" -G http://localhost:8080/api/logs \
  --data-urlencode 'f=status>=500' --data-urlencode 'f=duration<2.5' \
  --data-urlencode 'f=src~^10\.0\.' --data-urlencode 're=timeout|refused'
```

All conditions must hold (they are ANDed, with the text search and the other filters). An entry that
lacks the field never matches, `!=` included, and a value that is not a number (`2.5s`) matches no
ordering. Regular expressions use Rust's [regex syntax](https://docs.rs/regex/latest/regex/#syntax)
(no look-around or back-references; `(?i)` makes one case-insensitive), run in linear time whatever the
pattern, and are limited to 500 bytes and a bounded compiled size; a bad one is refused with `400`. They
cannot use the full-text index: they scan the entries the other filters leave, so combine them with a
time range, a host or `q` on large databases. The same conditions work in every endpoint that takes the
search filters (`/api/stats`, `/api/hosts`, `/api/top`, `/api/patterns`, `/api/export`), in saved views, the
live tail, and the web UI: the *field* box takes any of the forms above and the *Regex on message* box
next to it takes `re`.

### Search text

`q` is a small language, compiled to full-text queries made only of quoted strings, so no
input can be interpreted as full-text syntax:

| You type | It means |
|---|---|
| `disk error` | both words (the default) |
| `error OR timeout` | either; `AND` binds tighter, so `disk error OR timeout` is `(disk AND error) OR timeout` |
| `"disk error"` | the words next to each other, in that order |
| `fail*` or `"disk er"*` | words starting with that |
| `-debug` or `NOT debug` | exclude entries that contain it (applies to the whole query, even alone) |

`OR`, `AND` and `NOT` must be upper case (lower case is an ordinary word), and matching ignores
case. The same text works in `/api/stats`, `/api/hosts`, `/api/export`, the web UI and the
live tail (which has no index, so it matches words as substrings, a little more loosely).

### Context around an entry

`GET /api/logs/{id}/context` returns an entry with the entries just before and after it, which is
how you read what led to a line found by a search. The id is the `id` of an entry returned by
`/api/logs`.

```sh
curl -s -H "Authorization: Bearer $TOKEN" 'http://localhost:8080/api/logs/4312/context?lines=10'
# {"entry": {…}, "before": [oldest … newest], "after": [oldest … newest]}
```

| Parameter | Meaning |
|---|---|
| `lines` | Entries on each side, default 5, at most 100 |
| `scope` | `host` (default): only the entry's own host; `all`: every host, interleaved by time |

Neighbours follow the search order (timestamp, then id). Near the start or the end of the data
there are simply fewer of them, and an unknown id gives `404`. In the web UI, click the
time of a line to open its context under it; the panel can show more lines, switch between
this host and all hosts, and be closed again. Lines that arrived through the live stream have no
id yet, so they can be expanded after the next search.

### Paging

A search returns at most `limit` entries, newest first. When a page is full the response has an
`X-Next-Cursor: <ts>:<id>` header; pass it as `before` to get the next page, until the header
is absent. Entries sharing a timestamp are ordered by id, so no entry is skipped or repeated even
while new ones arrive. The web UI's *Load more* button does this, 500 entries at a time.

```sh
curl -sD - -H "Authorization: Bearer $TOKEN" 'http://localhost:8080/api/logs?q=error&limit=1000'
curl -s -H "Authorization: Bearer $TOKEN" 'http://localhost:8080/api/logs?q=error&limit=1000&before=1700000000123:42'
```

For everything at once, use [export](#export-and-backup).

## Display preferences

The *Settings* button in the filter row of the web UI holds the access token and the display preferences,
both kept in this browser (`localStorage`); the preferences are applied before the first search:

| Preference | Choices |
|---|---|
| Theme | follow the system (default), light, dark |
| Times | local time (default), UTC (`2026-10-03 18:56:01.888 UTC`), ISO 8601 (`2026-10-03T18:56:01.888Z`) |
| Density | comfortable (default), compact |
| Long messages | wrap (default), one line (cut with an ellipsis) |
| Columns | time, level, host, app, and the structured fields after each message |
| Notify me of new alerts | off (default) or on: each new alert shows in the page with a *Show* button that zooms to it, and, while the tab is in the background, as a system notification (the browser asks first; it needs LogPit over [HTTPS](#https) or `localhost`) |

They change how the page looks and never what is asked of the server: links, saved views, exports and
the API are not affected, and times in the API stay Unix milliseconds. *Reset display* restores the defaults.
Changing the time format searches again, since the rows are written with it; the chart tooltips, the
context panels and the alert list follow it too.

## Keyboard and active filters

The page itself is served without its indentation and comments, and gzipped for browsers that accept
it (about 35 KB instead of 130 KB).


Outside a text field, the web UI answers to a few keys (also listed under *Settings*):

| Key | Action |
|---|---|
| `/` | focus the search box |
| `L` | turn the live tail on or off |
| `J` / `K` | move to the next or previous line |
| `Enter` | open the context of the current line (on a line with a trace link, Tab reaches it) |
| `Esc` | close *Settings*, leave a field, or close the panel under the current line |
| `←` / `→`, `Home` / `End` | move along the time scale or the alert timeline under the chart, or along the chart legend (each one tab stop) |
| `Ctrl`+`K` / `⌘`+`K` | command palette: saved views, hosts, ranges, levels, live, theme, density, export, settings |

The *Host* and *App* fields suggest the names found in the current time window (picking one searches).
The filters of the last search (search words, host, app, tag, field, regex, level and a zoomed time
window) show as chips under the header; a chip's cross removes that filter and searches again, and
*Clear all* removes them all.

The time scale under the chart is clickable: a time (minutes to days, as fine as fits) scrolls the list to
its lines without searching again, or zooms to it when those lines are not loaded yet.

In Live mode, new lines slide in lit and the light fades, and counts roll to their new value. Scrolling
down to read keeps what you read in place while new lines arrive above; a *new lines above* pill counts
them and brings you back to the top. The context of a line is fetched while the pointer rests on it, so
it opens at once.

The **?** button next to the search box lists the search, field-filter and regex syntax with examples;
clicking an example searches with it. Hovering a line (or moving to it with `J`/`K`) shows *copy* (the
message), *JSON* (the whole entry) and *link* (a link to the minute around the line on its host, never
including the token); copying also works when LogPit is served over plain HTTP. A search that finds
nothing offers a wider time range and to remove the filters.

The words of the search (not the excluded ones) and the regex matches are highlighted in the messages.
In the chart legend, a severity sets the minimum level. A structured field can be left out instead of
kept: Alt-click it under a message, or use the − button beside a value in *Top values* (this writes
`field!=value` in the field filter; host and app cannot be excluded this way).

The time range selector has a *Custom…* entry with two local date-times (chosen from the keyboard, it opens the form and leaves the focus on the selector; Tab reaches the fields), and a zoomed window gets a
*Zoom out* button that doubles it around its middle.

Alerts that arrived since the panel was last open are counted on its title (*3 new*), and the browser
tab shows that count, plus the error lines that arrived live while the tab was in the background, as
`(3) LogPit`. The newest line of the previous visit is remembered in the browser, and the next visit
marks it in the list: the lines above the mark came since. Relative ages in the side panels ("3m ago")
refresh every 30 seconds.

## Board, host pages, administration and comparison

Besides the search page, the web UI has four views (links in the filter row, and in the command palette).
They use the same token as the main page, kept in the same browser, and the same theme.

- **`/board`**: a board of the hosts, made for a screen left on the wall. Each host is a row with its
  state over the last 15 minutes (`?minutes=60` for another window): *Silent*, *Failing* (errors, with the
  latest error), *Degraded* (warnings, with the latest warning) or *Healthy*,
  its recent form (five slices of the window, red or amber only when one stands out), its last log and its
  counts, worst first; a dot pulses while the host is talking. It refreshes every 30 seconds and is dark unless the light
  theme is chosen under Settings.
- **`/host/<name>`**: everything about one host: its volume over 7 days by severity, latest errors, apps
  and message patterns over 24 hours, its alerts, tags and state, and a link to search its logs. The
  Hosts panel links each host to its page.
- **`/admin`** (admin scope): the storage (the database's size, entries, oldest entry and last day's
  arrivals, where its size is heading at that pace with the retention and the size cap, and each host's
  share of the entries; `GET /api/storage` gives the figures), the maintenance windows (start one for some hosts and minutes, end an API
  window), the tokens with their scopes, restrictions and quotas and how many requests each had refused
  for quota (from `/metrics`), and the audit trail, filterable by token and to refused requests.
- **`/compare`**: two time windows side by side (by default the hour before and the last hour, with
  optional host, app and search filters): totals, each host's entries and errors with the change, and the
  message patterns that appeared, went away or at least doubled. The address keeps the windows, so a
  comparison can be shared.

On the main page, the chart is a momentum curve: per bucket, what is not an error rises above the line
and errors push below it (grouped by host or app, everything rises); it morphs to its new values instead
of being redrawn, a tooltip tells the bucket under the pointer, and while the window slides with the clock
its right end is marked *now*. Dragging across it dims the lines outside the range and counts what it
holds, then zooms to it on release. The alerts of the chart's window appear as marks on a timeline under
it (red for problems, green for recoveries; a mark zooms to the 20 minutes around it), and maintenance
windows that cover the searched host (or all of them) are hatched over the curve when the token has the
admin scope. *Copy as CLI* copies the
current search as the equivalent `logpit search` command. A trace panel places each line on a bar
between the first and the last entry of the trace. A server that has received nothing yet shows how to
send logs to it, with its own address in the commands.

## Web UI links

The address bar always reflects the last search, so a link reproduces the same view and the
browser's Back and Forward buttons step through your searches (including zooms):

```
http://logpit-host:8080/?q=disk&host=pve&level=3&range=86400000&group=host
http://logpit-host:8080/?since=1700000000000&until=1700000299999   # a zoomed window
```

Parameters: `q`, `host`, `app`, `level`, `f` (`key:value`), `range` (a window in milliseconds
ending now, or `all`; the default is one hour), `since` and `until` (a fixed window in Unix
milliseconds, which take precedence over `range`) and `group` (`host` or `app` to stack the
chart by; the default is severity). Unknown or invalid values fall back to the defaults. The
token is never put in the URL: whoever opens a link still enters their own.

## Statistics

```sh
curl -H "Authorization: Bearer $TOKEN" \
  'http://localhost:8080/api/stats?since=1700000000000&bucket=5m&group_by=host&level=4'
```

Counts entries per time bucket, which is what the chart at the top of the web UI shows. The
chart can be stacked by severity, host or app (*Stack by*); the legend gives the totals, and
clicking a host or app in it filters the log table on it. With *Live* on, the chart is redrawn every 5 s (while the tab is visible). Clicking a bar zooms to that bucket's time window, and dragging across the chart zooms to the buckets under the selection (Escape cancels the drag); the window is shown as an extra entry in the time-range selector (pick another range to leave it, and *Live* is switched off).
It takes the filters of `/api/logs` (`q`, `host`, `app`, `level`, `f`, `since`, `until`) plus:

| Parameter | Meaning |
|---|---|
| `bucket` | Bucket size: seconds, or a duration such as `30s`, `5m`, `1h30m`, `1d` (at least 1 s). Default: a size giving about 120 buckets over the range |
| `group_by` | Split each bucket by `host`, `app`, `severity` or `field:<key>` (e.g. `field:act`) |

`until` defaults to now and `since` to the oldest entry. Buckets are aligned to the Unix epoch,
empty ones are returned with `total: 0`, and a range may not need more than 2000 buckets.
With `group_by`, the 10 largest groups are listed in `keys` (largest first) and the rest are
summed into `other`:

```json
{"bucket_ms":300000,"since":…,"until":…,"keys":["pve","nas"],
 "buckets":[{"ts":1700000100000,"total":12,"groups":{"pve":8,"nas":4}}, …]}
```

It needs the `read` scope. Free text (`q`) uses the same full-text index as search.

### Hosts

`GET /api/hosts` summarizes the matching entries per host, busiest first: `count`, `errors`
(severity 0-3), `warnings` (severity 4) and `last_ts` (Unix ms of the host's latest entry), plus
`silent` when [silence alerts](#silence-alerts) are enabled and tracking that host. It takes the
filters of `/api/logs`, `limit` (default 100) for the number of hosts, and `sort`
(`host`, `count`, `errors`, `warnings` or `last_ts`; default `count`) with `order` (`asc` or
`desc`; default `asc` for `host`, `desc` otherwise). The limit applies after sorting, so
`sort=last_ts&order=asc` lists the quietest hosts even when there are more hosts than `limit`.
With `form=N` (1 to 24) and a `since`, each host also gets its recent `form`: the window, up to
`until` or now, cut in N equal slices, oldest first, each with its `count`, `errors` and `warnings`.
It needs the `read` scope. The web UI shows it in the collapsible *Hosts* panel (in the left rail on wide screens): it follows the
current filters and time range, lists every host even when one is selected, refreshes with the
chart in Live mode, and clicking a host filters the log table on it. It is sorted by errors by default, with
the hosts that went silent listed first under that order. Click a column header to sort by it (again to reverse; Enter or Space works with the
keyboard); the choice is remembered, and the server does the sorting, so the 200 hosts shown
are the first 200 in that order. Each row has a dot that pulses while the host is talking (red when its
latest slice has more errors than usual, hollow when it went silent, lit again by each line that arrives
live), its recent form as five marks over the window (red or amber only for a slice that stands out from
the host's own window), its counts and a bar for its share of the entries; the arrow on hover opens its
page.

## Export and backup

**Export** streams the entries matching the search filters, oldest first, as a download:

```sh
curl -H "Authorization: Bearer $TOKEN" -o logpit.ndjson \
  'http://localhost:8080/api/export?host=pve&level=4&since=1700000000000'
curl -H "Authorization: Bearer $TOKEN" -o logpit.csv 'http://localhost:8080/api/export?format=csv'
```

It takes the filters of `/api/logs`, `format` (`ndjson`, the default, or `csv`) and an optional
`limit` (any size; without it the whole match is exported). Rows are read and sent
incrementally, so memory does not grow with the size of the export. It needs the `read` scope,
and at most 2 exports run at once (others get `503`). NDJSON lines use the same keys as
`POST /ingest` (`ts`, `host`, `app`, `severity`, `message`, `fields`), so an export can be loaded
into another instance with `curl --data-binary @logpit.ndjson …/ingest`. CSV has the columns
`id,ts,time,host,app,severity,message,fields` (`time` is ISO 8601 UTC, `fields` is JSON); log
text is untrusted, so be careful opening a CSV in a spreadsheet, which may interpret cells
starting with `=`, `+`, `-` or `@` as formulas. The *Export* buttons in the web UI download the
current view, up to 100,000 entries (the browser has to hold the file in memory); use the API
for more.

**Backup** writes a consistent copy of the database to a new file, safely while LogPit is
running (it uses SQLite's `VACUUM INTO` and checks the result):

```sh
podman exec logpit /logpit --backup /data/backup-$(date +%F).db
podman cp logpit:/data/backup-$(date +%F).db .
# without a container
logpit --config logpit.toml --backup /var/backups/logpit-$(date +%F).db
```

It reads the database of the usual configuration (`LOGPIT_STORAGE_PATH` or the config file), never
overwrites an existing file, does not migrate the schema, and leaves a file you can restore by
putting it back at the storage path while LogPit is stopped.

### Scheduled backups

`[backup]` makes LogPit take the backup itself, on a schedule, and keep the newest few:

```toml
[backup]
dir = "/var/lib/logpit/backups"   # setting it turns scheduled backups on; env LOGPIT_BACKUP_DIR
every_hours = 24                  # LOGPIT_BACKUP_EVERY_HOURS
keep = 7                          # LOGPIT_BACKUP_KEEP
```

- **What it writes.** The same consistent copy as `logpit --backup` (SQLite `VACUUM INTO`, safe while
  LogPit runs, checked with an integrity check), named `logpit-YYYYMMDDTHHMMSSZ.db` by UTC time. It
  contains the entries, saved views and the audit trail; the [cold archive](#cold-archive) is separate
  files and is not copied. Restore by stopping LogPit and putting a copy at the storage path.
- **Schedule.** The first backup comes a minute after startup when none exists or the newest is older
  than the interval; otherwise LogPit waits out the rest of the interval, so restarting does not cause
  a backup each time. A failed backup is logged (`logpit_backup_errors_total`), leaves no partial
  file, and is retried within the hour at the latest.
- **Rotation.** After each successful backup only the newest `keep` files *with that name pattern*
  stay; anything else in the directory (other files, a `logpit.db`) is never touched.
- **Metrics.** `logpit_backups_total`, `logpit_backup_errors_total`,
  `logpit_backup_last_success_timestamp_seconds` (alert on it getting old) and
  `logpit_backup_last_size_bytes`, shown when `dir` is set.
- **Limits.** Each backup is a full copy: with a large database and a short interval it costs the
  disk space, `VACUUM INTO` time and I/O of one copy, so mind `keep`. Copies are not compressed (use
  `zstd` or the filesystem) and stay on the same machine: copy them off-site yourself (`rsync`,
  `restic`, object storage). The directory is created and checked at startup, and a path that cannot
  be written stops LogPit with a message. Changing `[backup]` needs a restart; a reload says so.

### Top values

`GET /api/top?field=<field>` lists the most frequent values of a field among the entries matching
the filters, which answers questions like *which source addresses were blocked most?* or *which
status codes is this app returning?*:

```sh
curl -s -H "Authorization: Bearer $TOKEN" \
  'http://localhost:8080/api/top?field=src&f=act:block&host=fw1&since=1700000000000&limit=10'
# {"field":"src","matching":115,"with_field":115,"distinct":23,
#  "values":[{"value":"203.0.113.5","count":49}, …],"other":43}
```

`field` is `host`, `app`, `severity`, or the name of a [structured field](#structured-fields) (CEF,
or extracted from JSON and `key=value` messages); use `field:<name>` for a field that shares a name
with a built-in one. It takes the filters of `/api/logs`, and `limit` (default 10, at most 100).
`with_field` is how many matching entries have a value, `distinct` how many different values there
are, and `other` the entries whose value is not among those listed. `GET /api/fields` lists the
field names present in the matching entries with how many entries carry each (`limit` up to 200), to
know what can be asked. Both need the `read` scope.

In the web UI the *Top values* panel, under *Hosts*, does the same for the current results: pick a
field, and each value gets a bar and its share; clicking a value filters on it (a host, an app, a
severity of error, warning or info, or `field:value`). The filter on the field being listed is
ignored for that list, so its alternatives stay visible after you click one.

### Message patterns

`GET /api/patterns` groups the matching entries by message template: the first line of a message
with every token that contains a digit (and the value of a `key=value` pair that has one) replaced
by `<*>`, so `user 4312 logged in from 10.0.0.7` and `user 77 logged in from 10.0.0.9` count together
as `user <*> logged in from <*>`. It answers *what is my noisiest message?* and *what just started
happening?* without knowing the message formats in advance.

```sh
curl -s -H "Authorization: Bearer $TOKEN" \
  'http://localhost:8080/api/patterns?host=web1&level=4&since=1700000000000&limit=10'
# {"scanned":1200,"truncated":false,"since":…,"until":…,"distinct":4,"other":0,"patterns":[
#   {"pattern":"disk <*> at <*> full","search":"disk full","count":39,"previous":0,"recent":39,
#    "hosts":3,"severity":"err","first_ts":…,"last_ts":…,
#    "example":{"id":1199,"ts":…,"host":"h1","message":"disk /dev/sda1 at 93% full"}}, …]}
```

It takes the filters of `/api/logs` and `limit` (default 25, at most 200); most frequent first. Per
pattern: `count`, `hosts` (distinct, counted up to 100), the most severe `severity` seen, the first and
last timestamps, the newest entry as `example`, and `search`, the plain words of the pattern, which
finds its entries with `q=` (an approximation: other messages may share those words).

- **Trend.** The window is `since` (or the oldest entry) to `until` (or now); `previous` counts the
  entries of its first half and `recent` those of its second half. A pattern with `previous` 0 and a
  `recent` above 0 appeared in the second half. If more entries match than were analysed, the window
  starts at the oldest entry analysed, and `truncated` is true.
- **Cost.** Only the newest 20 000 matching entries are read, each cut to its first 400 characters,
  and at most 5000 templates are tracked (entries of any further template count in `other`), so the
  cost does not grow with the database. Narrow the filters or the range to analyse older entries.
- **Limits of the template.** Only numbers are masked: words that vary (user names, host names without
  digits, UUIDs made of letters only) keep messages in separate patterns, and a very long message is
  cut after 48 words. Messages whose first line is empty share the pattern `""`.

The web UI has a collapsible *Message patterns* panel under *Top values*: counts, a trend
(`new`, `+60%`, `−40%`, or a grey percentage when it barely moved) and the template; hovering shows an example
and clicking searches for the pattern's words. It follows the current filters and needs the `read` scope.

### Saved views

A view is a named search (filters, time range or zoomed window, chart grouping) kept on the server,
so a team shares its useful searches. In the web UI, the *Views* menu in the header opens one,
*Save view* asks for a name in place and stores the current search under it (an existing name is replaced;
Enter saves, Escape cancels), and *Delete* asks for a confirmation in place before removing the selected
one. The menu shows which view matches the current search.

```sh
curl -s -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  http://localhost:8080/api/views -d '{"name":"Disk errors on pve","query":"host=pve&q=disk+error&level=3"}'
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/views        # list, by name
curl -s -X DELETE -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/views/3
```

`query` is the query string of the [web UI link](#web-ui-links), with `q`, `host`, `app`, `level`, `f`,
`range`, `since`, `until` and `group` only (anything else is refused, 400), at most 2000 bytes. A name
has at most 80 characters, and at most 100 views are kept (`409` beyond that). Listing, saving and
deleting need the `read` scope, so the people who view the logs also manage the views; a token that
can only ingest cannot. Views are stored in the database file (a table created on first use that does
not change the schema version, so an older LogPit can still open the file) and are part of
`logpit --backup`.

## Command line: search and tail

The `logpit` binary can also query a running server, which saves writing `curl` and a `jq` filter for
the usual questions:

```sh
export LOGPIT_URL=http://logpit-host:8080 LOGPIT_TOKEN_FILE=~/.config/logpit/read-token

logpit search -q "disk error" --level warn --since 2h             # oldest first, like a log file
logpit search --tag prod -f 'status>=500' --regex 'timeout|refused' -n 500 --fields
logpit search --host web1 --since 2026-10-03T08:00:00Z --until 2026-10-03T09:00:00Z --format ndjson | jq .message
logpit tail --tag prod --level err                                 # last 10, then follow; Ctrl-C to stop
```

| Option | Meaning |
|---|---|
| `--url`, `--token-file` | The server (or `LOGPIT_URL`) and a read token (or `LOGPIT_TOKEN`, `LOGPIT_TOKEN_FILE`); never on the command line |
| `-q`, `--host`, `--app`, `--level`, `-f`, `--regex`, `--tag`, `--trace` | The [search filters](#searching): `-f` and `--tag` can be repeated; `--level` takes `err`, `warn`… or 0-7 and means that severity and worse |
| `--since`, `--until` | `search` only: a duration before now (`15m`, `2h`, `1d`, `1h30m`), an RFC 3339 time, or Unix seconds or milliseconds |
| `-n`, `--limit` | Entries to print: `search` 100 by default (up to 1 000 000, fetched 1000 at a time), `tail` 10 |
| `--format` | `text` (default), `json` (one array, `search` only) or `ndjson` |
| `--fields` | Text output: add the structured fields after the message |
| `--newest-first` | `search` only: newest entries first instead of oldest first |

- **Text output** is one line per entry: UTC time, host, app (`-` when empty), severity name, message;
  continuation lines of a multi-line message are indented. JSON and NDJSON are the API's own entries
  (`id`, `ts` in Unix ms, `host`, `app`, `severity`, `message`, `fields`).
- **`tail`** subscribes to the live stream first and then prints the last entries, so nothing is
  missed between the two (an entry can appear twice at that moment). It reconnects with a growing delay
  when the connection drops, tells you on stderr if the server skipped entries because they came too
  fast, and gives up at once on a refused token. It follows the [live tail](#live-tail) semantics,
  where free text matches words loosely and regular expressions and field comparisons work as in
  search.
- **Errors** go to stderr with a non-zero exit status (`401`: give a read token); a closed pipe such
  as `logpit search | head` ends quietly. The same read restrictions and tags as in the API apply.
- It talks plain HTTP/1.1 or HTTPS with the built-in certificate authorities; there is no option to
  trust a private CA, so for that use a reverse proxy with a public certificate or the `curl` examples.

## Live tail

```sh
curl -N -H "Authorization: Bearer $TOKEN" 'http://localhost:8080/api/tail?host=pve&level=4'
```

Streams new entries as server-sent events (one JSON object per `data:` line). It accepts
the `q`, `host`, `app`, `level` and `f` filters of `/api/logs`; `since`, `until` and `limit`
are ignored. Unlike search, `q` here is matched in memory (same syntax, but words match as case-insensitive
substrings of the message and field values). Only entries ingested after the connection opens are sent. A slow client
gets a `lagged` event with the number of skipped entries; at most 32 clients may tail at once.

## Grafana and the Loki query API

LogPit answers the read side of Loki's HTTP API, so Grafana's **Loki data source** can explore and chart
it. In Grafana: *Connections → Data sources → Loki*, URL `http://logpit-host:8080`, and for the token
either *Basic auth* (any user name, a **read token as the password**) or a custom header
`Authorization: Bearer <token>`. *Save & test* works (it sends `vector(1)+vector(1)`).

| Endpoint | Answers |
|---|---|
| `GET\|POST /loki/api/v1/query_range` | log streams for a log query, a matrix for a metric query |
| `GET\|POST /loki/api/v1/query` | a vector for a metric query, the last hour's newest lines for a log query |
| `GET /loki/api/v1/labels`, `…/label/<name>/values` | label names and values (take `start`, `end` and an optional `query` selector) |
| `GET\|POST /loki/api/v1/series` | label sets of the streams matching `match[]` selectors |

They need the `read` scope, follow [read restrictions](#named-tokens-restrictions-and-audit), and take
`start` and `end` as Unix seconds, ms, µs or ns or RFC 3339, `limit` (default 100, at most 5000),
`direction` and `step` (seconds or `1m`) as Loki does; POST bodies may be form-encoded.

**Labels.** Every stream is `host`, `app` (when set) and `level` (`critical`, `error`, `warning`, `info`,
`debug`; severities notice and info share `info`). The aliases `hostname`; `service_name`, `service`,
`job`; and `severity`, `detected_level`, `log_level` are understood in queries. Any other label name is a
[structured field](#structured-fields), so `{status="500"}` or `sum by (src) (…)` work on CEF, JSON and
`key=value` fields, and `labels` lists the fields found in the window. A label that is absent never
matches `!=` or `!~` on a field (unlike Loki).

**LogQL subset.**

- Selectors with `=`, `!=`, `=~`, `!~` (regexes match the whole value, as in Loki).
- Line filters `|=`, `!=`, `|~`, `!~` (substring, case-sensitive; regular expressions, unanchored).
- `| json` and `| logfmt` (accepted: LogPit extracted those fields at ingestion) and label filters
  `| status >= 500`, `| env="prod"`, `| code =~ "5.."` (numbers compare with `>`, `>=`, `<`, `<=`).
- `count_over_time(<log query> [5m])` and `rate(…)`, alone (one series per stream) or inside `sum` /
  `sum by (a, b)`; durations such as `30s`, `5m`, `1h30m`, `2d`. A step shows the entries of the window
  *ending* at it, and points without entries are left out, as Loki does.
- `vector(1)+vector(1)` and similar, for Grafana's connection test.

Anything else (`line_format`, `unwrap`, `topk`, `avg_over_time`, aggregations other than `sum`,
`without`, binary operations on log queries…) is refused with `400` and a message naming it. Not
provided: the tail WebSocket, `index/stats`, `index/volume`, `detected_fields` and `patterns` (Grafana's
*Logs Drilldown* needs those), and OTLP-style structured metadata in responses.

**Limits.** A metric result has at most 11 000 points per series and 1000 series (group by fewer labels).
Line filters and regular expressions scan the entries the selector leaves, since they cannot use the
full-text index; keep the time range tight on large databases. Timestamps have millisecond precision
(`ts` in a stream value is the entry's milliseconds followed by zeros), and the native
[search API](#searching) remains the way to page through everything. This is tested against requests
shaped like Grafana's, not against a Grafana instance.

## Silence alerts

Detects hosts that stop sending logs (a crashed node, a dead router). Enable it for every
host with `LOGPIT_SILENCE_AFTER_SECS=600`, or per host in the TOML file:

```toml
[silence]
default_after_secs = 600     # every host; 0 = only the hosts listed below
webhook_url = "http://ntfy.lan/logpit"
check_interval_secs = 30

[silence.hosts]
pve = 120                    # tighter threshold
nas = 3600
printer = 0                  # never alert for this host
```

A host alerts once when it exceeds its threshold, and once more when logs resume. Hosts are
tracked from the first log received (or from startup, for hosts already in the database or
listed under `[silence.hosts]`, which get a full threshold of grace after a restart). Hosts
not in the config are forgotten after 7 days of silence, and at most 1024 hosts are tracked.

### Alert webhook

Alerts and recoveries are sent as a `POST` to `webhook_url`, which can be `http://` or
`https://` (certificates are checked against the Mozilla root list built into LogPit, so it works
from the image without any CA bundle). The request is retried up to 3 times, failures are logged
without the URL or headers (they often hold a token), and `webhook_format` picks the body:

| `webhook_format` | Body | For |
|---|---|---|
| `json` (default) | `{"event":"host_silent","host":"pve","silent_for_secs":125,"threshold_secs":120,"message":"…"}`, with `"event":"host_recovered"` on recovery | your own receiver |
| `slack` | `{"text": "…"}` | Slack, Mattermost, Rocket.Chat |
| `discord` | `{"content": "…"}`, mentions disabled | Discord |
| `ntfy` | the text, plus `Title`, `Priority` and `Tags` headers | [ntfy](https://ntfy.sh) |
| `text` | the text | anything that takes a plain body |

```toml
[silence]
default_after_secs = 600
webhook_url = "https://ntfy.example.com/logpit"
webhook_format = "ntfy"
webhook_headers = ["Authorization: Bearer tk_…"]   # extra headers, e.g. a token
```

`LOGPIT_SILENCE_WEBHOOK_URL`, `LOGPIT_SILENCE_WEBHOOK_FORMAT` and `LOGPIT_SILENCE_WEBHOOK_HEADER`
(one header; use the file for several) are the environment equivalents. The headers `Host`,
`Content-Type`, `Content-Length`, `Connection`, `Transfer-Encoding` and `Expect` are set by LogPit
and cannot be overridden. Host names come from whoever sent the logs, so they are clipped, and
escaped where the target interprets them (`<!channel>` in Slack text, mentions in Discord, non-ASCII
in ntfy headers). Redirects are not followed, so give the final URL.

The same state is exposed on `/metrics` as `logpit_host_silent{host="…"} 1` for each silent host,
so Prometheus/Alertmanager can notify instead.

## Volume alerts

Silence alerts catch a host that stopped completely; `[volume]` catches the ones that are merely
**too loud or too quiet**: a service stuck in an error loop, a crashed forwarder that left a trickle, a
deployment that changed how much a host logs.

```toml
[volume]
enabled = true            # or LOGPIT_VOLUME_ALERTS=true; off by default
window_secs = 300         # entries are counted per host in windows of this length
baseline_windows = 12     # a host's usual volume is averaged over about this many windows
high_factor = 5           # a window with 5x the usual or more is a surge (0 = no surge alerts)
low_factor = 0.2          # a window with 0.2x the usual or less is a drop, none at all included (0 = off)
min_baseline = 20         # ignore hosts that usually send fewer than this many entries per window
cooldown_secs = 3600      # at most one notification per host per hour
max_hosts = 1024
```

It notifies through the same [webhook](#alert-webhook) (and the log):

```json
{"event":"volume_surge","host":"web1","count":2400,"baseline":300,"window_secs":300,
 "message":"web1 sent 2400 entries in 5m, far above its usual 300"}
{"event":"volume_drop","host":"db1","count":4,"baseline":280,"window_secs":300,
 "message":"db1 sent 4 entries in 5m, far below its usual 280"}
```

- **Baseline.** A moving average of the host's closed windows (a plain average until it has
  `baseline_windows` of them). Nothing is reported for a host before that, so a new host gets
  `baseline_windows × window_secs` of grace (one hour with the defaults). At startup the baselines are
  seeded from the stored entries of the last `baseline_windows` windows, so a restart does not reset
  them.
- **Anomalies do not move the baseline.** While a host is outside its factors the baseline stays put,
  so a long outage is still a drop at the next window; if it lasts a whole `baseline_windows`, it is
  accepted as the new normal and alerts stop.
- **What is counted.** Every entry received from the host, before rate limits, rules and
  deduplication, so limiting or dropping does not look like a drop.
- **Limits.** The baseline is one number per host, not a daily or weekly profile: a host that is
  busy by day and idle at night will drop-alert at dusk unless `low_factor` is low or `window_secs`
  long enough to see it coming, and `min_baseline` keeps small hosts quiet. Hosts that have sent
  nothing for a long while and have no baseline are forgotten. Counts and baselines are in memory.
- **Reloading.** `SIGHUP` applies the section, and keeps the baselines unless the window length changed
  (they would mean something else then). Turning it on by a reload starts without history.
- **Metrics.** `logpit_volume_alerts_total{kind="surge"|"drop"}` and `logpit_volume_hosts`.

### E-mail notifications

`[email]` sends the same notifications by e-mail, beside the webhook (both go out at the same time, and
either may be used alone):

```toml
[email]
host = "smtp.example.com"          # empty turns it off; env LOGPIT_EMAIL_HOST
port = 587                         # default: 587 for starttls, 465 for tls, 25 for none
security = "starttls"              # starttls (default), tls (from the first byte) or none
from = "logpit@example.com"        # LOGPIT_EMAIL_FROM
to = ["ops@example.com", "oncall@example.org"]   # LOGPIT_EMAIL_TO, comma separated
username = "logpit"                # with password; LOGPIT_EMAIL_USERNAME
password = "…"                     # prefer LOGPIT_EMAIL_PASSWORD or LOGPIT_EMAIL_PASSWORD_FILE
subject_prefix = "[LogPit]"
kinds = ["host_silent", "volume_surge", "volume_drop"]   # empty = every kind
max_per_hour = 30                  # 0 = no limit
```

- **What is sent.** One message per notification (a silent host and its recovery, pattern alerts, new
  patterns and surges, volume alerts), `text/plain` in UTF-8 and base64, with the alert text as subject
  (clipped, non-ASCII encoded as RFC 2047) and as first line of the body, then the event as JSON. Mail is
  marked `Auto-Submitted: auto-generated`. Addresses are checked at startup (plain `name@domain`), and
  everything that comes from log data (host names, samples) is made harmless in headers.
- **SMTP.** `starttls` upgrades a plain connection and refuses a server that does not offer it, rather
  than falling back to clear text; `tls` is implicit TLS. Certificates are checked against the built-in
  authorities (a private CA is not supported). Authentication is `AUTH PLAIN`, or `AUTH LOGIN` if that
  is all the server offers; with `security = "none"` a login is only accepted for a server on this
  machine, so a password never crosses the network unencrypted. One connection per message, three
  attempts 5 s apart, 30 s per command.
- **Floods.** `max_per_hour` (30) caps what is sent; the rest are dropped, logged, and counted in
  `logpit_email_suppressed_total`, but still recorded in the [alert history](#alert-history), where each
  entry shows `email` (`true`, `false` or absent when not sent by e-mail). Use `kinds` to keep the noisy
  kinds out of your mailbox.
- **Reloading.** `SIGHUP` applies the section (the hourly count starts over). Metrics:
  `logpit_email_sent_total`, `logpit_email_failed_total` and `logpit_email_suppressed_total`.

### Alert history

Every notification LogPit raises (a silent host and its recovery, [pattern alerts](#pattern-alerts),
[new patterns and surges](#new-pattern-alerts), [volume alerts](#volume-alerts)) is recorded, whether or
not a webhook is configured or reachable, so a missed message in your chat is not a missed alert:

```sh
curl -s -H "Authorization: Bearer $TOKEN" 'http://localhost:8080/api/alerts?kind=volume_surge&since=1700000000000&limit=20'
# [{"ts":1791058984000,"kind":"volume_surge","host":"web1",
#   "message":"web1 sent 2400 entries in 5m, far above its usual 300",
#   "delivered":true,"details":{"event":"volume_surge","host":"web1","count":2400,…}}, …]
```

- **Fields.** `ts` (Unix ms), `kind` (`host_silent`, `host_recovered`, `log_alert`, `new_pattern`,
  `pattern_surge`, `volume_surge`, `volume_drop`), `host` (absent for an alert that is not about one
  host), `message`, `delivered`, `email` (the same for the e-mail, see above) and `details` (the event as
  the `json` webhook format sends it).
  `delivered` is `true` when the webhook accepted it, `false` when it gave up after its attempts, and
  absent when no webhook was configured. The entry is written once the webhook attempts end, which
  can take around fifteen seconds when it is unreachable, but is stamped with the time of the event.
- **Query.** `limit` (default 50, at most 1000), `since`, `until` (Unix ms), `kind` and `host`; newest
  first; it needs the `read` scope. A token limited to some hosts or tags sees only the alerts about
  those hosts, and a token limited by app sees none (an alert has no app to check).
- **Retention.** `silence.history_days` (default 30) keeps them in the database, purged as new ones
  arrive and part of `logpit --backup`; `0` keeps only the last 200 in memory. Changing it needs a
  restart.
- **Web UI.** The collapsible *Alerts* panel lists the latest 50 with their age, kind, host (click to
  filter) and whether the webhook took them; it does not depend on the search filters or time range.

### Maintenance windows

During planned work a host going quiet or noisy is expected. A window holds back the notifications about
the hosts it covers (silence and recovery, pattern alerts, new patterns and surges, volume alerts): they
reach neither the webhook nor the e-mail, but are still written to the log and recorded in the
[alert history](#alert-history), with `"muted"` and the window's reason in `details`.

```toml
[[maintenance]]
hosts = ["web*", "db1"]          # names or patterns; tags = ["prod"] adds the hosts of [[tags]]
reason = "kernel upgrade"        # shown in the alert history
from = "2026-10-05T02:00:00Z"    # a one-off period, RFC 3339 …
until = "2026-10-05T04:00:00Z"

[[maintenance]]
hosts = ["nas"]
between = "02:00-04:30"          # … or a time of day in UTC, every day
days = ["sun"]                   # or only on these days (mon … sun); an end before the start runs past midnight
```

A window needs `hosts` or `tags` (`"*"` for every host), and either `from` and `until` or `between`.
Alerts that name no host (a pattern alert without one) are never muted. The alert is muted when it is
raised, so a host that went silent during a window and is still silent afterwards is not announced again
when the window ends; its `logpit_host_silent` gauge stays accurate throughout. `SIGHUP` applies the
windows.

Windows can also be started on the fly with the `admin` scope; they live in memory until they end or
LogPit restarts:

```sh
curl -s -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  -X POST http://localhost:8080/api/maintenance \
  -d '{"hosts":["web*"],"minutes":60,"reason":"deploy"}'     # 201 {"id":1,"source":"api","active":true,…}
curl -s -H "Authorization: Bearer $ADMIN" http://localhost:8080/api/maintenance     # configured and API windows
curl -s -H "Authorization: Bearer $ADMIN" -X DELETE http://localhost:8080/api/maintenance/1   # 204
```

`minutes` is 1 to 10080 (a week) and at most 100 such windows exist at once.

## Pattern alerts

Silence alerts watch for logs that stop; pattern alerts watch for logs that pile up, such as five
disk errors in ten minutes, or a host that suddenly logs a thousand lines a minute. Each
`[[alerts]]` table counts the matching entries as they arrive and notifies when `count` of them
fall within `window_secs`:

```toml
[[alerts]]
name = "disk-errors"
pattern = "(?i)disk|smart"        # regex on the message (optional)
severity = ["err", "crit"]         # names or numbers (optional)
host = "pve"                       # exact match (optional)
app = "kernel"                     # exact match (optional)
count = 5
window_secs = 600
cooldown_secs = 1800               # quiet period after a notification; default window_secs
per_host = true                    # count and notify per host instead of overall

[[alerts]]
name = "flood"                     # no condition: every entry counts
count = 1000
window_secs = 60
per_host = true
```

- Notifications go to the same [webhook](#alert-webhook) as silence alerts (configured under
  `[silence]`, with any `webhook_format`), and are always written to the log. The message names the
  rule, the count, the window, the host (with `per_host`) and the last matching line, clipped to one
  line. `"event":"log_alert"` in the JSON format.
- Entries are counted as LogPit receives them, **after** ingestion rules, so dropped noise does
  not count and masked secrets never appear in a notification.
- After a notification the alert clears its matches and waits for the cooldown. Matches that arrive
  during the cooldown still count: a problem that goes on is reported again as soon as the cooldown
  ends and a new match arrives.
- Memory is bounded: an alert keeps at most `count` timestamps per host (`count` up to 10,000),
  and `per_host` tracks at most 1024 hosts per alert.
- Mistakes (a bad regex, `count = 0`, a duplicate name…) stop LogPit at startup with the alert's
  name. `logpit_alerts_fired_total{rule="…"}` counts the notifications.

### Alerts from the web UI

On the search page, each message pattern has a bell: it asks how many lines like it within how many
minutes (per host or overall) should notify you, and creates the rule, whose regular expression is the
pattern's template (each `<*>` matches anything). The rule runs at once, beside the configuration's
`[[alerts]]`, and behaves like them. The *Alert rules* section of `/admin` lists them, with how many times
each fired since LogPit started, edits them in place (name, lines, window, quiet period, per host;
the pattern is kept) and deletes them.

They are kept in the database (a table that does not change the schema version) and managed with the
`admin` scope:

```sh
curl -s -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' -X POST \
  http://localhost:8080/api/alert-rules \
  -d '{"name":"disk failing","pattern":"unreadable .* sectors","count":5,"window_secs":600,"per_host":true}'
curl -s -H "Authorization: Bearer $ADMIN" http://localhost:8080/api/alert-rules          # the stored rules
curl -s -H "Authorization: Bearer $ADMIN" -X DELETE http://localhost:8080/api/alert-rules/1   # 204
```

The body takes the fields of an `[[alerts]]` table; `name` is required (at most 80 characters, and not
one the configuration uses), and saving under an existing name replaces that rule. At most 100 rules are
stored. Each change rebuilds the stored rules, so their counts start again; a reload of the
configuration (`SIGHUP`) leaves them alone.

A pattern alert that keeps coming back while you fix the cause can be put on mute: *Mute 1 h* on its
notification in the page or on its row under `/admin` (or `POST /api/mutes`, admin scope). While muted,
its notifications are still logged and recorded in the alert history, marked *muted*, but the webhook and
e-mail are not told. Mutes work for the configuration's rules too, live in memory until they end or
LogPit restarts, and last at most a week:

```sh
curl -s -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' -X POST \
  http://localhost:8080/api/mutes -d '{"rule":"disk failing","minutes":60}'   # {"rule":"disk failing","until":…}
curl -s -H "Authorization: Bearer $ADMIN" http://localhost:8080/api/mutes      # the live mutes
curl -s -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' -X POST \
  http://localhost:8080/api/mutes -d '{"rule":"disk failing","minutes":0}'    # 204: unmuted
```

## New-pattern alerts

`[new_patterns]` notifies through the same webhook when a **message template never seen before**
appears (a new kind of error after a deployment, say), and optionally when a known template **surges**.
Templates are the ones of [Message patterns](#message-patterns): numbers and ids are masked, so
`disk 7 failed` and `disk 12 failed` are the same template and only `kernel panic at <*>` is new.

```toml
[new_patterns]
enabled = true                 # or LOGPIT_NEW_PATTERNS=true; off by default
learn_secs = 600               # quiet period after startup, templates seen meanwhile are learned
severity = ["warning", "err"]  # watched severities (default: warning and above)
ignore = ["healthcheck"]       # regexes: matching messages are not watched
max_per_minute = 10            # notification throttle; the rest count in a metric
max_known = 20000              # templates remembered
surge_factor = 8               # 0 (default) = no surge detection
surge_min = 100                # a surge needs this many entries in one window...
surge_window_secs = 60         # ...of this length, and 8x the template's usual count per window
```

```json
{"event":"new_pattern","host":"web1","severity":"err","pattern":"kernel panic at <*>",
 "sample":"kernel panic at 0xdead","message":"New log pattern (err) on web1: kernel panic at <*>. Example: …"}
{"event":"pattern_surge","pattern":"retry <*>","count":400,"usual":12,"window_secs":60,
 "sample":"retry 3","message":"Pattern surge: retry <*> seen 400 times within 60s (usually about 12). Last: …"}
```

- **Not announcing history.** The templates of the newest 50 000 stored entries are learned at
  startup, and nothing is announced during `learn_secs` after startup (or after the watch is turned on
  by a reload), so a restart or a fresh database does not raise a flood. The templates are kept in
  memory only. Only the watched severities are learned, so a pattern seen at `info` is still new the
  first time it shows up as an error.
- **Surges.** For each template LogPit keeps a moving average of its count per window. A surge is a
  window with at least `surge_min` entries and `surge_factor` times the usual count (at least 1). It
  needs 10 closed windows of history for that template, and is announced once, then not again for five
  windows. Templates learned from the database at startup have no history either.
- **Limits.** `max_per_minute` bounds notifications (new patterns and surges together; the suppressed
  ones are counted, not queued). With `max_known` templates remembered, new ones are neither learned
  nor announced and a warning is logged once; raise it. Words that vary (user names without digits…)
  make separate templates, so an app that logs them can produce many "new" patterns: `ignore` them.
- **Cost.** Every ingested entry at a watched severity is templated and looked up, which is why it
  is off by default. A reload (`SIGHUP`) applies the section and keeps what was learned; turning it
  on starts a new learning period.
- **Metrics** (while on): `logpit_new_patterns_total`, `logpit_pattern_surges_total`,
  `logpit_pattern_alerts_suppressed_total` and `logpit_known_patterns`. It uses the webhook of
  `[silence]` (see [Alert webhook](#alert-webhook)); without one, notifications go to the log only.

## Metrics from logs

`[[metrics]]` rules turn log lines into Prometheus counters on `/metrics`, to graph and alert on things
that exist only as text (failed logins, 5xx responses, backup runs) with the tools you already have:

```toml
[[metrics]]
name = "ssh_failures"                  # exposes logpit_log_ssh_failures_total
help = "Failed SSH logins"             # optional
pattern = "Failed password|Invalid user"   # regex on the message (optional)
severity = ["warning", "err"]          # names or numbers (optional)
host = "bastion"                       # exact match (optional)
app = "sshd"                           # exact match (optional)
labels = ["host", "level"]             # dimensions, see below

[[metrics]]
name = "api_requests"
app = "api"
labels = ["http.status"]               # a structured field (JSON, key=value, CEF…)
value_field = "bytes"                  # also adds up this numeric field
max_series = 100                       # default 200
```

```
logpit_log_ssh_failures_total{host="bastion",level="warning"} 14
logpit_log_api_requests_total{http_status="200"} 1209
logpit_log_api_requests_value_sum{http_status="200"} 5.1e+06
```

- **What is counted.** Entries after rate limits, `[[ingest.rules]]` (dropped entries are not counted,
  masked ones are matched on their masked text) and structured extraction, whether or not they are later
  stored, so the counters do not depend on retention. `name` must be unique, lower-case letters, digits
  and `_`, up to 48 characters; a rule without conditions counts everything.
- **Labels.** `host`, `app`, `level` (`critical`, `error`, `warning`, `info`, `debug`), or the name of a
  structured field (`.` and `-` become `_` in the label name; an entry without the field gets an empty
  value). At most 5 labels. Every distinct combination is a time series: once a rule has `max_series`
  of them (default 200, at most 10 000), further combinations are counted under the value `_other`
  of every label, so a runaway field cannot exhaust memory or your Prometheus.
- **Sums.** With `value_field`, the numeric values of that field are added in
  `logpit_log_<name>_value_sum`; a missing or non-numeric value counts the entry but adds nothing.
- **Reloading.** A change to any `[[metrics]]` rule (`SIGHUP`) replaces the rules and restarts their
  counters from zero, which Prometheus handles as a counter reset; reloads that leave them alone keep
  the counts. Counters are in memory only, so they also restart with LogPit.
- Every rule examines every entry, so keep patterns cheap and the list short. To be notified rather than
  to graph, use [pattern alerts](#pattern-alerts), or alert in Prometheus on these counters.

## Structured fields

Messages that contain a CEF record (`CEF:0|Vendor|Product|…|key=value …`), whether
sent over syslog or HTTP, are parsed on ingestion: `app` becomes the product name,
`message` becomes the event name (plus its `msg` text), and everything else is kept
in `fields` (`cef_vendor`, `cef_name`, `src`, `act`, …). Field values are part of the
full-text index. UniFi's `UNIFIutcTime` (UTC, with milliseconds) becomes the entry's time, so
UniFi events need no [`syslog.timezone`](#rfc-3164-timestamps); a value that does not parse
leaves the syslog one.

JSON ingestion accepts the same thing through an optional `"fields": {"key": "value"}`
object. Keys are limited to letters, digits, `_`, `.` and `-`.

### JSON and `key=value` in the message

Application logs are often structured text. A message that is a JSON object, or made of
`key=value` pairs (logfmt, quoted values allowed), has its values extracted into `fields`:

```
level=warn msg="slow request" path=/login status=504   →  level, msg, path, status
{"level":"error","http":{"status":500},"retry":true}   →  level, http.status, retry
```

Nested JSON objects are joined with dots (three levels deep); null, empty values and arrays are
skipped; keys are made valid (anything but letters, digits, `_`, `.`, `-` becomes `_`), and
there are at most 64 fields of 1 KiB each. The message text is kept exactly as received. Like
CEF fields, the values are filterable (`f=level:error`, `f=http.status:500`), can be used for
`group_by=field:level` in statistics, are matched by `q`, and are clickable in the web UI.

A multi-line message (a stack trace after a header line, as [`logpit ship --multiline-start`](#sending-logs) joins them) is
read as a whole first and, when that finds nothing, by its first line alone.

Plain text is left alone: `key=value` data only counts when there are at least two pairs and
no more bare words than pairs, so a sentence containing `a=b` is not mistaken for logfmt. Entries
that already carry fields (parsed CEF, or sent with `fields`) are not touched. Turn the
extraction off with `LOGPIT_PARSE_STRUCTURED=false` (or `[ingest] parse_structured = false`).

### Trace correlation

OpenTelemetry logs carry the trace and span of the request they belong to. LogPit keeps them as the
`trace_id` and `span_id` fields (lower-case hex), and does the same for logs from other sources: a
field named `traceId`, `trace-id`, `trace.id`, `otel.trace_id`, `dd.trace_id`, `x-b3-traceid` or
`x-trace-id` (and the span equivalents) is copied to `trace_id`/`span_id` when the entry has none, and a
`traceparent` field (W3C Trace Context) gives both. Hexadecimal ids are lower-cased, so `4BF9…` and
`4bf9…` are the same trace; the original field stays. This happens on every ingestion path, after
parsers and JSON or `key=value` extraction, and before ingestion rules and alerts.

```sh
curl -H "Authorization: Bearer $TOKEN" 'http://localhost:8080/api/logs?trace=4bf92f3577b34da6a3ce929d0e0e4736'
logpit search --trace 4bf92f3577b34da6a3ce929d0e0e4736 --since 1h      # oldest first, across hosts
```

`trace=<id>` is shorthand for `f=trace_id:<id>`, on search, export, live tail and the other endpoints that
take filters; read restrictions apply, so a token limited to some hosts sees only its part of the trace.
In the web UI a line that has a `trace_id` shows a **trace** link: it opens every entry of the trace
under the line, oldest first, with the time since the first one and the hosts involved (up to 500).

## Regex parsers

For plain-text formats with no JSON or `key=value` in them, `[[parsers]]` extract fields with a
regular expression: every **named group** becomes a field you can filter on (`f=status>=500`), list in
*Top values*, use as a [metric](#metrics-from-logs) label or in the Loki API.

```toml
[[parsers]]
name = "nginx"
app = "nginx"                        # filters: host, app, severity (all optional)
regex = '^(?P<remote>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<method>[A-Z]+) (?P<path>\S+) [^"]*" (?P<status>\d{3}) (?P<bytes>\d+|-)'
timestamp_from = "time"              # use the log's own time as the entry's timestamp
timestamp_format = "%d/%b/%Y:%H:%M:%S %z"

[[parsers]]
name = "sshd-failures"
app = "sshd"
regex = 'Failed password for (?:invalid user )?(?P<user>\S+) from (?P<src>\S+)'

[[parsers]]
name = "relayed"                     # a relay put the real host and level in the text
regex = '^(?P<h>\S+) (?P<a>\w+)\[\d+\]: (?P<lvl>[A-Za-z]+): (?P<msg>.*)$'
host_from = "h"
app_from = "a"
level_from = "lvl"                   # a word (error, warn…) or a number 0-7
message_from = "msg"                 # store only this part as the message
```

- **Order.** Parsers run in file order on every entry that passes their filters, and the **first one
  whose regex matches wins**; entries no parser matches are untouched. Put the specific ones first.
  A parser runs after CEF decoding and before generic extraction, rate limits having already used the
  original host, and before [ingestion rules](#ingestion-rules), [metrics](#metrics-from-logs) and
  alerts, which therefore see the fields and the rewritten host, level and message.
- **Generic extraction.** A matching parser stands in for the generic JSON and `key=value`
  extraction, whose fields would only add noise next to the precise ones. `keep_generic = true` runs it
  too, for keys the parser did not set.
- **Fields.** Group names become field names (anything outside letters, digits, `_`, `.` and `-` is
  replaced by `_`); empty captures add nothing, values are clipped to 1 KiB and an entry holds at most 64
  fields. Unnamed groups, `(?:…)` included, only structure the pattern.
- **Special groups.** `level_from` sets the severity (an unrecognized word leaves it as it was),
  `host_from` and `app_from` replace the host and app, `message_from` replaces the stored message, and
  `timestamp_from` sets the entry's time from `timestamp_format`: `rfc3339`, `unix` (seconds, maybe
  fractional), `unix_ms`, or a strftime pattern (a pattern without a zone is read as UTC; one with `%z`
  is converted). A time that does not parse leaves the entry's own. The group itself stays a field.
- **Safety.** Expressions run in linear time whatever they contain and are limited to 4096 bytes and a
  bounded compiled size; an invalid one, a `*_from` naming a missing group or a regex without any named
  group is refused at startup (or by the reload, which then changes nothing).
- **Reloading and metrics.** `SIGHUP` applies changes. `logpit_parser_matched_total{parser="…"}` counts
  what each parser matched, which shows a format that stopped matching.
- Parsers do not touch entries already stored; and they cost a regex match per entry that passes the
  filters, so give them `app` or `host` filters rather than letting each one scan everything.

## Ingestion rules

Rules drop noise and mask secrets **before** an entry is stored, shown in the live tail or
exported, so what they remove never reaches the disk. They live in the TOML file as
`[[ingest.rules]]` tables and run in order, after structured fields have been extracted:

```toml
[[ingest.rules]]
name = "cron-noise"            # shown in the metrics; defaults to rule-<position>
action = "drop"
app = "cron"
severity = ["info", "debug"]   # names or numbers; all conditions must hold

[[ingest.rules]]
name = "healthchecks"
action = "drop"
pattern = "GET /healthz"       # a regular expression searched in the message

[[ingest.rules]]
name = "secrets"
action = "mask"
pattern = '(password|token)=\S+'
replace = "$1=[hidden]"        # default "***"; $1 is a capture group, $$ a literal $

[[ingest.rules]]
name = "router-ips"
action = "mask"
host = "router"                # limit the rule to one host
pattern = '\b\d{1,3}(\.\d{1,3}){3}\b'
```

- `host` and `app` are exact matches, `severity` is any of the listed levels, and `pattern` is a
  [Rust regex](https://docs.rs/regex/latest/regex/#syntax) (case-sensitive; use `(?i)`; it runs in
  linear time, so a pattern cannot be used to stall LogPit).
- **`drop`** discards the entry when every condition given matches; it needs at least one
  condition, so a rule cannot drop everything by mistake. Later rules do not run on a dropped
  entry. A host whose entries are all dropped still counts as alive for
  [silence alerts](#silence-alerts).
- **`mask`** needs a `pattern` and rewrites what it matches in the message and in every field
  value. A rule that masks a host's IP addresses is a rule over that host only.
- Rules see the text as received: put masks for secrets before drops that match on that text.
- A mistake (unknown action, bad regex, a drop with no condition, an unknown severity) stops
  LogPit at startup with the rule's name, instead of being found on the first entry.
- `logpit_rule_hits_total{rule="…",action="drop|mask"}` counts the entries each rule dropped or
  changed, so a rule that never matches, or matches too much, is easy to spot.

Rules apply to what LogPit receives from now on; entries already stored are not rewritten.
They are TOML-only (there is no environment variable for a list of rules).

## Forwarding entries

`[[forward]]` targets receive a copy of the entries that match their filter, to feed a SIEM, a second
site or another LogPit while this one keeps the full history:

```toml
[[forward]]
name = "siem"                          # label in metrics and logs; default forward-1, forward-2…
url = "https://siem.example/ingest"    # NDJSON batches over HTTP(S), or
# syslog = "tcp://10.0.0.5:514"        # RFC 5424 over udp:// or tcp://
headers = ["Authorization: Bearer …"]  # for url only
severity = ["warning", "err"]          # filter: severities, host, app, regex on the message
host = "web1"
app = "nginx"
pattern = "denied|refused"
batch_lines = 200                      # HTTP: entries per request (default 200)
batch_ms = 1000                        # HTTP: longest wait before sending a partial batch
queue = 10000                          # entries waiting for this target (default 10 000)
```

- **HTTP.** One POST per batch, `Content-Type: application/x-ndjson`, one JSON object per line with
  `ts` (Unix ms), `host`, `app`, `severity` (0-7), `message` and `fields`: exactly what `POST /ingest`
  of another LogPit reads, so `url = "http://other-logpit:8080/ingest"` with its write token as a
  `Bearer` header replicates entries with their structured fields. Any 2xx is success.
- **Syslog.** RFC 5424 messages, facility `user`, the severity as priority, the timestamp of the entry,
  host and app as the header fields, and the structured fields as one `[logpit@32473 key="value"]`
  element (the first 32 fields whose name is at most 32 characters, values clipped to 256).
  UDP sends one datagram per entry; TCP keeps one connection and frames messages by octet
  counting (RFC 6587), and reconnects when it breaks. There is no TLS for syslog output: use
  `https://` or a TLS-terminating relay.
- **What is forwarded.** The entries that are stored, after [collapsing](#collapsing-repeated-messages)
  (summaries included) and after masking and drop rules, so a secret masked at ingestion is never sent.
- **When the target is slow or down.** Each target has its own bounded queue and task, so ingestion is
  never held up. A failed batch (connection error, timeout, HTTP `408`, `425`, `429` or `5xx`) is
  retried five times after 1, 2, 4, 8 and 16 seconds, then dropped; other `4xx` answers drop it at
  once. While a batch is being retried, the queue fills and further entries for that target are
  dropped, not buffered on disk. For delivery that survives outages and restarts, ship from the
  source with `logpit ship` (see [Sending logs](#sending-logs)).
- **Metrics.** `logpit_forward_sent_total`, `…dropped_total` (queue full), `…failed_total` (given up or
  refused) and `…queued`, each with a `target` label, and a warning in the log when a target starts
  failing (never with the URL or headers, which can hold secrets).
- Changing `[[forward]]` needs a restart; a reload reports it.

## Collapsing repeated messages

A flapping link or a crash loop can write the same line thousands of times. `[ingest.dedup]` stores
the first one as usual, only counts the identical ones that follow, and replaces them with a single
summary entry when the window ends, the way syslogd's "last message repeated N times" does:

```toml
[ingest.dedup]
enabled = true       # off by default, when every repeat is stored
window_secs = 30     # how long repeats are counted after the first one
max_keys = 10000     # distinct messages tracked at once
```

```
12:00:00  sw1  link down port 7                                     <- the first one
12:00:30  sw1  link down port 7 [repeated 412 more times over 29s]  <- the summary, field repeats=412
```

- **Identical** means the same host, app, severity and message (after masking and field extraction,
  so numbers in the text count: `retry 3` and `retry 4` are different). The summary takes the severity
  and host, the timestamp of the last repeat, and a `repeats` field you can filter on (`f=repeats>100`).
  The window starts at the first entry; when it ends the next identical entry is stored and starts a new
  run, and a run with no repeats leaves nothing behind. Summaries are also written when LogPit stops.
- **What still sees every entry.** Rate limits, [pattern alerts](#pattern-alerts),
  [new-pattern alerts](#new-pattern-alerts), [metrics from logs](#metrics-from-logs) and silence tracking
  run before it, so counts and alerts are unchanged; only what is stored, listed and shown in the live
  tail is reduced.
- **Limits.** Messages over 2 KiB are never collapsed, and when `max_keys` messages are being tracked
  further new ones are stored without collapsing. State is in memory: a restart ends the runs (their
  summaries are written first on a normal stop). Counters: `logpit_dedup_suppressed_total`,
  `logpit_dedup_summaries_total` and `logpit_dedup_groups`. A reload (`SIGHUP`) applies the section, and
  runs in progress finish with the window they started with.

## Rate limiting

A sender that loops, or a misconfigured debug level, can send thousands of lines a second and
push everyone else out of the write queue. Rate limits cap that at the door, per host and/or
overall:

```toml
[ingest.rate_limit]
per_host_per_sec = 500   # sustained entries per second from one host (0 = no limit)
burst = 2000             # entries a host may send at once; default 4x the rate
global_per_sec = 5000    # sustained entries per second across all hosts (0 = no limit)
```

or `LOGPIT_RATE_LIMIT_PER_HOST`, `LOGPIT_RATE_LIMIT_BURST` and `LOGPIT_RATE_LIMIT_GLOBAL`. It is a
token bucket: each host starts with `burst` entries of credit, which refill at the sustained rate,
so short bursts pass and a continuous flood is cut to the rate. The global limit has a burst of
four times its rate and is shared by all hosts; an entry is refused if either limit is exhausted,
and a refused entry uses up neither.

- Refused entries are dropped, not queued. They do not reach storage, the live tail, alerts or
  exports, but they still count as activity for [silence alerts](#silence-alerts), so a host that
  is merely too chatty is not reported as silent.
- At most 4096 hosts get a bucket of their own; further host names share one, so inventing names
  does not get around the limit.
- `logpit_rate_limited_total` counts refused entries and `logpit_rate_limited_host_total{host}`
  lists the ten hosts refused most. The log notes a host that exceeds its limit, at most once a
  minute per host.
- Limits apply to what arrives after the host name is known (the `host` of the entry), not to
  bytes, and a single request of the HTTP API is judged entry by entry.

## Reloading the configuration

Send `SIGHUP` and LogPit re-reads its configuration file and the files it points to, without
restarting and without dropping the connections it is serving:

```sh
systemctl reload logpit              # with contrib/logpit.service
podman kill --signal HUP logpit      # or: docker kill --signal HUP logpit
kill -HUP "$(pidof logpit)"
```

**Applied by a reload**: `[volume]`, `[[maintenance]]`, `syslog.timezone`, the HTTPS certificates, `[[ingest.rules]]`, `[[parsers]]`, `[[tags]]` (and the tokens that use them), `[ingest.dedup]`, `[[alerts]]`, `[[metrics]]`, `[new_patterns]`, `[ingest.rate_limit]`,
`ingest.parse_structured`, the silence thresholds, webhook and check interval, the API tokens
(`http.token`, `[[http.tokens]]` and the `*_FILE` secret files), and the syslog TLS certificate,
key and client CA files. The last two are read again on every reload, so renewing a certificate or
rotating a token in place (same paths) takes effect without touching the configuration text. TLS
connections already open keep the certificate they started with; new ones get the new one.

**Needs a restart**: `storage.*`, the syslog and HTTP listen addresses, `http.max_body_bytes`, and
turning the TLS listener on or off. The reload still goes ahead and says in the log which of these
differ, until you restart.

- **All or nothing.** The new file is fully parsed, every rule and alert compiled, the webhook
  checked and the certificates loaded before anything is replaced. If any step fails (a TOML typo, a
  bad regex, an unreadable certificate) the error is logged, `logpit_config_reload_failures_total`
  goes up, and the running settings stay exactly as they were.
- **Unchanged parts are kept.** A rule list, alert list or rate-limit setting that did not change
  is not rebuilt, so its counters, alert windows and rate-limit buckets carry over. A changed one
  starts fresh.
- Environment variables are fixed for the life of the process: a `LOGPIT_*` variable still wins over
  the file after a reload, and changing one needs a restart (use the `*_FILE` variants to rotate
  secrets). `logpit_config_reloads_total` counts successful reloads.
- Switching silence alerts on at runtime starts watching hosts from then on (hosts named in
  `[silence.hosts]` immediately); hosts that were silent before the reload are not known.
- There is no HTTP endpoint for reloading: it needs access to the process, not to the API.

## Without a container

Each release also publishes static binaries (`x86_64` and `aarch64`, musl) with a
`SHA256SUMS` file on the [releases page](https://github.com/Opperiesen/logpit/releases),
and [`contrib/logpit.service`](contrib/logpit.service) is a hardened systemd unit.
Or build from source:

```sh
cargo build --release
cp logpit.example.toml logpit.toml
./target/release/logpit --config logpit.toml
```

Without a config file the defaults listen on loopback only.

## Limitations

- RFC 3164 timestamps carry no year or zone, so reception time is used unless `syslog.timezone` says how
  to read them (see [RFC 3164 timestamps](#rfc-3164-timestamps)); a zone name needs the system's zone
  database (`/usr/share/zoneinfo`), which the `scratch` image does not include.
- Entries stored before CEF support keep their raw message; only new ones are parsed.
- Single node, no user accounts (access is by token), and no built-in certificate management
  (use [HTTPS](#https) or a reverse proxy). Retention is by age and optionally by size; see
  [Retention by severity](#retention-by-severity) and [Disk size cap](#disk-size-cap).
- Read restrictions take host and app names or patterns (`*`, `?`), and tags for hosts.

## Development

```sh
cargo fmt --all && cargo clippy --all-targets -- -D warnings && cargo test
```

The release workflow builds the static binaries, then packages them into the
multi-arch image and smoke-tests it (healthcheck, auth, syslog ingestion, read-only
with all capabilities dropped) before pushing to `ghcr.io`.

## License

Apache-2.0. See [LICENSE](LICENSE).
