# LogPit

A small, self-contained log aggregator written in Rust, shipped as a container.
One static binary in a `scratch` image, a single SQLite file, a few MB of RAM — a
lightweight alternative to Graylog or ELK for homelabs and small servers
(Proxmox, routers, LXC containers…).

## Features

- **Ingestion**: syslog over UDP, TCP and TLS (RFC 5424 and RFC 3164, newline or octet-counted
  framing, optional client certificates), and HTTP
  (`POST /ingest`) accepting NDJSON or a JSON array, including raw
  `journalctl -o json` output.
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
- **Silence alerts**: get notified (webhook + Prometheus gauge) when a host stops sending logs.
- **Observability**: Prometheus metrics at `/metrics`, health at `/healthz`.

## Quick start

```sh
TOKEN=$(openssl rand -base64 24 | tr -d '=+/\n')
podman run -d --name logpit --restart always \
  -p 514:5514/udp -p 514:5514/tcp -p 8080:8080 \
  -e LOGPIT_HTTP_TOKEN="$TOKEN" \
  -v logpit-data:/data \
  ghcr.io/opperiesen/logpit:0.5.0
echo "$TOKEN"
```

(`docker` works the same.) Open <http://localhost:8080> and enter the token.
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
| `LOGPIT_SYSLOG_UDP_LISTEN` | `0.0.0.0:5514` | Empty string disables UDP syslog |
| `LOGPIT_SYSLOG_TCP_LISTEN` | `0.0.0.0:5514` | Empty string disables TCP syslog |
| `LOGPIT_SYSLOG_TLS_LISTEN` | *(off)* | Address of the syslog-over-TLS listener, e.g. `0.0.0.0:6514`; needs the next two |
| `LOGPIT_SYSLOG_TLS_CERT`, `LOGPIT_SYSLOG_TLS_KEY` | | PEM certificate chain and private key for the TLS listener |
| `LOGPIT_SYSLOG_TLS_CLIENT_CA` | | PEM CA file: clients must then present a certificate issued by it |
| `LOGPIT_STORAGE_PATH` | `/data/logpit.db` | SQLite file |
| `LOGPIT_RETENTION_DAYS` | `14` | `0` disables purging |
| `LOGPIT_PARSE_STRUCTURED` | `true` | Extract JSON and `key=value` data from messages into fields |
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

A write token can only `POST /ingest`, a read token can only call `/api/logs` and `/api/tail`;
the wrong scope gets `403` (a missing or unknown token gets `401`). `LOGPIT_HTTP_TOKEN` keeps
both scopes, and any token turns authentication on. Further tokens can be added in the TOML
file with `[[http.tokens]]` entries (`token`, `scopes = ["read", "write"]`). `/healthz` and
`/metrics` stay open.

## Sending logs

Syslog (rsyslog, on any Linux host or router):

```
*.* @@logpit-host:514      # TCP; use a single @ for UDP
```

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

Other sources:

Proxmox / systemd journal — run this every few seconds from a systemd timer or
cron on the node. `--cursor-file` remembers where the last run stopped, so each
run ships only new entries (the first run ships the whole journal):

```sh
journalctl -o json --no-pager --cursor-file=/var/lib/logpit-shipper.cursor \
  | curl -fsS -H "Authorization: Bearer $TOKEN" -X POST --data-binary @- \
      http://logpit-host:8080/ingest
```

If the POST fails, that batch is not retried (the cursor has already moved).

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
| `f` | `key:value` exact match on a structured field; repeat to combine (e.g. `f=act:blocked&f=proto:TCP`) |
| `since`, `until` | Unix timestamps in milliseconds |
| `limit` | 1–1000, default 100 |
| `before` | Paging cursor `<ts>:<id>`: only entries older than that one, as given by the `X-Next-Cursor` header |

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
timestamp of a line to open its context under it; the panel can show more lines, switch between
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
clicking a host or app in it filters the log table on it. With *Live* on, the chart is redrawn every 5 s (while the tab is visible). Clicking a bar zooms to that bucket's time window (shown as an extra entry in the time-range selector; pick another range to leave it, and *Live* is switched off).
It takes the filters of `/api/logs` (`q`, `host`, `app`, `level`, `f`, `since`, `until`) plus:

| Parameter | Meaning |
|---|---|
| `bucket` | Bucket size: seconds, or `30s`, `5m`, `1h`, `1d` (at least 1 s). Default: a size giving about 120 buckets over the range |
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
It needs the `read` scope. The web UI shows it in the collapsible *Hosts* panel below the chart: it follows the
current filters and time range, lists every host even when one is selected, refreshes with the
chart in Live mode, and clicking a host filters the log table on it. Click a column header to sort by it (again to reverse; Enter or Space works with the
keyboard); the choice is remembered, and the server does the sorting, so the 200 hosts shown
are the first 200 in that order.

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

## Live tail

```sh
curl -N -H "Authorization: Bearer $TOKEN" 'http://localhost:8080/api/tail?host=pve&level=4'
```

Streams new entries as server-sent events (one JSON object per `data:` line). It accepts
the `q`, `host`, `app`, `level` and `f` filters of `/api/logs`; `since`, `until` and `limit`
are ignored. Unlike search, `q` here is matched in memory (same syntax, but words match as case-insensitive
substrings of the message and field values). Only entries ingested after the connection opens are sent. A slow client
gets a `lagged` event with the number of skipped entries; at most 32 clients may tail at once.

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

## Structured fields

Messages that contain a CEF record (`CEF:0|Vendor|Product|…|key=value …`), whether
sent over syslog or HTTP, are parsed on ingestion: `app` becomes the product name,
`message` becomes the event name (plus its `msg` text), and everything else is kept
in `fields` (`cef_vendor`, `cef_name`, `src`, `act`, …). Field values are part of the
full-text index.

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

Plain text is left alone: `key=value` data only counts when there are at least two pairs and
no more bare words than pairs, so a sentence containing `a=b` is not mistaken for logfmt. Entries
that already carry fields (parsed CEF, or sent with `fields`) are not touched. Turn the
extraction off with `LOGPIT_PARSE_STRUCTURED=false` (or `[ingest] parse_structured = false`).

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

- RFC 3164 timestamps carry no year or zone, so reception time is used.
- TCP syslog supports newline-delimited framing only (no octet counting).
- Retention is age-based only; there is no size cap yet.
- Entries stored before CEF support keep their raw message; only new ones are parsed.
- Single node, no alerting, no multi-user accounts, no built-in TLS
  (use a reverse proxy).

## Development

```sh
cargo fmt --all && cargo clippy --all-targets -- -D warnings && cargo test
```

The release workflow builds the static binaries, then packages them into the
multi-arch image and smoke-tests it (healthcheck, auth, syslog ingestion, read-only
with all capabilities dropped) before pushing to `ghcr.io`.

## License

Apache-2.0. See [LICENSE](LICENSE).
