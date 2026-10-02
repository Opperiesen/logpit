# LogPit

A small, self-contained log aggregator written in Rust. One static binary, a
single SQLite file, a few MB of RAM — a lightweight alternative to Graylog or
ELK for homelabs and small servers (Proxmox, routers, LXC containers…).

## Features

- **Ingestion**: syslog over UDP and TCP (RFC 5424 and RFC 3164), and HTTP
  (`POST /ingest`) accepting NDJSON or a JSON array, including raw
  `journalctl -o json` output.
- **Storage**: SQLite (WAL) with FTS5 full-text search, batched writes,
  automatic retention.
- **Structured fields**: CEF events (e.g. UniFi's SIEM export) are parsed into
  key/value fields, which are indexed for search and filterable by exact match.
- **Search**: `GET /api/logs` and a minimal built-in web UI at `/`.
- **Robustness**: bounded queue with drop counters (no unbounded memory),
  message size limits, TCP connection limits and idle timeouts, graceful
  shutdown that flushes pending writes, parser tested against malformed input.
- **Observability**: Prometheus metrics at `/metrics`, health at `/healthz`.

## Quick start

```sh
cargo build --release
cp logpit.example.toml logpit.toml
./target/release/logpit --config logpit.toml
```

Open <http://127.0.0.1:8080>. Defaults listen on loopback only; edit the config
to receive logs from other machines and set `http.token` before exposing HTTP.

## Sending logs

Syslog (rsyslog, on any Linux host or router):

```
*.* @@logpit-host:514      # TCP; use a single @ for UDP
```

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

## Searching

```sh
curl -H "Authorization: Bearer $TOKEN" \
  'http://localhost:8080/api/logs?q=disk+error&host=pve&level=3&since=1700000000000&limit=50'
```

| Parameter | Meaning |
|---|---|
| `q` | Words that must all appear in the message (always treated as literals) |
| `host`, `app` | Exact match |
| `level` | Maximum severity number: 0 emergency … 3 error … 6 info … 7 debug |
| `f` | `key:value` exact match on a structured field; repeat to combine (e.g. `f=act:blocked&f=proto:TCP`) |
| `since`, `until` | Unix timestamps in milliseconds |
| `limit` | 1–1000, default 100 |

## Structured fields (CEF)

Messages that contain a CEF record (`CEF:0|Vendor|Product|…|key=value …`), whether
sent over syslog or HTTP, are parsed on ingestion: `app` becomes the product name,
`message` becomes the event name (plus its `msg` text), and everything else is kept
in `fields` (`cef_vendor`, `cef_name`, `src`, `act`, …). Field values are part of the
full-text index. Configure UniFi under *Settings → CyberSecure → Traffic Logging →
Activity Logging → SIEM Server* with LogPit's address and port.

JSON ingestion accepts the same thing through an optional `"fields": {"key": "value"}`
object. Keys are limited to letters, digits, `_`, `.` and `-`.

## Configuration

See [`logpit.example.toml`](logpit.example.toml). Unknown keys are rejected at
startup. A systemd unit is provided in [`contrib/`](contrib/logpit.service).

## Limitations (v0.1)

- RFC 3164 timestamps carry no year or zone, so reception time is used.
- TCP syslog supports newline-delimited framing only (no octet counting).
- Retention is age-based only; there is no size cap yet.
- Entries stored before CEF support keep their raw message; only new ones are parsed.
- The v0.2 database schema cannot be opened by older builds (back up before upgrading).
- Single node, no alerting, no multi-user accounts, no built-in TLS
  (use a reverse proxy).

## Development

```sh
cargo fmt --all && cargo clippy --all-targets -- -D warnings && cargo test
```

## License

Apache-2.0. See [LICENSE](LICENSE).
