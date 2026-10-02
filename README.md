# LogPit

A small, self-contained log aggregator written in Rust, shipped as a container.
One static binary in a `scratch` image, a single SQLite file, a few MB of RAM — a
lightweight alternative to Graylog or ELK for homelabs and small servers
(Proxmox, routers, LXC containers…).

## Features

- **Ingestion**: syslog over UDP and TCP (RFC 5424 and RFC 3164), and HTTP
  (`POST /ingest`) accepting NDJSON or a JSON array, including raw
  `journalctl -o json` output.
- **Structured fields**: CEF events (e.g. UniFi's SIEM export) are parsed into
  key/value fields, which are indexed for search and filterable by exact match.
- **Storage**: SQLite (WAL) with FTS5 full-text search, batched writes,
  automatic retention.
- **Search**: `GET /api/logs` and a minimal built-in web UI at `/`.
- **Robustness**: bounded queue with drop counters (no unbounded memory),
  message size limits, TCP connection limits and idle timeouts, graceful
  shutdown that flushes pending writes, parser tested against malformed input.
- **Container-native**: multi-arch image (amd64, arm64), non-root, runs read-only
  with all capabilities dropped, configured through environment variables,
  built-in healthcheck, token via secret file.
- **Observability**: Prometheus metrics at `/metrics`, health at `/healthz`.

## Quick start

```sh
TOKEN=$(openssl rand -base64 24 | tr -d '=+/\n')
podman run -d --name logpit --restart always \
  -p 514:5514/udp -p 514:5514/tcp -p 8080:8080 \
  -e LOGPIT_HTTP_TOKEN="$TOKEN" \
  -v logpit-data:/data \
  ghcr.io/opperiesen/logpit:0.2.1
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
migrated database cannot be opened by older versions, so **back up the volume
before upgrading** (copy `logpit.db` and `logpit.db-wal` from `/data`). Rolling
back means restoring that backup and the previous tag.

## Configuration

Environment variables win over the config file. All are optional.

| Variable | Default (in the image) | Meaning |
|---|---|---|
| `LOGPIT_HTTP_TOKEN` | *(none)* | Protects `/ingest` and `/api/*`. **Set it.** |
| `LOGPIT_HTTP_TOKEN_FILE` | | Read the token from a file (container secret). Not with `LOGPIT_HTTP_TOKEN`. |
| `LOGPIT_HTTP_LISTEN` | `0.0.0.0:8080` | Web UI and API address |
| `LOGPIT_SYSLOG_UDP_LISTEN` | `0.0.0.0:5514` | Empty string disables UDP syslog |
| `LOGPIT_SYSLOG_TCP_LISTEN` | `0.0.0.0:5514` | Empty string disables TCP syslog |
| `LOGPIT_STORAGE_PATH` | `/data/logpit.db` | SQLite file |
| `LOGPIT_RETENTION_DAYS` | `14` | `0` disables purging |
| `LOGPIT_CONFIG` | `/etc/logpit/logpit.toml` | TOML file with the same settings |

For more settings (batching, queue size, message limit) mount your own TOML over
`/etc/logpit/logpit.toml`; see [`logpit.example.toml`](logpit.example.toml). Unknown
keys are rejected at startup.

The image runs as an unprivileged user, so syslog listens on 5514 inside the
container and you map it to 514 when publishing. With a bind mount instead of a
named volume, make the directory writable by uid 65532.

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

UniFi: *Settings → CyberSecure → Traffic Logging → Activity Logging → SIEM Server*,
with LogPit's address and port 514.

## Searching

```sh
curl -H "Authorization: Bearer $TOKEN" \
  'http://localhost:8080/api/logs?q=disk+error&host=pve&level=3&since=1700000000000&limit=50'
```

| Parameter | Meaning |
|---|---|
| `q` | Words that must all appear in the message or its fields (always treated as literals) |
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
full-text index.

JSON ingestion accepts the same thing through an optional `"fields": {"key": "value"}`
object. Keys are limited to letters, digits, `_`, `.` and `-`.

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
