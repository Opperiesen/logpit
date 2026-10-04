# LogPit

Self-contained log aggregator in Rust (edition 2024): one static binary, one SQLite file, shipped in a
`scratch` container. Targets homelabs (Proxmox, LXC, routers, UniFi). See `PRODUCT.md` for users and
principles, `DESIGN.md` for the web UI's visual system.

## Commands

CI (`.github/workflows/ci.yml`) runs exactly these; run them before calling work done:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
```

- One test: `cargo test --locked <name>` (e.g. `web_ui_stays_within_its_size_budget`).
- Run locally: `cp logpit.example.toml logpit.toml` (git-ignored), then `cargo run -- --config logpit.toml`.
- Subcommands of the same binary: `ship`, `search`, `tail`, `restore`; flags `--healthcheck`, `--backup`.

## Layout

Single crate, flat modules in `src/` (one concern per file, listed in `src/lib.rs`), each opening with a
`//!` doc comment that states its contract. Start there before changing a module.

- `main.rs`: argument parsing and wiring. `config.rs`: TOML + `LOGPIT_*` environment (environment wins).
- Ingestion: `ingest.rs` (syslog listeners), `syslog.rs`, `framing.rs`, `gelf.rs`, `loki.rs`, `otlp.rs`,
  `grpc.rs`, `cef.rs`, `structured.rs`, `parsers.rs`, then `rules.rs` (drop/mask) before the queue.
- `store.rs`: SQLite (WAL, FTS5), batched writer thread, retention, migrations. The largest module.
- `api.rs`: HTTP API and the embedded web UI. `lokiapi.rs` + `logql.rs`: Loki query API for Grafana.
- `query.rs`: the `q` search language, compiled to FTS5 made only of quoted strings.
- Alerting: `alerts.rs`, `silence.rs`, `volume.rs`, `patterns.rs`, `maintenance.rs`, delivered by
  `webhook.rs` and `mail.rs`, recorded by `alertlog.rs`.
- `live.rs`: settings reloadable on `SIGHUP`; a reload builds everything first and swaps only if all built.
- `shipper.rs`: `logpit ship` (journal and files, spooled, at-least-once). `cli.rs`: `search` / `tail`.
- Tests: unit tests inline in each module (`#[cfg(test)]`), end-to-end in `tests/http_api.rs`, malformed
  input in `tests/fuzz_smoke.rs`.

## Constraints

- **Few dependencies.** Protocol pieces are written in-tree (`snappy.rs`, `inflate.rs`, `proto.rs`,
  `grpc.rs`, `mail.rs`, `httpget.rs`). Look for an existing module before adding a crate, and ask before
  adding one. The release binary must stay fully static (musl); CI checks it.
- **Bounded memory.** Queues and per-rule state are bounded, with drop counters; never buffer unbounded.
- **Untrusted input.** Everything from the network is hostile: parsers must not panic (the release profile
  uses `panic = "abort"`). New parsers get malformed-input tests.
- **Schema changes.** Add a migration and bump `SCHEMA_VERSION` in `store.rs`; never edit an existing
  migration. A migrated database cannot be opened by older versions, so say so in the changelog.
- **Web UI** (`src/web/index.html`, `pages.html`, shared `theme.css`, embedded with `include_str!`):
  vanilla HTML/CSS/JS, no build step, no framework, no external resource (strict CSP, `INDEX_CSP` in
  `api.rs`). Each page has a 32 KiB budget for the served (minified, gzipped) size, enforced by
  `web_ui_stays_within_its_size_budget`; do not raise it without asking. The minifier drops whole-line
  comments and indentation, so the script must not contain multi-line strings. Desktop browsers only;
  phones are not a target. Keep keyboard paths and accessible names working.

## Documentation to keep in step

A user-visible change updates, in the same commit:

- `CHANGELOG.md`, under `## Unreleased`.
- `README.md` (features list, configuration table, the relevant section).
- `logpit.example.toml` for a new config key, and the `LOGPIT_*` table in the README if it has a variable.
- `contrib/` if deployment defaults change.

## Commits and releases

- Subject: one imperative sentence saying what changed, no prefix (`Add …`, `Serve …`, `Tighten …`).
  Body: plain prose explaining what and why, wrapped at ~72 columns.
- Release: bump `version` in `Cargo.toml` (and `Cargo.lock`), move `Unreleased` to `## X.Y.Z - date` in
  the changelog, update the image tag in the README quick start, commit as `Release X.Y.Z`. Pushing the
  tag `vX.Y.Z` triggers `.github/workflows/release.yml`, which publishes the GitHub release and the
  `ghcr.io` image: only tag or push when asked.
