# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

Homelab administrators and self-hosters running a few servers (Proxmox nodes, LXC containers, routers, small VMs). They open the LogPit web UI when something breaks or looks wrong: search and filter logs across hosts, follow an incident in the live tail, and work out which host or app is noisy, silent or failing.

## Product Purpose

LogPit is a small, self-contained log aggregator: it ingests logs from the usual homelab sources, stores them in a single SQLite file with full-text search, and makes them searchable from a built-in web UI, a CLI and an HTTP API. Success is an admin going from "something is off" to the relevant log lines quickly, without running or maintaining a heavier stack.

## Positioning

LogPit speaks homelab formats natively: syslog (RFC 5424/3164, UDP/TCP/TLS) from routers and appliances, UniFi's CEF/SIEM export parsed into fields, `journalctl -o json`, Proxmox and LXC hosts, plus OTLP, Loki push and GELF. Those sources are first-class rather than afterthoughts of an enterprise pipeline.

## Operating Context

- Deployed as one container (static binary, `scratch` image, multi-arch), configured through environment variables or `logpit.example.toml`.
- The web UI is used from desktop browsers (laptop or desktop screen, mouse and keyboard). Phones are not a target (confirmed by the owner, 2026-10-04): the narrow-screen layout may stay as a fallback, but touch gestures and phone ergonomics are not acceptance criteria.
- The web UI is served by the same process at `/`, authenticated with a token; read-only tokens may hide parts of the UI (e.g. *Views*).
- Typical use: an incident or curiosity session — search, time range, live tail, hosts panel, top values, message patterns, trace correlation, alert history, export.
- Grafana (Loki API) and the `logpit search` / `logpit tail` CLI are alternative views on the same data.

## Capabilities and Constraints

- UI priority, as stated by the owner: **the best visual result for the smallest size and the fastest response time.** Weight, render cost and latency are part of every design decision.
- Current implementation: one file, `src/web/index.html`, embedded in the binary with `include_str!` (`src/api.rs`); vanilla HTML/CSS/JS, no front-end build step or framework.
- The page is served with a strict Content-Security-Policy (`default-src 'none'`, inline scripts only, see `INDEX_CSP` in `src/api.rs`): no external scripts, stylesheets, fonts or CDNs.
- Existing UI features to preserve: search with filters, live tail, volume chart with stacking, saved views, hosts panel, top values, message patterns, alert history, NDJSON/CSV export, trace links, display preferences (theme auto/light/dark, time format, density, wrapping, columns) kept in the browser.

## Brand Commitments

Name: LogPit. No logo or other brand assets exist in the repository.

## Evidence on Hand

- `README.md` and `CHANGELOG.md` describe the features and release history accurately.
- No users, testimonials, benchmarks or adoption figures exist; do not invent any.

## Product Principles

1. Lightness is a feature: every byte and millisecond the UI adds must earn its place.
2. Homelab sources first: formats and workflows of routers, hypervisors and containers come before enterprise abstractions.
3. Get to the relevant line fast: search, filter and live tail beat dashboards and decoration.
4. Self-contained: everything the UI needs ships in the binary.
