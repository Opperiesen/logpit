use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::sync::mpsc::sync_channel;
use std::time::Duration;

use anyhow::Context;
use logpit::api::{self, AppState};
use logpit::config::Config;
use logpit::ingest::{self, Sink, now_ms};
use logpit::live::LiveSettings;
use logpit::metrics::Metrics;
use logpit::silence::{self, MAX_TRACKED_HOSTS, Tracker};
use logpit::store;
use tokio::task::JoinSet;
use tracing_subscriber::EnvFilter;

const USAGE: &str =
    "usage: logpit [--config <path>] [--healthcheck] [--backup <file>] | --help | --version

Configuration comes from the TOML file (--config, $LOGPIT_CONFIG or ./logpit.toml)
and LOGPIT_* environment variables, which take precedence.
--healthcheck probes the running instance's /healthz and exits 0 or 1.
--backup writes a consistent copy of the database to a new file (safe while LogPit runs).";

struct Args {
    config: Option<PathBuf>,
    healthcheck: bool,
    backup: Option<PathBuf>,
}

fn parse_args() -> anyhow::Result<Args> {
    let mut args = std::env::args().skip(1);
    let mut config = std::env::var_os("LOGPIT_CONFIG").map(PathBuf::from);
    let mut healthcheck = false;
    let mut backup = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" | "-c" => {
                config = Some(PathBuf::from(args.next().context("--config needs a path")?));
            }
            "--healthcheck" => healthcheck = true,
            "--backup" => {
                backup = Some(PathBuf::from(
                    args.next().context("--backup needs a file path")?,
                ));
            }
            "--help" | "-h" => {
                println!("{USAGE}");
                std::process::exit(0);
            }
            "--version" | "-V" => {
                println!("logpit {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            other => anyhow::bail!("unknown argument {other:?}\n{USAGE}"),
        }
    }
    Ok(Args {
        config,
        healthcheck,
        backup,
    })
}

fn parse_addr(label: &str, s: &str) -> anyhow::Result<Option<SocketAddr>> {
    if s.is_empty() {
        return Ok(None);
    }
    s.parse()
        .map(Some)
        .with_context(|| format!("invalid {label} address {s:?}"))
}

/// Time-based retention runs hourly; the size cap and the size gauge every minute.
async fn retention_loop(
    path: PathBuf,
    retention_days: [u32; 8],
    max_db_bytes: u64,
    metrics: Arc<Metrics>,
) {
    const TICK: Duration = Duration::from_secs(60);
    const TICKS_PER_PURGE: u64 = 60;
    let mut tick = tokio::time::interval(TICK);
    let mut n = 0u64;
    loop {
        tick.tick().await;
        let purge_by_age =
            n.is_multiple_of(TICKS_PER_PURGE) && retention_days.iter().any(|&d| d > 0);
        n += 1;
        let now = now_ms();
        let cutoffs = retention_days.map(|d| (d > 0).then(|| now - i64::from(d) * 86_400_000));
        let path = path.clone();
        let result = tokio::task::spawn_blocking(move || -> anyhow::Result<(usize, usize, u64)> {
            let conn = store::open(&path)?;
            let aged = if purge_by_age {
                store::purge(&conn, &cutoffs)?
            } else {
                0
            };
            let evicted = if max_db_bytes > 0 {
                store::enforce_size_limit(&conn, max_db_bytes)?
            } else {
                0
            };
            Ok((aged, evicted, store::used_bytes(&conn)?))
        })
        .await;
        match result {
            Ok(Ok((aged, evicted, used))) => {
                metrics.db_used_bytes.store(used, Ordering::Relaxed);
                Metrics::inc(&metrics.size_evicted, evicted as u64);
                if aged > 0 {
                    tracing::info!("retention: purged {aged} entries");
                }
                if evicted > 0 {
                    tracing::warn!(
                        "size limit: evicted {evicted} oldest entries ({} MB in use, limit {} MB)",
                        used / 1_000_000,
                        max_db_bytes / 1_000_000
                    );
                }
            }
            Ok(Err(e)) => tracing::error!("retention failed: {e:#}"),
            Err(e) => tracing::error!("retention task failed: {e}"),
        }
    }
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = term.recv() => {}
                }
                return;
            }
            Err(e) => tracing::warn!("cannot install SIGTERM handler: {e}"),
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}

/// Reloads the configuration each time the process receives SIGHUP. A file that does not load, or
/// a rule or certificate that does not build, is reported and the running settings stay as they are.
#[cfg(unix)]
async fn reload_on_sighup(
    path: Option<PathBuf>,
    mut current: Config,
    settings: Arc<LiveSettings>,
    tracker: Arc<Tracker>,
    metrics: Arc<Metrics>,
) {
    use std::sync::atomic::Ordering;
    use tokio::signal::unix::{SignalKind, signal};
    let mut hup = match signal(SignalKind::hangup()) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("cannot listen for SIGHUP, configuration reload is unavailable: {e}");
            return;
        }
    };
    while hup.recv().await.is_some() {
        tracing::info!("SIGHUP received, reloading the configuration");
        let outcome = Config::load(path.as_deref()).and_then(|new| {
            let report = settings.reload(&current, &new)?;
            Ok((new, report))
        });
        match outcome {
            Ok((new, report)) => {
                // Silence tracking follows the new thresholds, and starts watching hosts that the
                // new file names explicitly.
                let silence = settings.silence.get();
                tracker.set_enabled(silence.rules.enabled());
                if silence.rules.enabled() {
                    tracker.seed(silence.rules.configured_hosts(), now_ms());
                }
                if report.applied.is_empty() {
                    tracing::info!("configuration reloaded: nothing changed");
                } else {
                    tracing::info!("configuration reloaded: {}", report.applied.join(", "));
                }
                if !report.restart_required.is_empty() {
                    tracing::warn!(
                        "these settings changed but only take effect after a restart: {}",
                        report.restart_required.join(", ")
                    );
                }
                metrics.reloads.fetch_add(1, Ordering::Relaxed);
                // Remember what the running process is configured with, to diff against next time.
                // Settings that need a restart keep their running values in `current`.
                current = Config {
                    storage: current.storage.clone(),
                    syslog: logpit::config::SyslogConfig {
                        udp_listen: current.syslog.udp_listen.clone(),
                        tcp_listen: current.syslog.tcp_listen.clone(),
                        tls_listen: current.syslog.tls_listen.clone(),
                        ..new.syslog.clone()
                    },
                    http: logpit::config::HttpConfig {
                        listen: current.http.listen.clone(),
                        max_body_bytes: current.http.max_body_bytes,
                        ..new.http.clone()
                    },
                    ..new
                };
            }
            Err(e) => {
                tracing::error!("reload failed, keeping the running configuration: {e:#}");
                metrics.reload_failures.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // `logpit ship ...` is a log shipper, not the server: it has its own options.
    let raw: Vec<String> = std::env::args().skip(1).collect();
    if raw.first().map(String::as_str) == Some("ship") {
        if raw[1..].iter().any(|a| a == "--help" || a == "-h") {
            println!("{}", logpit::shipper::USAGE);
            return Ok(());
        }
        let cfg = logpit::shipper::ShipConfig::from_args(&raw[1..], &|k| std::env::var(k).ok())?;
        tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
            .init();
        return logpit::shipper::run(cfg).await;
    }

    let args = parse_args()?;

    if args.healthcheck {
        let cfg = Config::load(args.config.as_deref())?;
        let listen: SocketAddr = cfg
            .http
            .listen
            .parse()
            .with_context(|| format!("invalid http.listen address {:?}", cfg.http.listen))?;
        return logpit::health::check(logpit::health::probe_target(listen));
    }

    if let Some(dest) = &args.backup {
        let cfg = Config::load(args.config.as_deref())?;
        let size = store::backup(&cfg.storage.path, dest)?;
        println!("backup written to {} ({size} bytes)", dest.display());
        return Ok(());
    }

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let cfg = Config::load(args.config.as_deref())?;

    let udp = parse_addr("syslog.udp_listen", &cfg.syslog.udp_listen)?;
    let tcp = parse_addr("syslog.tcp_listen", &cfg.syslog.tcp_listen)?;
    let tls = parse_addr("syslog.tls_listen", &cfg.syslog.tls_listen)?;
    let gelf_udp = parse_addr("gelf.udp_listen", &cfg.gelf.udp_listen)?;
    let gelf_tcp = parse_addr("gelf.tcp_listen", &cfg.gelf.tcp_listen)?;
    let http: SocketAddr = cfg
        .http
        .listen
        .parse()
        .with_context(|| format!("invalid http.listen address {:?}", cfg.http.listen))?;
    // Everything a reload can replace (rules, alerts, limits, tokens, silence thresholds and the
    // webhook, TLS certificates) is built here, so a bad rule or certificate fails fast.
    let settings = Arc::new(LiveSettings::from_config(&cfg)?);

    let db_path = cfg.storage.path.clone();
    let conn = store::open(&db_path)?;
    let seed_conn = store::open(&db_path)?;
    let metrics = Arc::new(Metrics::default());
    let (tx, rx) = sync_channel(cfg.storage.queue_capacity);

    let writer = {
        let metrics = metrics.clone();
        let batch = cfg.storage.batch_size;
        let flush = Duration::from_millis(cfg.storage.flush_interval_ms);
        std::thread::Builder::new()
            .name("logpit-writer".into())
            .spawn(move || store::run_writer(conn, rx, batch, flush, metrics))?
    };

    let silence_rules = settings.silence.get();
    let tracker = Arc::new(Tracker::new(silence_rules.rules.enabled()));
    if silence_rules.rules.enabled() {
        let known = store::known_hosts(&seed_conn, MAX_TRACKED_HOSTS)?;
        tracker.seed(
            known
                .iter()
                .map(String::as_str)
                .chain(silence_rules.rules.configured_hosts()),
            now_ms(),
        );
    }
    drop(silence_rules);

    let retention_metrics = metrics.clone();
    let reload_metrics = metrics.clone();
    // Pattern alerts reach the notifier through a channel, so ingestion never waits for a webhook.
    let (alert_tx, mut alert_rx) = tokio::sync::mpsc::channel::<silence::Event>(256);

    let sink = Sink::new(tx, metrics, cfg.storage.max_message_bytes, tracker.clone())
        .with_settings(settings.clone())
        .with_alert_channel(alert_tx);
    let state = AppState {
        sink: sink.clone(),
        db_path: db_path.clone(),
        settings: settings.clone(),
        exports: Arc::new(tokio::sync::Semaphore::new(api::MAX_EXPORTS)),
    };
    if !settings.auth.get().enabled() && !http.ip().is_loopback() {
        tracing::warn!("HTTP API is exposed on {http} without any token; set http.token");
    }

    let mut tasks: JoinSet<anyhow::Result<()>> = JoinSet::new();
    if let Some(addr) = udp {
        tasks.spawn(ingest::run_udp(addr, sink.clone()));
    }
    if let Some(addr) = tcp {
        tasks.spawn(ingest::run_tcp(addr, sink.clone()));
    }
    if let Some(addr) = gelf_udp {
        tasks.spawn(ingest::run_gelf_udp(addr, sink.clone()));
    }
    if let Some(addr) = gelf_tcp {
        tasks.spawn(ingest::run_gelf_tcp(addr, sink.clone()));
    }
    if let (Some(addr), Some(acceptor)) = (tls, settings.tls.clone()) {
        tasks.spawn(ingest::run_tls(addr, sink.clone(), acceptor));
    }
    drop(sink);

    let listener = tokio::net::TcpListener::bind(http)
        .await
        .with_context(|| format!("cannot bind HTTP listener on {http}"))?;
    tracing::info!("HTTP listening on http://{http}");
    let app = api::router(state, cfg.http.max_body_bytes);
    tasks.spawn(async move { axum::serve(listener, app).await.map_err(Into::into) });

    // Both notifiers read their webhook from the settings each time, so a reload can add, change
    // or remove alerts and the webhook without restarting them.
    {
        let settings = settings.clone();
        tasks.spawn(async move {
            while let Some(event) = alert_rx.recv().await {
                tracing::warn!(
                    "{}",
                    event.payload()["message"].as_str().unwrap_or_default()
                );
                if let Some(hook) = settings.silence.get().webhook.clone() {
                    tokio::spawn(async move { hook.send(&event).await });
                }
            }
            Ok(())
        });
    }
    {
        let (tracker, settings) = (tracker.clone(), settings.clone());
        tasks.spawn(async move {
            silence::run(tracker, settings).await;
            Ok(())
        });
    }
    #[cfg(unix)]
    {
        let (path, settings, running) = (args.config.clone(), settings.clone(), cfg.clone());
        tasks.spawn(async move {
            reload_on_sighup(path, running, settings, tracker, reload_metrics).await;
            Ok(())
        });
    }
    #[cfg(not(unix))]
    drop((tracker, reload_metrics));

    let retention = cfg.storage.retention_table()?;
    let max_db_bytes = cfg.storage.max_db_size_mb * 1_000_000;
    tasks.spawn(async move {
        retention_loop(db_path, retention, max_db_bytes, retention_metrics).await;
        Ok(())
    });

    tokio::select! {
        _ = shutdown_signal() => tracing::info!("shutdown requested"),
        Some(res) = tasks.join_next() => {
            match res {
                Ok(Ok(())) => tracing::error!("a service task exited unexpectedly"),
                Ok(Err(e)) => tracing::error!("service task failed: {e:#}"),
                Err(e) => tracing::error!("service task panicked: {e}"),
            }
        }
    }

    // Stop producers, drop their queue handles, then let the writer drain and exit.
    tasks.shutdown().await;
    tokio::task::spawn_blocking(move || writer.join())
        .await?
        .map_err(|_| anyhow::anyhow!("writer thread panicked"))?;
    tracing::info!("bye");
    Ok(())
}
