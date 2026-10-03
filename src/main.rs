use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::sync::mpsc::sync_channel;
use std::time::Duration;

use anyhow::Context;
use logpit::api::{self, AppState};
use logpit::audit::AuditLog;
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
--backup writes a consistent copy of the database to a new file (safe while LogPit runs).

Other commands: `logpit ship` follows the journal and log files, `logpit restore` loads archive
files into a server, `logpit search` and `logpit tail` query a server; all take --help.";

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
    archiver: Option<Arc<logpit::archive::Archiver>>,
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
        let (archiver, archive_metrics) = (archiver.clone(), metrics.clone());
        let result = tokio::task::spawn_blocking(move || -> anyhow::Result<(usize, usize, u64)> {
            let conn = store::open(&path)?;
            // Entries are archived, a chunk at a time, before they are deleted; if the archive
            // cannot be written they stay in the database.
            let write = |rows: &[store::Row]| -> anyhow::Result<()> {
                let archiver = archiver.as_ref().expect("only called while archiving");
                match archiver.write(rows) {
                    Ok(_) => {
                        Metrics::inc(&archive_metrics.archived, rows.len() as u64);
                        Ok(())
                    }
                    Err(e) => {
                        Metrics::inc(&archive_metrics.archive_errors, 1);
                        Err(e.context("archiving entries before removal"))
                    }
                }
            };
            let hook: Option<store::ArchiveHook<'_>> = archiver.is_some().then_some(&write);
            let aged = if purge_by_age {
                store::purge(&conn, &cutoffs, hook)?
            } else {
                0
            };
            let evicted = if max_db_bytes > 0 {
                store::enforce_size_limit(&conn, max_db_bytes, hook)?
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
    let command = raw.first().map(String::as_str);
    let usage = match command {
        Some("ship") => Some(logpit::shipper::USAGE),
        Some("search" | "tail") => Some(logpit::cli::SEARCH_USAGE),
        Some("restore") => Some(logpit::restore::USAGE),
        _ => None,
    };
    if let Some(usage) = usage
        && raw[1..].iter().any(|a| a == "--help" || a == "-h")
    {
        println!("{usage}");
        return Ok(());
    }
    if command == Some("ship") {
        let cfg = logpit::shipper::ShipConfig::from_args(&raw[1..], &|k| std::env::var(k).ok())?;
        tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
            .init();
        return logpit::shipper::run(cfg).await;
    }

    // `logpit search ...` and `logpit tail ...` query a running server from the terminal.
    if matches!(command, Some("search" | "tail")) {
        let cli = logpit::cli::Cli::from_args(&raw[1..], &|k| std::env::var(k).ok(), now_ms())?;
        let mut out = std::io::stdout().lock();
        let result = if raw[0] == "search" {
            logpit::cli::search(&cli, &mut out).await.map(|_| ())
        } else {
            tokio::select! {
                r = logpit::cli::tail(&cli, &mut out, None) => r,
                _ = tokio::signal::ctrl_c() => Ok(()),
            }
        };
        // A closed pipe (`logpit search | head`) is not an error worth a message.
        return match result {
            Err(e)
                if e.downcast_ref::<std::io::Error>()
                    .is_some_and(|io| io.kind() == std::io::ErrorKind::BrokenPipe) =>
            {
                Ok(())
            }
            other => other,
        };
    }

    // `logpit restore ...` loads archive files into a server.
    if command == Some("restore") {
        let cfg = logpit::restore::RestoreConfig::from_args(&raw[1..], &|k| std::env::var(k).ok())?;
        let dry = cfg.dry_run;
        let summary = logpit::restore::run(cfg).await?;
        println!(
            "{} {} entries from {} files{}",
            if dry { "would restore" } else { "restored" },
            summary.entries,
            summary.files,
            if summary.bad_lines > 0 {
                format!(" ({} unreadable lines skipped)", summary.bad_lines)
            } else {
                String::new()
            }
        );
        return Ok(());
    }

    let args = parse_args()?;

    if args.healthcheck {
        let cfg = Config::load(args.config.as_deref())?;
        let listen: SocketAddr = cfg
            .http
            .listen
            .parse()
            .with_context(|| format!("invalid http.listen address {:?}", cfg.http.listen))?;
        let target = logpit::health::probe_target(listen);
        // Served over TLS: the probe talks TLS to its own server without checking the certificate
        // (it is about liveness, and the certificate is for the public name, not localhost); a
        // server that demands client certificates is only checked for accepting connections.
        return match (&cfg.http.tls_cert, &cfg.http.tls_client_ca) {
            (Some(_), None) => logpit::health::check_tls(target),
            (Some(_), Some(_)) => logpit::health::check_connect(target),
            _ => logpit::health::check(target),
        };
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

    // Set at shutdown: connections still open keep queue senders alive, so the writer cannot
    // wait for all of them to be dropped.
    let stop_writer = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let writer = {
        let (metrics, stop) = (metrics.clone(), stop_writer.clone());
        let batch = cfg.storage.batch_size;
        let flush = Duration::from_millis(cfg.storage.flush_interval_ms);
        std::thread::Builder::new()
            .name("logpit-writer".into())
            .spawn(move || store::run_writer(conn, rx, batch, flush, metrics, stop))?
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

    // Templates already in the database are not "new": learn them before ingestion starts.
    if settings.watch.enabled() {
        let (samples, _) = store::recent_samples(
            &seed_conn,
            &store::Query::default(),
            logpit::watch::SEED_ENTRIES,
            400,
        )?;
        settings.watch.seed(
            samples.iter().map(|s| (s.severity, s.message.as_str())),
            now_ms(),
        );
        tracing::info!(
            "new-pattern alerts on: learned the templates of {} stored entries, quiet for {}s",
            samples.len(),
            cfg.new_patterns.learn_secs
        );
    }

    let retention_metrics = metrics.clone();
    let reload_metrics = metrics.clone();
    // Pattern alerts reach the notifier through a channel, so ingestion never waits for a webhook.
    let (alert_tx, mut alert_rx) = tokio::sync::mpsc::channel::<silence::Event>(256);

    let forwarders = logpit::forward::Forwarders::start(&cfg.forward)?;
    let volume_tx = alert_tx.clone();
    let alert_log = Arc::new(logpit::alertlog::AlertLog::new(
        Some(db_path.clone()),
        cfg.silence.history_days,
    ));
    let sink = Sink::new(tx, metrics, cfg.storage.max_message_bytes, tracker.clone())
        .with_settings(settings.clone())
        .with_forwarders(forwarders)
        .with_alert_channel(alert_tx);
    let state = AppState {
        sink: sink.clone(),
        db_path: db_path.clone(),
        settings: settings.clone(),
        exports: Arc::new(tokio::sync::Semaphore::new(api::MAX_EXPORTS)),
        alerts: alert_log.clone(),
        audit: Arc::new(if cfg.http.audit_retention_days > 0 {
            AuditLog::persistent(&db_path, cfg.http.audit_retention_days)?
        } else {
            AuditLog::default()
        }),
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
    // Volume baselines start from the stored history, then each window is closed on a timer.
    if settings.volume.enabled() {
        let history = store::host_window_counts(
            &seed_conn,
            now_ms(),
            i64::try_from(cfg.volume.window_secs).unwrap_or(300) * 1000,
            cfg.volume.baseline_windows,
        )?;
        let hosts = history.len();
        settings.volume.seed(history);
        tracing::info!("volume alerts on: baselines seeded for {hosts} hosts");
    }
    {
        let settings = settings.clone();
        tasks.spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(settings.volume.window_secs())).await;
                for event in settings.volume.close_window(now_ms()) {
                    let _ = volume_tx.try_send(event);
                }
            }
        });
    }
    // Summaries of collapsed repeats are written when their window ends, and once more at exit.
    let flush_sink = sink.clone();
    {
        let (sink, settings) = (sink.clone(), settings.clone());
        tasks.spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(1));
            loop {
                tick.tick().await;
                for summary in settings.dedup.flush(now_ms()) {
                    sink.push_summary(summary);
                }
            }
        });
    }
    drop(sink);

    let listener = tokio::net::TcpListener::bind(http)
        .await
        .with_context(|| format!("cannot bind HTTP listener on {http}"))?;
    let app = api::router(state, cfg.http.max_body_bytes);
    match settings.http_tls.clone() {
        Some(acceptor) => {
            tracing::info!("HTTP listening on https://{http}");
            let listener =
                logpit::tls::HttpsListener::new(listener, acceptor, retention_metrics.clone())?;
            let service = app.into_make_service_with_connect_info::<logpit::tls::PeerAddr>();
            tasks.spawn(async move { axum::serve(listener, service).await.map_err(Into::into) });
        }
        None => {
            tracing::info!("HTTP listening on http://{http}");
            let service = app.into_make_service_with_connect_info::<std::net::SocketAddr>();
            tasks.spawn(async move { axum::serve(listener, service).await.map_err(Into::into) });
        }
    }

    // Both notifiers read their webhook from the settings each time, so a reload can add, change
    // or remove alerts and the webhook without restarting them; every notification is also kept in
    // the alert history.
    {
        let (settings, alerts) = (settings.clone(), alert_log.clone());
        tasks.spawn(async move {
            while let Some(event) = alert_rx.recv().await {
                logpit::alertlog::dispatch(event, &settings, &alerts);
            }
            Ok(())
        });
    }
    {
        let (tracker, settings) = (tracker.clone(), settings.clone());
        tasks.spawn(async move {
            silence::run(tracker, settings, alert_log).await;
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

    let archiver = cfg
        .storage
        .archive_dir
        .as_deref()
        .map(logpit::archive::Archiver::new)
        .transpose()?
        .map(Arc::new);
    if let Some(dir) = &cfg.storage.archive_dir {
        tracing::info!("cold archive: expired entries go to {}", dir.display());
    }
    // Scheduled backups of the database, into a directory checked now so a bad path stops startup.
    if let Some(dir) = &cfg.backup.dir {
        logpit::backup::prepare(dir)?;
        retention_metrics
            .backup_enabled
            .store(true, std::sync::atomic::Ordering::Relaxed);
        tasks.spawn({
            let (db, cfg, metrics) = (
                db_path.clone(),
                cfg.backup.clone(),
                retention_metrics.clone(),
            );
            async move {
                logpit::backup::run(db, cfg, metrics).await;
                Ok(())
            }
        });
    }
    let retention = cfg.storage.retention_table()?;
    let max_db_bytes = cfg.storage.max_db_size_mb * 1_000_000;
    tasks.spawn(async move {
        retention_loop(
            db_path,
            retention,
            max_db_bytes,
            retention_metrics,
            archiver,
        )
        .await;
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
    for summary in settings.dedup.flush_all() {
        flush_sink.push_summary(summary);
    }
    drop(flush_sink);
    stop_writer.store(true, Ordering::Release);
    tokio::task::spawn_blocking(move || writer.join())
        .await?
        .map_err(|_| anyhow::anyhow!("writer thread panicked"))?;
    tracing::info!("bye");
    Ok(())
}
