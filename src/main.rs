use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc::sync_channel;
use std::time::Duration;

use anyhow::Context;
use logpit::api::{self, AppState};
use logpit::config::Config;
use logpit::ingest::{self, Sink, now_ms};
use logpit::metrics::Metrics;
use logpit::silence::{self, MAX_TRACKED_HOSTS, Rules, Tracker, Webhook};
use logpit::store;
use tokio::task::JoinSet;
use tracing_subscriber::EnvFilter;

const USAGE: &str = "usage: logpit [--config <path>] [--healthcheck] | --help | --version

Configuration comes from the TOML file (--config, $LOGPIT_CONFIG or ./logpit.toml)
and LOGPIT_* environment variables, which take precedence.
--healthcheck probes the running instance's /healthz and exits 0 or 1.";

struct Args {
    config: Option<PathBuf>,
    healthcheck: bool,
}

fn parse_args() -> anyhow::Result<Args> {
    let mut args = std::env::args().skip(1);
    let mut config = std::env::var_os("LOGPIT_CONFIG").map(PathBuf::from);
    let mut healthcheck = false;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" | "-c" => {
                config = Some(PathBuf::from(args.next().context("--config needs a path")?));
            }
            "--healthcheck" => healthcheck = true,
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

async fn retention_loop(path: PathBuf, days: u32) {
    let mut tick = tokio::time::interval(Duration::from_secs(3600));
    loop {
        tick.tick().await;
        let cutoff = now_ms() - i64::from(days) * 86_400_000;
        let path = path.clone();
        let result = tokio::task::spawn_blocking(move || {
            let conn = store::open(&path)?;
            store::purge_older_than(&conn, cutoff).map_err(anyhow::Error::from)
        })
        .await;
        match result {
            Ok(Ok(0)) => {}
            Ok(Ok(n)) => tracing::info!("retention: purged {n} entries"),
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
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

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let cfg = Config::load(args.config.as_deref())?;

    let udp = parse_addr("syslog.udp_listen", &cfg.syslog.udp_listen)?;
    let tcp = parse_addr("syslog.tcp_listen", &cfg.syslog.tcp_listen)?;
    let http: SocketAddr = cfg
        .http
        .listen
        .parse()
        .with_context(|| format!("invalid http.listen address {:?}", cfg.http.listen))?;

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

    let silence_rules = Rules::from_config(&cfg.silence);
    let tracker = Arc::new(Tracker::new(silence_rules.enabled()));
    if silence_rules.enabled() {
        let known = store::known_hosts(&seed_conn, MAX_TRACKED_HOSTS)?;
        tracker.seed(
            known
                .iter()
                .map(String::as_str)
                .chain(silence_rules.configured_hosts()),
            now_ms(),
        );
    }

    let sink = Sink::new(tx, metrics, cfg.storage.max_message_bytes, tracker.clone());
    let state = AppState {
        sink: sink.clone(),
        db_path: db_path.clone(),
        auth: Arc::new(cfg.auth()),
    };
    if !state.auth.enabled() && !http.ip().is_loopback() {
        tracing::warn!("HTTP API is exposed on {http} without any token; set http.token");
    }

    let mut tasks: JoinSet<anyhow::Result<()>> = JoinSet::new();
    if let Some(addr) = udp {
        tasks.spawn(ingest::run_udp(addr, sink.clone()));
    }
    if let Some(addr) = tcp {
        tasks.spawn(ingest::run_tcp(addr, sink.clone()));
    }
    drop(sink);

    let listener = tokio::net::TcpListener::bind(http)
        .await
        .with_context(|| format!("cannot bind HTTP listener on {http}"))?;
    tracing::info!("HTTP listening on http://{http}");
    let app = api::router(state, cfg.http.max_body_bytes);
    tasks.spawn(async move { axum::serve(listener, app).await.map_err(Into::into) });

    if silence_rules.enabled() {
        let webhook = match cfg.silence.webhook_url.as_str() {
            "" => None,
            url => Some(Webhook::parse(url)?),
        };
        let interval = Duration::from_secs(cfg.silence.check_interval_secs);
        tasks.spawn(async move {
            silence::run(tracker, silence_rules, interval, webhook).await;
            Ok(())
        });
    }

    if cfg.storage.retention_days > 0 {
        tasks.spawn(async move {
            retention_loop(db_path, cfg.storage.retention_days).await;
            Ok(())
        });
    }

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
