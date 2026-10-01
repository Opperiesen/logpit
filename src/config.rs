use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use serde::Deserialize;

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub storage: StorageConfig,
    pub syslog: SyslogConfig,
    pub http: HttpConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct StorageConfig {
    pub path: PathBuf,
    /// Entries older than this are purged. 0 disables retention.
    pub retention_days: u32,
    pub batch_size: usize,
    pub flush_interval_ms: u64,
    /// Capacity of the in-memory queue between ingestion and storage.
    pub queue_capacity: usize,
    /// Messages longer than this are truncated.
    pub max_message_bytes: usize,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SyslogConfig {
    /// UDP listen address; empty string disables the listener.
    pub udp_listen: String,
    /// TCP listen address (newline-delimited); empty string disables it.
    pub tcp_listen: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HttpConfig {
    pub listen: String,
    /// When set, `/ingest` and `/api/*` require `Authorization: Bearer <token>`.
    pub token: Option<String>,
    pub max_body_bytes: usize,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            path: PathBuf::from("logpit.db"),
            retention_days: 14,
            batch_size: 500,
            flush_interval_ms: 500,
            queue_capacity: 10_000,
            max_message_bytes: 16 * 1024,
        }
    }
}

impl Default for SyslogConfig {
    fn default() -> Self {
        Self {
            udp_listen: "127.0.0.1:5514".into(),
            tcp_listen: "127.0.0.1:5514".into(),
        }
    }
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:8080".into(),
            token: None,
            max_body_bytes: 8 * 1024 * 1024,
        }
    }
}

impl Config {
    pub fn parse(text: &str) -> anyhow::Result<Self> {
        let cfg: Config = toml::from_str(text).context("invalid configuration")?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Loads `path` if given (it must exist), else `./logpit.toml` if present, else defaults.
    pub fn load(path: Option<&Path>) -> anyhow::Result<Self> {
        let (path, required) = match path {
            Some(p) => (p.to_path_buf(), true),
            None => (PathBuf::from("logpit.toml"), false),
        };
        match std::fs::read_to_string(&path) {
            Ok(text) => Self::parse(&text).with_context(|| format!("in {}", path.display())),
            Err(e) if !required && e.kind() == std::io::ErrorKind::NotFound => {
                let cfg = Config::default();
                cfg.validate()?;
                Ok(cfg)
            }
            Err(e) => Err(e).with_context(|| format!("cannot read {}", path.display())),
        }
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        let s = &self.storage;
        if s.batch_size == 0 || s.queue_capacity == 0 || s.flush_interval_ms == 0 {
            bail!("storage.batch_size, queue_capacity and flush_interval_ms must be > 0");
        }
        if s.max_message_bytes < 64 {
            bail!("storage.max_message_bytes must be >= 64");
        }
        if matches!(&self.http.token, Some(t) if t.is_empty()) {
            bail!("http.token must not be empty (remove it to disable auth)");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_valid_and_local() {
        let cfg = Config::parse("").unwrap();
        assert!(cfg.http.listen.starts_with("127.0.0.1"));
        assert_eq!(cfg.storage.retention_days, 14);
    }

    #[test]
    fn rejects_unknown_keys_and_bad_values() {
        assert!(Config::parse("[storage]\nbogus = 1").is_err());
        assert!(Config::parse("[storage]\nbatch_size = 0").is_err());
        assert!(Config::parse("[http]\ntoken = \"\"").is_err());
    }

    #[test]
    fn partial_override_keeps_other_defaults() {
        let cfg = Config::parse("[syslog]\nudp_listen = \"0.0.0.0:514\"").unwrap();
        assert_eq!(cfg.syslog.udp_listen, "0.0.0.0:514");
        assert_eq!(cfg.syslog.tcp_listen, "127.0.0.1:5514");
    }
}
