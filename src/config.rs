use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use serde::Deserialize;

use crate::auth::Scope;

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub storage: StorageConfig,
    pub syslog: SyslogConfig,
    pub http: HttpConfig,
    pub silence: SilenceConfig,
    pub ingest: IngestConfig,
    /// Pattern alerts (`[[alerts]]`), notified through the webhook configured under `[silence]`.
    pub alerts: Vec<crate::alerts::AlertConfig>,
    /// Notifications for message patterns never seen before (`[new_patterns]`), sent through the
    /// same webhook.
    pub new_patterns: crate::watch::WatchConfig,
    /// Prometheus counters derived from the logs (`[[metrics]]`), exposed on `/metrics`.
    pub metrics: Vec<crate::logmetrics::MetricConfig>,
    pub gelf: GelfConfig,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct StorageConfig {
    pub path: PathBuf,
    /// Entries older than this are purged. 0 disables retention.
    pub retention_days: u32,
    /// Per-severity override of `retention_days`, by name or number (e.g. `debug = 2`,
    /// `err = 90`); 0 keeps that severity forever.
    pub retention_by_severity: BTreeMap<String, u32>,
    /// Soft cap on the database size in MB: the oldest entries are evicted beyond it.
    /// 0 disables the cap.
    pub max_db_size_mb: u64,
    pub batch_size: usize,
    pub flush_interval_ms: u64,
    /// Capacity of the in-memory queue between ingestion and storage.
    pub queue_capacity: usize,
    /// Messages longer than this are truncated.
    pub max_message_bytes: usize,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct SyslogConfig {
    /// UDP listen address; empty string disables the listener.
    pub udp_listen: String,
    /// TCP listen address (newline-delimited or octet-counted); empty string disables it.
    pub tcp_listen: String,
    /// TLS listen address (RFC 5425, usually port 6514); empty string disables it. Needs
    /// `tls_cert` and `tls_key`.
    pub tls_listen: String,
    /// PEM certificate chain presented to clients (the server certificate first).
    pub tls_cert: Option<PathBuf>,
    /// PEM private key for `tls_cert`.
    pub tls_key: Option<PathBuf>,
    /// PEM file of CAs: when set, clients must present a certificate issued by one of them.
    pub tls_client_ca: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct HttpConfig {
    pub listen: String,
    /// When set, `/ingest` and `/api/*` require `Authorization: Bearer <token>`.
    pub token: Option<String>,
    /// Additional tokens limited to some scopes (`read`, `write`, `admin`), with an optional name
    /// and read restrictions. With `token`, any configured token turns authentication on.
    pub tokens: Vec<TokenConfig>,
    pub max_body_bytes: usize,
    /// Days to keep the audit trail in the database; `0` keeps it in memory only (the last 1000
    /// events, lost on restart).
    pub audit_retention_days: u32,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TokenConfig {
    pub token: String,
    pub scopes: Vec<Scope>,
    /// How the token appears in the audit trail and `/api/tokens` (default `token-N`, the
    /// position in the list). Letters, digits, `_`, `-` and `.`.
    #[serde(default)]
    pub name: Option<String>,
    /// Limits reading to these hosts (exact names); empty means every host.
    #[serde(default)]
    pub hosts: Vec<String>,
    /// Limits reading to these apps (exact names); empty means every app.
    #[serde(default)]
    pub apps: Vec<String>,
}

/// Longest token name and longest host or app list of one token.
const MAX_TOKEN_NAME: usize = 64;
const MAX_ACCESS_ITEMS: usize = 100;

/// GELF listeners (Graylog's JSON log format). `POST /gelf` on the HTTP port is always available.
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct GelfConfig {
    /// UDP listen address; empty string (the default) disables it.
    pub udp_listen: String,
    /// TCP listen address (messages separated by NUL or newline); empty string disables it.
    pub tcp_listen: String,
}

/// How incoming entries are processed before they are stored.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct IngestConfig {
    /// Extract JSON objects and `key=value` pairs found in messages into structured fields.
    pub parse_structured: bool,
    /// Rules that drop noisy entries or mask secrets, applied in order (`[[ingest.rules]]`).
    pub rules: Vec<crate::rules::RuleConfig>,
    /// Per-host and global limits on how fast entries are accepted.
    pub rate_limit: crate::ratelimit::RateLimitConfig,
    /// Collapses runs of identical messages into one entry and a summary (`[ingest.dedup]`).
    pub dedup: crate::dedup::DedupConfig,
}

impl Default for IngestConfig {
    fn default() -> Self {
        Self {
            parse_structured: true,
            rules: Vec::new(),
            rate_limit: Default::default(),
            dedup: Default::default(),
        }
    }
}

/// Alerts for hosts that stop sending logs.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct SilenceConfig {
    /// Alert when any host has sent nothing for this many seconds. 0 disables the default.
    pub default_after_secs: u64,
    /// How often silence is evaluated.
    pub check_interval_secs: u64,
    /// `http://` or `https://` URL that receives a POST on each alert and recovery.
    pub webhook_url: String,
    /// Body format: `json` (default), `text`, `slack`, `discord` or `ntfy`.
    pub webhook_format: crate::webhook::WebhookFormat,
    /// Extra request headers as `"Name: value"`, for an `Authorization` token for instance.
    pub webhook_headers: Vec<String>,
    /// Per-host thresholds in seconds, overriding the default; 0 means never alert.
    pub hosts: BTreeMap<String, u64>,
}

impl Default for SilenceConfig {
    fn default() -> Self {
        Self {
            default_after_secs: 0,
            check_interval_secs: 30,
            webhook_url: String::new(),
            webhook_format: crate::webhook::WebhookFormat::Json,
            webhook_headers: Vec::new(),
            hosts: BTreeMap::new(),
        }
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            path: PathBuf::from("logpit.db"),
            retention_days: 14,
            retention_by_severity: BTreeMap::new(),
            max_db_size_mb: 0,
            batch_size: 500,
            flush_interval_ms: 500,
            queue_capacity: 10_000,
            max_message_bytes: 16 * 1024,
        }
    }
}

impl StorageConfig {
    /// Retention in days for each severity (index = severity number), 0 meaning forever.
    pub fn retention_table(&self) -> anyhow::Result<[u32; 8]> {
        let mut table = [self.retention_days; 8];
        let mut set = [false; 8];
        for (key, days) in &self.retention_by_severity {
            let sev = usize::from(crate::model::parse_severity(key).with_context(|| {
                format!(
                    "unknown severity {key:?} in retention_by_severity (use emerg … debug or 0-7)"
                )
            })?);
            if std::mem::replace(&mut set[sev], true) {
                bail!("severity {key:?} appears twice in retention_by_severity");
            }
            table[sev] = *days;
        }
        Ok(table)
    }
}

impl Default for SyslogConfig {
    fn default() -> Self {
        Self {
            udp_listen: "127.0.0.1:5514".into(),
            tcp_listen: "127.0.0.1:5514".into(),
            tls_listen: String::new(),
            tls_cert: None,
            tls_key: None,
            tls_client_ca: None,
        }
    }
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:8080".into(),
            token: None,
            tokens: Vec::new(),
            max_body_bytes: 8 * 1024 * 1024,
            audit_retention_days: 30,
        }
    }
}

/// Reads a secret from `NAME`, or from the file named by `NAME_FILE` (e.g. a mounted
/// container secret). Setting both is an error.
fn env_secret(get: &dyn Fn(&str) -> Option<String>, name: &str) -> anyhow::Result<Option<String>> {
    let file_var = format!("{name}_FILE");
    match (get(name), get(&file_var)) {
        (Some(_), Some(_)) => bail!("set only one of {name} and {file_var}"),
        (Some(t), None) => Ok(Some(t)),
        (None, Some(path)) => {
            let text = std::fs::read_to_string(&path)
                .with_context(|| format!("cannot read {file_var} {path}"))?;
            Ok(Some(text.trim_end_matches(['\r', '\n']).to_string()))
        }
        (None, None) => Ok(None),
    }
}

impl Config {
    pub fn parse(text: &str) -> anyhow::Result<Self> {
        let cfg: Config = toml::from_str(text).context("invalid configuration")?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Applies `LOGPIT_*` environment overrides (they win over the file), which is
    /// how containers are usually configured. An empty syslog address disables
    /// that listener. `LOGPIT_HTTP_TOKEN_FILE` reads the token from a file, e.g. a
    /// mounted container secret.
    pub fn apply_env(&mut self, get: &dyn Fn(&str) -> Option<String>) -> anyhow::Result<()> {
        if let Some(v) = get("LOGPIT_STORAGE_PATH") {
            self.storage.path = PathBuf::from(v);
        }
        if let Some(v) = get("LOGPIT_RETENTION_DAYS") {
            self.storage.retention_days = v
                .trim()
                .parse()
                .with_context(|| format!("invalid LOGPIT_RETENTION_DAYS {v:?}"))?;
        }
        if let Some(v) = get("LOGPIT_AUDIT_RETENTION_DAYS") {
            self.http.audit_retention_days = v
                .trim()
                .parse()
                .with_context(|| format!("invalid LOGPIT_AUDIT_RETENTION_DAYS {v:?}"))?;
        }
        if let Some(v) = get("LOGPIT_MAX_DB_SIZE_MB") {
            self.storage.max_db_size_mb = v
                .trim()
                .parse()
                .with_context(|| format!("invalid LOGPIT_MAX_DB_SIZE_MB {v:?}"))?;
        }
        if let Some(v) = get("LOGPIT_RETENTION_BY_SEVERITY") {
            for pair in v.split(',').map(str::trim).filter(|p| !p.is_empty()) {
                let (sev, days) = pair.split_once('=').with_context(|| {
                    format!("invalid LOGPIT_RETENTION_BY_SEVERITY entry {pair:?} (expected severity=days)")
                })?;
                let days = days.trim().parse().with_context(|| {
                    format!("invalid days in LOGPIT_RETENTION_BY_SEVERITY entry {pair:?}")
                })?;
                self.storage
                    .retention_by_severity
                    .insert(sev.trim().to_ascii_lowercase(), days);
            }
        }
        if let Some(v) = get("LOGPIT_SYSLOG_UDP_LISTEN") {
            self.syslog.udp_listen = v;
        }
        if let Some(v) = get("LOGPIT_SYSLOG_TCP_LISTEN") {
            self.syslog.tcp_listen = v;
        }
        if let Some(v) = get("LOGPIT_NEW_PATTERNS") {
            self.new_patterns.enabled = match v.trim().to_ascii_lowercase().as_str() {
                "1" | "true" | "yes" | "on" => true,
                "0" | "false" | "no" | "off" => false,
                _ => bail!("invalid LOGPIT_NEW_PATTERNS {v:?} (use true or false)"),
            };
        }
        if let Some(v) = get("LOGPIT_PARSE_STRUCTURED") {
            self.ingest.parse_structured = match v.trim().to_ascii_lowercase().as_str() {
                "1" | "true" | "yes" | "on" => true,
                "0" | "false" | "no" | "off" => false,
                _ => bail!("invalid LOGPIT_PARSE_STRUCTURED {v:?} (use true or false)"),
            };
        }
        for (name, slot) in [
            (
                "LOGPIT_RATE_LIMIT_PER_HOST",
                &mut self.ingest.rate_limit.per_host_per_sec,
            ),
            ("LOGPIT_RATE_LIMIT_BURST", &mut self.ingest.rate_limit.burst),
            (
                "LOGPIT_RATE_LIMIT_GLOBAL",
                &mut self.ingest.rate_limit.global_per_sec,
            ),
        ] {
            if let Some(v) = get(name) {
                *slot = v
                    .trim()
                    .parse()
                    .with_context(|| format!("invalid {name} {v:?} (a whole number, 0 = off)"))?;
            }
        }
        if let Some(v) = get("LOGPIT_GELF_UDP_LISTEN") {
            self.gelf.udp_listen = v;
        }
        if let Some(v) = get("LOGPIT_GELF_TCP_LISTEN") {
            self.gelf.tcp_listen = v;
        }
        if let Some(v) = get("LOGPIT_SYSLOG_TLS_LISTEN") {
            self.syslog.tls_listen = v;
        }
        for (name, slot) in [
            ("LOGPIT_SYSLOG_TLS_CERT", &mut self.syslog.tls_cert),
            ("LOGPIT_SYSLOG_TLS_KEY", &mut self.syslog.tls_key),
            (
                "LOGPIT_SYSLOG_TLS_CLIENT_CA",
                &mut self.syslog.tls_client_ca,
            ),
        ] {
            if let Some(v) = get(name) {
                *slot = (!v.is_empty()).then(|| PathBuf::from(v));
            }
        }
        if let Some(v) = get("LOGPIT_HTTP_LISTEN") {
            self.http.listen = v;
        }
        if let Some(v) = get("LOGPIT_SILENCE_AFTER_SECS") {
            self.silence.default_after_secs = v
                .trim()
                .parse()
                .with_context(|| format!("invalid LOGPIT_SILENCE_AFTER_SECS {v:?}"))?;
        }
        if let Some(v) = get("LOGPIT_SILENCE_WEBHOOK_URL") {
            self.silence.webhook_url = v;
        }
        if let Some(v) = get("LOGPIT_SILENCE_WEBHOOK_FORMAT") {
            self.silence.webhook_format = crate::webhook::WebhookFormat::parse(v.trim())
                .with_context(|| {
                    format!("invalid LOGPIT_SILENCE_WEBHOOK_FORMAT {v:?} (json, text, slack, discord or ntfy)")
                })?;
        }
        // One header per variable keeps secrets out of the config file; use TOML for several.
        if let Some(v) = env_secret(get, "LOGPIT_SILENCE_WEBHOOK_HEADER")? {
            self.silence.webhook_headers.push(v);
        }
        if let Some(t) = env_secret(get, "LOGPIT_HTTP_TOKEN")? {
            self.http.token = Some(t);
        }
        for (var, name, scope) in [
            ("LOGPIT_HTTP_TOKEN_READ", "env-read", Scope::Read),
            ("LOGPIT_HTTP_TOKEN_WRITE", "env-write", Scope::Write),
        ] {
            if let Some(token) = env_secret(get, var)? {
                self.http.tokens.push(TokenConfig {
                    token,
                    scopes: vec![scope],
                    name: Some(name.into()),
                    ..Default::default()
                });
            }
        }
        Ok(())
    }

    /// The name of each entry of `http.tokens`: the configured one, or `token-N` by position.
    fn token_name(index: usize, t: &TokenConfig) -> String {
        t.name
            .clone()
            .unwrap_or_else(|| format!("token-{}", index + 1))
    }

    /// All configured tokens; `http.token` is named `admin` and has every scope.
    pub fn auth(&self) -> crate::auth::Auth {
        use crate::auth::{Access, TokenEntry};
        let admin = self.http.token.iter().map(|t| TokenEntry {
            token: t.clone(),
            name: "admin".into(),
            scopes: vec![Scope::Read, Scope::Write, Scope::Admin],
            access: Access::default(),
        });
        let scoped = self
            .http
            .tokens
            .iter()
            .enumerate()
            .map(|(i, t)| TokenEntry {
                token: t.token.clone(),
                name: Self::token_name(i, t),
                scopes: t.scopes.clone(),
                access: Access {
                    hosts: t.hosts.clone(),
                    apps: t.apps.clone(),
                },
            });
        crate::auth::Auth::from_entries(admin.chain(scoped))
    }

    /// Loads `path` if given (it must exist), else `./logpit.toml` if present, else defaults.
    pub fn load(path: Option<&Path>) -> anyhow::Result<Self> {
        let (path, required) = match path {
            Some(p) => (p.to_path_buf(), true),
            None => (PathBuf::from("logpit.toml"), false),
        };
        let mut cfg = match std::fs::read_to_string(&path) {
            Ok(text) => toml::from_str::<Config>(&text)
                .with_context(|| format!("invalid configuration in {}", path.display()))?,
            Err(e) if !required && e.kind() == std::io::ErrorKind::NotFound => Config::default(),
            Err(e) => return Err(e).with_context(|| format!("cannot read {}", path.display())),
        };
        cfg.apply_env(&|k| std::env::var(k).ok())?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        let s = &self.storage;
        if s.batch_size == 0 || s.queue_capacity == 0 || s.flush_interval_ms == 0 {
            bail!("storage.batch_size, queue_capacity and flush_interval_ms must be > 0");
        }
        if s.max_message_bytes < 64 {
            bail!("storage.max_message_bytes must be >= 64");
        }
        s.retention_table()?;
        if s.max_db_size_mb != 0 && s.max_db_size_mb < 16 {
            bail!("storage.max_db_size_mb must be 0 (off) or at least 16");
        }
        if matches!(&self.http.token, Some(t) if t.is_empty()) {
            bail!("http.token must not be empty (remove it to disable auth)");
        }
        crate::rules::Rules::from_config(&self.ingest.rules)?;
        self.ingest.rate_limit.validate()?;
        crate::alerts::AlertRules::from_config(&self.alerts)?;
        self.new_patterns.validate()?;
        self.ingest.dedup.validate()?;
        crate::logmetrics::LogMetrics::from_config(&self.metrics)?;
        let sy = &self.syslog;
        if !sy.tls_listen.is_empty() && (sy.tls_cert.is_none() || sy.tls_key.is_none()) {
            bail!("syslog.tls_listen needs syslog.tls_cert and syslog.tls_key");
        }
        if sy.tls_listen.is_empty()
            && (sy.tls_cert.is_some() || sy.tls_key.is_some() || sy.tls_client_ca.is_some())
        {
            bail!(
                "syslog.tls_cert, tls_key and tls_client_ca are set but syslog.tls_listen is empty"
            );
        }
        let mut seen = std::collections::HashSet::new();
        let mut names = std::collections::HashSet::new();
        if self.http.token.is_some() {
            names.insert("admin".to_string());
        }
        for (i, t) in self.http.tokens.iter().enumerate() {
            if t.token.is_empty() {
                bail!("http.tokens entries must not have an empty token");
            }
            if t.scopes.is_empty() {
                bail!("http.tokens entries need at least one scope (read, write, admin)");
            }
            let name = Self::token_name(i, t);
            if name.is_empty()
                || name.len() > MAX_TOKEN_NAME
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
            {
                bail!(
                    "token name {name:?} must be 1 to {MAX_TOKEN_NAME} letters, digits, '_', '-' or '.'"
                );
            }
            if !names.insert(name.clone()) {
                bail!("token name {name:?} is used twice");
            }
            if !t.hosts.is_empty() || !t.apps.is_empty() {
                if !t.scopes.contains(&Scope::Read) {
                    bail!(
                        "token {name:?} restricts hosts or apps, which only limits reading: it needs the read scope"
                    );
                }
                for (what, list) in [("hosts", &t.hosts), ("apps", &t.apps)] {
                    if list.len() > MAX_ACCESS_ITEMS || list.iter().any(|v| v.is_empty()) {
                        bail!(
                            "token {name:?}: {what} takes at most {MAX_ACCESS_ITEMS} non-empty names"
                        );
                    }
                }
            }
            if !seen.insert(t.token.as_str()) || self.http.token.as_deref() == Some(&t.token) {
                bail!("the same token is configured twice; give each token one entry");
            }
        }
        let si = &self.silence;
        if si.check_interval_secs == 0 {
            bail!("silence.check_interval_secs must be > 0");
        }
        if si.hosts.keys().any(|h| h.is_empty()) {
            bail!("silence.hosts keys must not be empty");
        }
        if !si.webhook_url.is_empty() {
            crate::webhook::Webhook::new(&si.webhook_url, si.webhook_format, &si.webhook_headers)?;
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

    fn env<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |k| {
            pairs
                .iter()
                .find(|(n, _)| *n == k)
                .map(|(_, v)| v.to_string())
        }
    }

    #[test]
    fn env_overrides_file_values() {
        let mut cfg =
            Config::parse("[http]\nlisten = \"127.0.0.1:1\"\ntoken = \"from-file\"").unwrap();
        cfg.apply_env(&env(&[
            ("LOGPIT_HTTP_LISTEN", "0.0.0.0:8080"),
            ("LOGPIT_HTTP_TOKEN", "from-env"),
            ("LOGPIT_RETENTION_DAYS", "30"),
            ("LOGPIT_SYSLOG_TCP_LISTEN", ""),
            ("LOGPIT_STORAGE_PATH", "/data/x.db"),
        ]))
        .unwrap();
        assert_eq!(cfg.http.listen, "0.0.0.0:8080");
        assert_eq!(cfg.http.token.as_deref(), Some("from-env"));
        assert_eq!(cfg.storage.retention_days, 30);
        assert_eq!(cfg.syslog.tcp_listen, "");
        assert_eq!(cfg.storage.path, PathBuf::from("/data/x.db"));
        cfg.validate().unwrap();
    }

    #[test]
    fn token_file_is_read_and_trimmed() {
        let path = std::env::temp_dir().join(format!("logpit-token-{}", std::process::id()));
        std::fs::write(&path, "s3cret\n").unwrap();
        let p = path.to_string_lossy().to_string();
        let mut cfg = Config::default();
        cfg.apply_env(&env(&[("LOGPIT_HTTP_TOKEN_FILE", &p)]))
            .unwrap();
        assert_eq!(cfg.http.token.as_deref(), Some("s3cret"));
        std::fs::remove_file(&path).ok();

        let mut cfg = Config::default();
        assert!(
            cfg.apply_env(&env(&[("LOGPIT_HTTP_TOKEN_FILE", "/nonexistent/x")]))
                .is_err()
        );
        assert!(
            cfg.apply_env(&env(&[
                ("LOGPIT_HTTP_TOKEN", "a"),
                ("LOGPIT_HTTP_TOKEN_FILE", "b")
            ]))
            .is_err()
        );
        assert!(
            cfg.apply_env(&env(&[("LOGPIT_RETENTION_DAYS", "abc")]))
                .is_err()
        );
    }

    #[test]
    fn silence_config_parses_and_validates() {
        let cfg = Config::parse(
            "[silence]\ndefault_after_secs = 600\nwebhook_url = \"http://ntfy:80/x\"\n\
             [silence.hosts]\nnas = 3600\nprinter = 0",
        )
        .unwrap();
        assert_eq!(cfg.silence.hosts["nas"], 3600);
        assert!(Config::parse("[silence]\nwebhook_url = \"https://hooks.example.com/x\"").is_ok());
        assert!(Config::parse("[silence]\nwebhook_url = \"ftp://x\"").is_err());
        assert!(Config::parse("[silence]\ncheck_interval_secs = 0").is_err());
        assert!(Config::parse("[silence]\nbogus = 1").is_err());

        let mut cfg = Config::default();
        cfg.apply_env(&env(&[
            ("LOGPIT_SILENCE_AFTER_SECS", "300"),
            ("LOGPIT_SILENCE_WEBHOOK_URL", "http://relay/hook"),
        ]))
        .unwrap();
        assert_eq!(cfg.silence.default_after_secs, 300);
        cfg.validate().unwrap();
        assert!(
            cfg.apply_env(&env(&[("LOGPIT_SILENCE_AFTER_SECS", "x")]))
                .is_err()
        );
    }

    #[test]
    fn audit_retention_defaults_and_env() {
        let mut cfg = Config::parse("").unwrap();
        assert_eq!(cfg.http.audit_retention_days, 30);
        cfg.apply_env(&env(&[("LOGPIT_AUDIT_RETENTION_DAYS", "0")]))
            .unwrap();
        assert_eq!(cfg.http.audit_retention_days, 0);
        assert!(
            cfg.apply_env(&env(&[("LOGPIT_AUDIT_RETENTION_DAYS", "x")]))
                .is_err()
        );
        let from_file = Config::parse("[http]\naudit_retention_days = 7").unwrap();
        assert_eq!(from_file.http.audit_retention_days, 7);
    }

    #[test]
    fn named_restricted_tokens() {
        use crate::auth::Scope::*;
        let cfg = Config::parse(
            "[http]\ntoken = \"root\"\n\
             [[http.tokens]]\ntoken = \"w\"\nname = \"web-team\"\nscopes = [\"read\"]\nhosts = [\"web1\", \"web2\"]\napps = [\"nginx\"]\n\
             [[http.tokens]]\ntoken = \"s\"\nscopes = [\"write\"]\n\
             [[http.tokens]]\ntoken = \"o\"\nname = \"ops.1\"\nscopes = [\"read\", \"admin\"]",
        )
        .unwrap();
        let a = cfg.auth();
        let root = a.identify(Some("root"), Admin).unwrap();
        assert_eq!(root.name, "admin");
        assert!(root.access.unrestricted());
        let web = a.identify(Some("w"), Read).unwrap();
        assert_eq!(web.name, "web-team");
        assert_eq!(web.access.hosts, ["web1", "web2"]);
        assert_eq!(web.access.apps, ["nginx"]);
        assert!(a.identify(Some("w"), Admin).is_err());
        // Unnamed tokens are numbered by their place in the list.
        assert_eq!(a.identify(Some("s"), Write).unwrap().name, "token-2");
        assert_eq!(a.identify(Some("o"), Admin).unwrap().name, "ops.1");

        let bad =
            |body: &str| Config::parse(&format!("[[http.tokens]]\ntoken = \"a\"\n{body}")).is_err();
        assert!(bad("scopes = [\"read\"]\nname = \"has space\""));
        assert!(bad("scopes = [\"read\"]\nname = \"\""));
        assert!(bad("scopes = [\"write\"]\nhosts = [\"h\"]"));
        assert!(bad("scopes = [\"read\"]\nhosts = [\"\"]"));
        assert!(!bad("scopes = [\"read\"]\nhosts = [\"h\"]"));
        // Names are unique, the default ones and `admin` included.
        assert!(
            Config::parse(
                "[[http.tokens]]\ntoken = \"a\"\nname = \"x\"\nscopes = [\"read\"]\n\
             [[http.tokens]]\ntoken = \"b\"\nname = \"x\"\nscopes = [\"read\"]"
            )
            .is_err()
        );
        assert!(
            Config::parse(
                "[[http.tokens]]\ntoken = \"a\"\nname = \"token-2\"\nscopes = [\"read\"]\n\
             [[http.tokens]]\ntoken = \"b\"\nscopes = [\"read\"]"
            )
            .is_err()
        );
        assert!(Config::parse(
            "[http]\ntoken = \"r\"\n[[http.tokens]]\ntoken = \"a\"\nname = \"admin\"\nscopes = [\"read\"]"
        )
        .is_err());
    }

    #[test]
    fn scoped_tokens_from_file_and_env() {
        let mut cfg = Config::parse(
            "[http]\ntoken = \"admin\"\n[[http.tokens]]\ntoken = \"ship\"\nscopes = [\"write\"]",
        )
        .unwrap();
        cfg.apply_env(&env(&[("LOGPIT_HTTP_TOKEN_READ", "view")]))
            .unwrap();
        cfg.validate().unwrap();
        let a = cfg.auth();
        use crate::auth::Decision::*;
        assert_eq!(a.check(Some("admin"), Scope::Read), Allowed);
        assert_eq!(a.check(Some("ship"), Scope::Write), Allowed);
        assert_eq!(a.check(Some("ship"), Scope::Read), Forbidden);
        assert_eq!(a.check(Some("view"), Scope::Read), Allowed);
        assert_eq!(a.check(Some("view"), Scope::Write), Forbidden);

        // Only scoped tokens still turn authentication on.
        let mut only = Config::default();
        only.apply_env(&env(&[("LOGPIT_HTTP_TOKEN_WRITE", "w")]))
            .unwrap();
        assert_eq!(only.auth().check(None, Scope::Read), Unauthorized);

        assert!(Config::parse("[[http.tokens]]\ntoken = \"a\"\nscopes = []").is_err());
        assert!(Config::parse("[[http.tokens]]\ntoken = \"\"\nscopes = [\"read\"]").is_err());
        assert!(Config::parse("[[http.tokens]]\ntoken = \"a\"\nscopes = [\"root\"]").is_err());
        assert!(
            Config::parse(
                "[http]\ntoken = \"a\"\n[[http.tokens]]\ntoken = \"a\"\nscopes = [\"read\"]"
            )
            .is_err()
        );
        let mut both = Config::default();
        assert!(
            both.apply_env(&env(&[
                ("LOGPIT_HTTP_TOKEN_READ", "a"),
                ("LOGPIT_HTTP_TOKEN_READ_FILE", "b")
            ]))
            .is_err()
        );
    }

    #[test]
    fn retention_by_severity() {
        let cfg = Config::parse(
            "[storage]\nretention_days = 14\n[storage.retention_by_severity]\ndebug = 2\nerr = 90\ncrit = 0",
        )
        .unwrap();
        assert_eq!(
            cfg.storage.retention_table().unwrap(),
            [14, 14, 0, 90, 14, 14, 14, 2]
        );

        let mut cfg = Config::default();
        cfg.apply_env(&env(&[(
            "LOGPIT_RETENTION_BY_SEVERITY",
            "Debug=1, info=7,6=3",
        )]))
        .unwrap();
        // "info" and "6" name the same severity: rejected rather than silently picking one.
        assert!(cfg.validate().is_err());

        let mut cfg = Config::default();
        cfg.apply_env(&env(&[("LOGPIT_RETENTION_BY_SEVERITY", "debug=1, info=7")]))
            .unwrap();
        cfg.validate().unwrap();
        assert_eq!(
            cfg.storage.retention_table().unwrap(),
            [14, 14, 14, 14, 14, 14, 7, 1]
        );

        assert!(Config::parse("[storage.retention_by_severity]\nloud = 1").is_err());
        let mut bad = Config::default();
        assert!(
            bad.apply_env(&env(&[("LOGPIT_RETENTION_BY_SEVERITY", "debug")]))
                .is_err()
        );
        assert!(
            bad.apply_env(&env(&[("LOGPIT_RETENTION_BY_SEVERITY", "debug=x")]))
                .is_err()
        );
    }

    #[test]
    fn max_db_size_config() {
        assert_eq!(Config::parse("").unwrap().storage.max_db_size_mb, 0);
        assert_eq!(
            Config::parse("[storage]\nmax_db_size_mb = 500")
                .unwrap()
                .storage
                .max_db_size_mb,
            500
        );
        assert!(Config::parse("[storage]\nmax_db_size_mb = 4").is_err());
        let mut cfg = Config::default();
        cfg.apply_env(&env(&[("LOGPIT_MAX_DB_SIZE_MB", "2048")]))
            .unwrap();
        assert_eq!(cfg.storage.max_db_size_mb, 2048);
        assert!(
            cfg.apply_env(&env(&[("LOGPIT_MAX_DB_SIZE_MB", "big")]))
                .is_err()
        );
    }

    #[test]
    fn webhook_format_and_headers_config() {
        let cfg = Config::parse(
            "[silence]\nwebhook_url = \"https://ntfy.example.com/logpit\"\nwebhook_format = \"ntfy\"\n\
             webhook_headers = [\"Authorization: Bearer tk_123\"]",
        )
        .unwrap();
        assert_eq!(
            cfg.silence.webhook_format,
            crate::webhook::WebhookFormat::Ntfy
        );
        assert_eq!(cfg.silence.webhook_headers.len(), 1);
        assert_eq!(
            Config::parse("").unwrap().silence.webhook_format,
            crate::webhook::WebhookFormat::Json
        );
        for bad in [
            "webhook_format = \"xml\"",
            "webhook_headers = [\"no colon\"]",
            "webhook_headers = [\"Host: evil\"]",
            "webhook_headers = [\"X-A: a\\r\\nInjected: 1\"]",
        ] {
            let text = format!("[silence]\nwebhook_url = \"https://x.example/h\"\n{bad}");
            assert!(Config::parse(&text).is_err(), "{bad}");
        }
        let mut cfg = Config::default();
        cfg.apply_env(&env(&[
            ("LOGPIT_SILENCE_WEBHOOK_URL", "https://hooks.example.com/x"),
            ("LOGPIT_SILENCE_WEBHOOK_FORMAT", "discord"),
            ("LOGPIT_SILENCE_WEBHOOK_HEADER", "X-Token: abc"),
        ]))
        .unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.silence.webhook_headers, ["X-Token: abc"]);
        assert!(
            cfg.apply_env(&env(&[("LOGPIT_SILENCE_WEBHOOK_FORMAT", "xml")]))
                .is_err()
        );
    }

    #[test]
    fn gelf_config() {
        let cfg =
            Config::parse("[gelf]\nudp_listen = \"0.0.0.0:12201\"\ntcp_listen = \"0.0.0.0:12202\"")
                .unwrap();
        assert_eq!(
            (cfg.gelf.udp_listen.as_str(), cfg.gelf.tcp_listen.as_str()),
            ("0.0.0.0:12201", "0.0.0.0:12202")
        );
        let off = Config::parse("").unwrap();
        assert!(
            off.gelf.udp_listen.is_empty() && off.gelf.tcp_listen.is_empty(),
            "off by default"
        );
        assert!(Config::parse("[gelf]\nbogus = 1").is_err());
        let mut cfg = Config::default();
        cfg.apply_env(&env(&[("LOGPIT_GELF_UDP_LISTEN", "127.0.0.1:12201")]))
            .unwrap();
        assert_eq!(cfg.gelf.udp_listen, "127.0.0.1:12201");
    }

    #[test]
    fn rate_limit_config() {
        let cfg = Config::parse(
            "[ingest.rate_limit]\nper_host_per_sec = 200\nburst = 1000\nglobal_per_sec = 5000",
        )
        .unwrap();
        assert_eq!(
            (
                cfg.ingest.rate_limit.per_host_per_sec,
                cfg.ingest.rate_limit.burst,
                cfg.ingest.rate_limit.global_per_sec
            ),
            (200, 1000, 5000)
        );
        assert_eq!(
            Config::parse("").unwrap().ingest.rate_limit,
            Default::default(),
            "off by default"
        );
        assert!(Config::parse("[ingest.rate_limit]\nburst = 10").is_err());
        assert!(Config::parse("[ingest.rate_limit]\nbogus = 1").is_err());
        let mut cfg = Config::default();
        cfg.apply_env(&env(&[
            ("LOGPIT_RATE_LIMIT_PER_HOST", "50"),
            ("LOGPIT_RATE_LIMIT_GLOBAL", "1000"),
        ]))
        .unwrap();
        cfg.validate().unwrap();
        assert_eq!(
            (
                cfg.ingest.rate_limit.per_host_per_sec,
                cfg.ingest.rate_limit.global_per_sec
            ),
            (50, 1000)
        );
        assert!(
            cfg.apply_env(&env(&[("LOGPIT_RATE_LIMIT_PER_HOST", "fast")]))
                .is_err()
        );
    }

    #[test]
    fn dedup_config() {
        let cfg = Config::parse("").unwrap();
        assert!(!cfg.ingest.dedup.enabled);
        assert_eq!(cfg.ingest.dedup.window_secs, 30);
        let cfg = Config::parse("[ingest.dedup]\nenabled = true\nwindow_secs = 5\nmax_keys = 100")
            .unwrap();
        assert!(cfg.ingest.dedup.enabled && cfg.ingest.dedup.max_keys == 100);
        assert!(Config::parse("[ingest.dedup]\nwindow_secs = 0").is_err());
        assert!(Config::parse("[ingest.dedup]\nmax_keys = 0").is_err());
        assert!(Config::parse("[ingest.dedup]\nbogus = 1").is_err());
    }

    #[test]
    fn metrics_config() {
        assert!(Config::parse("").unwrap().metrics.is_empty());
        let cfg = Config::parse(
            "[[metrics]]\nname = \"ssh_failures\"\npattern = \"Failed\"\nlabels = [\"host\"]\n\
             [[metrics]]\nname = \"bytes\"\nvalue_field = \"bytes\"\nmax_series = 50",
        )
        .unwrap();
        assert_eq!(cfg.metrics.len(), 2);
        assert!(Config::parse("[[metrics]]\nname = \"Bad\"").is_err());
        assert!(Config::parse("[[metrics]]\nname = \"a\"\nbogus = 1").is_err());
        assert!(Config::parse("[[metrics]]\npattern = \"x\"").is_err());
        assert!(Config::parse("[[metrics]]\nname = \"a\"\npattern = \"(\"").is_err());
    }

    #[test]
    fn new_patterns_config() {
        let cfg = Config::parse("").unwrap();
        assert!(!cfg.new_patterns.enabled);
        assert_eq!(cfg.new_patterns.learn_secs, 600);
        let cfg = Config::parse(
            "[new_patterns]\nenabled = true\nlearn_secs = 30\nseverity = [\"err\", 2]\n\
             ignore = [\"healthcheck\"]\nmax_per_minute = 3\nsurge_factor = 8\nsurge_min = 50",
        )
        .unwrap();
        assert!(cfg.new_patterns.enabled && cfg.new_patterns.surge_factor == 8.0);
        assert!(Config::parse("[new_patterns]\nbogus = 1").is_err());
        assert!(Config::parse("[new_patterns]\nignore = [\"(\"]").is_err());
        assert!(Config::parse("[new_patterns]\nsurge_factor = 0.5").is_err());
        let mut cfg = Config::default();
        cfg.apply_env(&env(&[("LOGPIT_NEW_PATTERNS", "on")]))
            .unwrap();
        assert!(cfg.new_patterns.enabled);
        cfg.apply_env(&env(&[("LOGPIT_NEW_PATTERNS", "0")]))
            .unwrap();
        assert!(!cfg.new_patterns.enabled);
        assert!(
            cfg.apply_env(&env(&[("LOGPIT_NEW_PATTERNS", "maybe")]))
                .is_err()
        );
    }

    #[test]
    fn alerts_config() {
        let cfg = Config::parse(
            "[[alerts]]\nname = \"disk\"\npattern = \"disk\"\nseverity = [\"err\"]\ncount = 5\nwindow_secs = 600\nper_host = true\n\
             [[alerts]]\ncount = 1000\nwindow_secs = 60",
        )
        .unwrap();
        assert_eq!(cfg.alerts.len(), 2);
        assert!(cfg.alerts[0].per_host && cfg.alerts[1].name.is_none());
        assert!(Config::parse("").unwrap().alerts.is_empty());
        // Missing required keys, invalid values and unknown keys are rejected at load time.
        assert!(Config::parse("[[alerts]]\ncount = 5").is_err());
        assert!(Config::parse("[[alerts]]\nwindow_secs = 5").is_err());
        assert!(Config::parse("[[alerts]]\ncount = 0\nwindow_secs = 5").is_err());
        assert!(Config::parse("[[alerts]]\ncount = 1\nwindow_secs = 5\npattern = \"(\"").is_err());
        assert!(Config::parse("[[alerts]]\ncount = 1\nwindow_secs = 5\nbogus = 1").is_err());
    }

    #[test]
    fn ingest_rules_config() {
        let cfg = Config::parse(
            "[[ingest.rules]]\nname = \"noise\"\naction = \"drop\"\napp = \"cron\"\nseverity = [\"info\", 7]\n\
             [[ingest.rules]]\naction = \"mask\"\npattern = \"token=\\\\S+\"\nreplace = \"token=***\"",
        )
        .unwrap();
        assert_eq!(cfg.ingest.rules.len(), 2);
        assert!(Config::parse("").unwrap().ingest.rules.is_empty());
        // Mistakes are caught when the configuration is loaded, not when the first entry arrives.
        assert!(Config::parse("[[ingest.rules]]\naction = \"drop\"").is_err());
        assert!(Config::parse("[[ingest.rules]]\naction = \"mask\"\npattern = \"(\"").is_err());
        assert!(Config::parse("[[ingest.rules]]\naction = \"zap\"\nhost = \"h\"").is_err());
        assert!(
            Config::parse("[[ingest.rules]]\naction = \"drop\"\nhost = \"h\"\nbogus = 1").is_err()
        );
    }

    #[test]
    fn structured_parsing_config() {
        assert!(
            Config::parse("").unwrap().ingest.parse_structured,
            "on by default"
        );
        assert!(
            !Config::parse("[ingest]\nparse_structured = false")
                .unwrap()
                .ingest
                .parse_structured
        );
        assert!(Config::parse("[ingest]\nbogus = 1").is_err());
        let mut cfg = Config::default();
        cfg.apply_env(&env(&[("LOGPIT_PARSE_STRUCTURED", "off")]))
            .unwrap();
        assert!(!cfg.ingest.parse_structured);
        cfg.apply_env(&env(&[("LOGPIT_PARSE_STRUCTURED", "1")]))
            .unwrap();
        assert!(cfg.ingest.parse_structured);
        assert!(
            cfg.apply_env(&env(&[("LOGPIT_PARSE_STRUCTURED", "maybe")]))
                .is_err()
        );
    }

    #[test]
    fn syslog_tls_config() {
        let ok = Config::parse(
            "[syslog]\ntls_listen = \"0.0.0.0:6514\"\ntls_cert = \"/c.pem\"\ntls_key = \"/k.pem\"\ntls_client_ca = \"/ca.pem\"",
        )
        .unwrap();
        assert_eq!(ok.syslog.tls_client_ca, Some(PathBuf::from("/ca.pem")));
        assert_eq!(Config::parse("").unwrap().syslog.tls_listen, "");
        // A listener without a certificate, or a certificate without a listener, is a mistake.
        assert!(Config::parse("[syslog]\ntls_listen = \"0.0.0.0:6514\"").is_err());
        assert!(
            Config::parse("[syslog]\ntls_listen = \"0.0.0.0:6514\"\ntls_cert = \"/c.pem\"")
                .is_err()
        );
        assert!(Config::parse("[syslog]\ntls_cert = \"/c.pem\"").is_err());

        let mut cfg = Config::default();
        cfg.apply_env(&env(&[
            ("LOGPIT_SYSLOG_TLS_LISTEN", "0.0.0.0:6514"),
            ("LOGPIT_SYSLOG_TLS_CERT", "/run/secrets/cert.pem"),
            ("LOGPIT_SYSLOG_TLS_KEY", "/run/secrets/key.pem"),
        ]))
        .unwrap();
        cfg.validate().unwrap();
        assert_eq!(
            cfg.syslog.tls_key,
            Some(PathBuf::from("/run/secrets/key.pem"))
        );
        // An empty value clears a path set in the file.
        cfg.apply_env(&env(&[("LOGPIT_SYSLOG_TLS_KEY", "")]))
            .unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn partial_override_keeps_other_defaults() {
        let cfg = Config::parse("[syslog]\nudp_listen = \"0.0.0.0:514\"").unwrap();
        assert_eq!(cfg.syslog.udp_listen, "0.0.0.0:514");
        assert_eq!(cfg.syslog.tcp_listen, "127.0.0.1:5514");
    }
}
