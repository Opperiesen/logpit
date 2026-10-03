//! Bearer-token authentication with scopes (`write` for ingestion, `read` for search and tail,
//! `admin` for the audit trail and token list), token names and per-token read restrictions.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    /// `POST /ingest` and the other ingestion endpoints.
    Write,
    /// `GET /api/logs`, `GET /api/tail` and the other read endpoints.
    Read,
    /// `GET /api/audit` and `GET /api/tokens`.
    Admin,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    /// Missing or unknown token.
    Unauthorized,
    /// Known token that lacks the required scope.
    Forbidden,
}

/// Which entries a token may read: the hosts and apps it is limited to, as exact names or
/// patterns with `*` and `?`. An empty list means no limit on that dimension, so the default value
/// restricts nothing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Access {
    pub hosts: Vec<String>,
    pub apps: Vec<String>,
}

impl Access {
    pub fn unrestricted(&self) -> bool {
        self.hosts.is_empty() && self.apps.is_empty()
    }

    pub fn allows(&self, host: &str, app: &str) -> bool {
        (self.hosts.is_empty() || self.hosts.iter().any(|h| crate::tags::glob_match(h, host)))
            && (self.apps.is_empty() || self.apps.iter().any(|a| crate::tags::glob_match(a, app)))
    }
}

/// Who is calling: the token's name and what it may read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub name: String,
    pub access: Access,
    /// What the token may ingest.
    pub limits: crate::quota::Limits,
}

impl Identity {
    /// The caller when authentication is off.
    pub fn anonymous() -> Self {
        Self {
            name: "anonymous".into(),
            access: Access::default(),
            limits: Default::default(),
        }
    }
}

/// One configured token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenEntry {
    pub token: String,
    pub name: String,
    pub scopes: Vec<Scope>,
    pub access: Access,
    pub limits: crate::quota::Limits,
}

/// The configured tokens. With none configured, authentication is off.
#[derive(Debug, Clone, Default)]
pub struct Auth {
    tokens: Vec<(Vec<u8>, TokenEntry)>,
}

/// Constant-time comparison to avoid leaking token prefixes through timing.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

impl Auth {
    /// Tokens without names or restrictions; they are named `token-1`, `token-2`…
    pub fn new(tokens: impl IntoIterator<Item = (String, Vec<Scope>)>) -> Self {
        Self::from_entries(
            tokens
                .into_iter()
                .enumerate()
                .map(|(i, (token, scopes))| TokenEntry {
                    token,
                    name: format!("token-{}", i + 1),
                    scopes,
                    access: Access::default(),
                    limits: Default::default(),
                }),
        )
    }

    pub fn from_entries(entries: impl IntoIterator<Item = TokenEntry>) -> Self {
        Self {
            tokens: entries
                .into_iter()
                .map(|e| (e.token.clone().into_bytes(), e))
                .collect(),
        }
    }

    pub fn enabled(&self) -> bool {
        !self.tokens.is_empty()
    }

    /// The configured tokens without their secrets, for `/api/tokens`.
    pub fn entries(&self) -> impl Iterator<Item = &TokenEntry> {
        self.tokens.iter().map(|(_, e)| e)
    }

    /// Checks `presented` (the bearer token, if any) against the required scope and says who the
    /// caller is. Every configured token is compared, so timing does not reveal which one matched.
    /// `Err` carries the refusal; for a known token that lacks the scope the name is still
    /// available through [`name_of`](Self::name_of).
    pub fn identify(&self, presented: Option<&str>, required: Scope) -> Result<Identity, Decision> {
        if !self.enabled() {
            return Ok(Identity::anonymous());
        }
        let Some(presented) = presented else {
            return Err(Decision::Unauthorized);
        };
        let (mut known, mut found) = (false, None);
        for (token, entry) in &self.tokens {
            if ct_eq(presented.as_bytes(), token) {
                known = true;
                if entry.scopes.contains(&required) {
                    found = Some(Identity {
                        name: entry.name.clone(),
                        access: entry.access.clone(),
                        limits: entry.limits,
                    });
                }
            }
        }
        match (known, found) {
            (_, Some(id)) => Ok(id),
            (true, None) => Err(Decision::Forbidden),
            (false, _) => Err(Decision::Unauthorized),
        }
    }

    /// The name of the token presented, whatever its scopes (for the audit trail).
    pub fn name_of(&self, presented: Option<&str>) -> Option<&str> {
        let presented = presented?;
        let mut name = None;
        for (token, entry) in &self.tokens {
            if ct_eq(presented.as_bytes(), token) {
                name = Some(entry.name.as_str());
            }
        }
        name
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auth() -> Auth {
        Auth::new([
            ("admin".to_string(), vec![Scope::Read, Scope::Write]),
            ("shipper".to_string(), vec![Scope::Write]),
            ("viewer".to_string(), vec![Scope::Read]),
        ])
    }

    #[test]
    fn scopes_are_enforced() {
        let a = auth();
        assert_eq!(a.identify(Some("admin"), Scope::Read).err(), None);
        assert_eq!(a.identify(Some("admin"), Scope::Write).err(), None);
        assert_eq!(a.identify(Some("shipper"), Scope::Write).err(), None);
        assert_eq!(
            a.identify(Some("shipper"), Scope::Read).err(),
            Some(Decision::Forbidden)
        );
        assert_eq!(a.identify(Some("viewer"), Scope::Read).err(), None);
        assert_eq!(
            a.identify(Some("viewer"), Scope::Write).err(),
            Some(Decision::Forbidden)
        );
    }

    #[test]
    fn unknown_or_missing_tokens_are_unauthorized() {
        let a = auth();
        assert_eq!(
            a.identify(Some("nope"), Scope::Read).err(),
            Some(Decision::Unauthorized)
        );
        assert_eq!(
            a.identify(Some(""), Scope::Read).err(),
            Some(Decision::Unauthorized)
        );
        assert_eq!(
            a.identify(None, Scope::Write).err(),
            Some(Decision::Unauthorized)
        );
    }

    #[test]
    fn no_tokens_means_open() {
        let a = Auth::default();
        assert!(!a.enabled());
        assert_eq!(a.identify(None, Scope::Write).err(), None);
    }

    #[test]
    fn constant_time_compare() {
        assert!(ct_eq(b"secret", b"secret"));
        assert!(!ct_eq(b"secret", b"secreT"));
        assert!(!ct_eq(b"secret", b"secre"));
    }

    #[test]
    fn identity_carries_name_and_access() {
        let a = Auth::from_entries([
            TokenEntry {
                token: "t-ops".into(),
                name: "ops".into(),
                scopes: vec![Scope::Read, Scope::Admin],
                access: Access::default(),
                limits: Default::default(),
            },
            TokenEntry {
                token: "t-web".into(),
                name: "web-team".into(),
                scopes: vec![Scope::Read],
                access: Access {
                    hosts: vec!["web1".into(), "web2".into()],
                    apps: vec![],
                },
                limits: Default::default(),
            },
        ]);
        let ops = a.identify(Some("t-ops"), Scope::Read).unwrap();
        assert_eq!(ops.name, "ops");
        assert!(ops.access.unrestricted());
        let web = a.identify(Some("t-web"), Scope::Read).unwrap();
        assert_eq!(web.name, "web-team");
        assert!(web.access.allows("web1", "nginx"));
        assert!(!web.access.allows("db1", "nginx"));
        assert_eq!(
            a.identify(Some("t-web"), Scope::Admin),
            Err(Decision::Forbidden)
        );
        assert_eq!(
            a.identify(Some("x"), Scope::Read),
            Err(Decision::Unauthorized)
        );
        assert_eq!(a.name_of(Some("t-web")), Some("web-team"));
        assert_eq!(a.name_of(Some("x")), None);
        assert_eq!(a.name_of(None), None);
        assert_eq!(
            Auth::default().identify(None, Scope::Admin),
            Ok(Identity::anonymous())
        );
    }

    #[test]
    fn apps_take_patterns_like_hosts() {
        let a = Access {
            hosts: vec![],
            apps: vec!["nginx*".into(), "cron".into()],
        };
        assert!(a.allows("h", "nginx") && a.allows("h", "nginx-proxy") && a.allows("h", "cron"));
        assert!(!a.allows("h", "cronjob") && !a.allows("h", "my-nginx"));
    }

    #[test]
    fn access_limits_hosts_and_apps_together() {
        let a = Access {
            hosts: vec!["h1".into()],
            apps: vec!["a1".into(), "a2".into()],
        };
        assert!(a.allows("h1", "a2"));
        assert!(!a.allows("h1", "a3"));
        assert!(!a.allows("h2", "a1"));
        let only_apps = Access {
            hosts: vec![],
            apps: vec!["a1".into()],
        };
        assert!(only_apps.allows("anything", "a1"));
        assert!(!only_apps.allows("anything", "b"));
        assert!(Access::default().allows("x", "y"));
    }
}
