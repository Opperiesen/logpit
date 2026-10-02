//! Bearer-token authentication with scopes: `write` (ingestion) and `read` (search, tail).

use serde::Deserialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    /// `POST /ingest`.
    Write,
    /// `GET /api/logs` and `GET /api/tail`.
    Read,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    Allowed,
    /// Missing or unknown token.
    Unauthorized,
    /// Known token that lacks the required scope.
    Forbidden,
}

/// The configured tokens. With none configured, authentication is off.
#[derive(Debug, Clone, Default)]
pub struct Auth {
    tokens: Vec<(Vec<u8>, Vec<Scope>)>,
}

/// Constant-time comparison to avoid leaking token prefixes through timing.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

impl Auth {
    pub fn new(tokens: impl IntoIterator<Item = (String, Vec<Scope>)>) -> Self {
        Self {
            tokens: tokens
                .into_iter()
                .map(|(t, s)| (t.into_bytes(), s))
                .collect(),
        }
    }

    pub fn enabled(&self) -> bool {
        !self.tokens.is_empty()
    }

    /// Checks `presented` (the bearer token, if any) against the required scope.
    /// Every configured token is compared, so timing does not reveal which one matched.
    pub fn check(&self, presented: Option<&str>, required: Scope) -> Decision {
        if !self.enabled() {
            return Decision::Allowed;
        }
        let Some(presented) = presented else {
            return Decision::Unauthorized;
        };
        let (mut known, mut allowed) = (false, false);
        for (token, scopes) in &self.tokens {
            if ct_eq(presented.as_bytes(), token) {
                known = true;
                allowed |= scopes.contains(&required);
            }
        }
        match (known, allowed) {
            (_, true) => Decision::Allowed,
            (true, false) => Decision::Forbidden,
            (false, _) => Decision::Unauthorized,
        }
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
        assert_eq!(a.check(Some("admin"), Scope::Read), Decision::Allowed);
        assert_eq!(a.check(Some("admin"), Scope::Write), Decision::Allowed);
        assert_eq!(a.check(Some("shipper"), Scope::Write), Decision::Allowed);
        assert_eq!(a.check(Some("shipper"), Scope::Read), Decision::Forbidden);
        assert_eq!(a.check(Some("viewer"), Scope::Read), Decision::Allowed);
        assert_eq!(a.check(Some("viewer"), Scope::Write), Decision::Forbidden);
    }

    #[test]
    fn unknown_or_missing_tokens_are_unauthorized() {
        let a = auth();
        assert_eq!(a.check(Some("nope"), Scope::Read), Decision::Unauthorized);
        assert_eq!(a.check(Some(""), Scope::Read), Decision::Unauthorized);
        assert_eq!(a.check(None, Scope::Write), Decision::Unauthorized);
    }

    #[test]
    fn no_tokens_means_open() {
        let a = Auth::default();
        assert!(!a.enabled());
        assert_eq!(a.check(None, Scope::Write), Decision::Allowed);
    }

    #[test]
    fn constant_time_compare() {
        assert!(ct_eq(b"secret", b"secret"));
        assert!(!ct_eq(b"secret", b"secreT"));
        assert!(!ct_eq(b"secret", b"secre"));
    }
}
