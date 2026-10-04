//! Domain discovery with interchangeable certificate transparency backends.

use std::net::IpAddr;
use std::time::Duration;

use anyhow::Result;
use jiff::Timestamp;
use serde::Serialize;

pub mod backend;
pub mod crtsh;

pub use backend::CertificateTransparencyBackend;
pub use crtsh::{CrtSh, discover_from_json};

/// A unique certificate identity. Wildcard identities remain separate from hosts.
#[derive(Debug, Serialize)]
pub struct DiscoveredDomain {
    pub domain: String,
    /// An HTTPS candidate or wildcard pattern; reachability is not checked.
    pub url: String,
    pub wildcard: bool,
    /// Earliest certificate validity start observed in the returned records.
    pub first_issued: Timestamp,
    /// Latest certificate validity start observed in the returned records.
    pub last_issued: Timestamp,
}

/// Normalize a query to an ASCII DNS domain, accepting a leading `*.`.
pub fn parse_domain(input: &str) -> std::result::Result<String, String> {
    let input = input.trim();
    let input = input.strip_prefix("*.").unwrap_or(input);
    normalize_name(input)
        .filter(|name| !name.starts_with("*."))
        .ok_or_else(|| {
            "expected a DNS domain such as example.com (no scheme, path, or port)".into()
        })
}

fn normalize_name(input: &str) -> Option<String> {
    let input = input.trim();
    let (wildcard, host) = match input.strip_prefix("*.") {
        Some(host) => (true, host),
        None => (false, input),
    };
    let host = idna::domain_to_ascii(host).ok()?.to_ascii_lowercase();
    let host = host.strip_suffix('.').unwrap_or(&host);
    if host.len() > 253 || !host.contains('.') || host.parse::<IpAddr>().is_ok() {
        return None;
    }
    if !host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    }) {
        return None;
    }
    Some(if wildcard {
        format!("*.{host}")
    } else {
        host.to_owned()
    })
}

fn in_scope(name: &str, domain: &str) -> bool {
    let host = name.strip_prefix("*.").unwrap_or(name);
    host == domain
        || host
            .strip_suffix(domain)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

/// Discover identities using the default certificate transparency backend.
///
/// The current default is [`CrtSh`]. Use [`discover_with_backend`] to supply
/// another implementation.
pub fn discover(domain: &str, timeout: Duration) -> Result<Vec<DiscoveredDomain>> {
    discover_with_backend(&CrtSh, domain, timeout)
}

/// Discover identities using a supplied certificate transparency backend.
///
/// Validates and normalizes the domain before calling the backend. The same
/// output model is used regardless of the selected backend.
pub fn discover_with_backend(
    backend: &dyn CertificateTransparencyBackend,
    domain: &str,
    timeout: Duration,
) -> Result<Vec<DiscoveredDomain>> {
    let domain = parse_domain(domain).map_err(anyhow::Error::msg)?;
    backend.discover(&domain, timeout)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    struct FixtureBackend {
        calls: Cell<usize>,
        fail: bool,
    }

    impl CertificateTransparencyBackend for FixtureBackend {
        fn discover(&self, domain: &str, timeout: Duration) -> Result<Vec<DiscoveredDomain>> {
            self.calls.set(self.calls.get() + 1);
            assert_eq!(domain, "example.com");
            assert_eq!(timeout, Duration::from_secs(15));
            if self.fail {
                anyhow::bail!("fixture backend unavailable");
            }
            let issued: Timestamp = "2024-01-01T00:00:00Z".parse()?;
            Ok(vec![DiscoveredDomain {
                domain: "api.example.com".into(),
                url: "https://api.example.com".into(),
                wildcard: false,
                first_issued: issued,
                last_issued: issued,
            }])
        }
    }

    #[test]
    fn supplied_backend_receives_normalized_domain_and_timeout() {
        let backend: Box<dyn CertificateTransparencyBackend> = Box::new(FixtureBackend {
            calls: Cell::new(0),
            fail: false,
        });
        let records = discover_with_backend(
            backend.as_ref(),
            " *.EXAMPLE.com. ",
            Duration::from_secs(15),
        )
        .unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].domain, "api.example.com");
        assert_eq!(records[0].url, "https://api.example.com");
        assert!(!records[0].wildcard);
    }

    #[test]
    fn invalid_domains_are_rejected_before_calling_backend() {
        let backend = FixtureBackend {
            calls: Cell::new(0),
            fail: false,
        };
        assert!(
            discover_with_backend(&backend, "https://example.com", Duration::from_secs(15))
                .is_err()
        );
        assert_eq!(backend.calls.get(), 0);
    }

    #[test]
    fn supplied_backend_errors_are_preserved() {
        let backend = FixtureBackend {
            calls: Cell::new(0),
            fail: true,
        };
        let error =
            discover_with_backend(&backend, "example.com", Duration::from_secs(15)).unwrap_err();
        assert_eq!(error.to_string(), "fixture backend unavailable");
        assert_eq!(backend.calls.get(), 1);
    }
}
