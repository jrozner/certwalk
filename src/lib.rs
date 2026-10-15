//! Domain discovery with interchangeable certificate transparency backends.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use jiff::Timestamp;
use serde::Serialize;

pub mod backend;
pub mod censys;
pub mod crtsh;

pub use backend::CertificateTransparencyBackend;
pub use censys::{Censys, CensysFree};
pub use crtsh::{CrtSh, discover_from_json};

/// Desktop Chrome user agent sent with every backend HTTP request.
pub(crate) const USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36";

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

/// Certificate validity-start range returned by one source.
#[derive(Debug, Serialize)]
pub struct CertificateHistory {
    pub first_issued: Timestamp,
    pub last_issued: Timestamp,
}

/// A unioned identity with coverage across all selected backends.
#[derive(Debug, Serialize)]
pub struct SourcedDomain {
    #[serde(flatten)]
    pub record: DiscoveredDomain,
    /// Source names mapped to their observed certificate histories.
    pub sources: BTreeMap<String, CertificateHistory>,
    /// Selected sources that returned no match for this identity in this run.
    /// This does not establish absence from their entire datasets.
    pub missing_from: Vec<String>,
    /// Selected backends whose queries failed; their coverage is unknown.
    pub failed_sources: Vec<String>,
}

/// Results from successful backends and errors from unsuccessful backends.
#[derive(Debug, Serialize)]
pub struct DiscoveryReport {
    pub records: Vec<SourcedDomain>,
    /// Backend names mapped to errors, including the failed domain query.
    pub backend_errors: BTreeMap<String, String>,
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

/// Discover and merge identities for multiple domains using the default backend.
///
/// Duplicate queries are normalized and queried once. Results are deduplicated
/// by identity, retaining the earliest/latest dates across overlapping queries.
pub fn discover_many(
    domains: impl IntoIterator<Item = impl AsRef<str>>,
    timeout: Duration,
) -> Result<Vec<DiscoveredDomain>> {
    discover_many_with_backend(&CrtSh, domains, timeout)
}

/// Discover and merge identities for multiple domains using a supplied backend.
///
/// All input domains are validated before querying. Queries run sequentially,
/// with the supplied timeout applied to each query. An empty input or a failed
/// query returns an error; callers receive results only when all queries succeed.
pub fn discover_many_with_backend(
    backend: &dyn CertificateTransparencyBackend,
    domains: impl IntoIterator<Item = impl AsRef<str>>,
    timeout: Duration,
) -> Result<Vec<DiscoveredDomain>> {
    let queries: BTreeSet<String> = domains
        .into_iter()
        .map(|domain| parse_domain(domain.as_ref()))
        .collect::<std::result::Result<_, _>>()
        .map_err(anyhow::Error::msg)?;
    if queries.is_empty() {
        bail!("at least one domain is required");
    }
    let mut records: BTreeMap<String, DiscoveredDomain> = BTreeMap::new();
    for domain in queries {
        let discovered = backend
            .discover(&domain, timeout)
            .with_context(|| format!("could not discover domains for {domain}"))?;
        for record in discovered {
            records
                .entry(record.domain.clone())
                .and_modify(|existing| {
                    existing.first_issued = existing.first_issued.min(record.first_issued);
                    existing.last_issued = existing.last_issued.max(record.last_issued);
                })
                .or_insert(record);
        }
    }
    Ok(records.into_values().collect())
}

/// Discover a domain with multiple named backends, preserving source coverage.
pub fn discover_with_backends(
    backends: &[(&str, &dyn CertificateTransparencyBackend)],
    domain: &str,
    timeout: Duration,
) -> Result<Vec<SourcedDomain>> {
    discover_many_with_backends(backends, [domain], timeout)
}

/// Union identities from multiple domains and named backends.
///
/// Names must be nonempty and unique. All inputs are validated before requests.
/// Queries run sequentially, with the timeout applied to each backend/domain
/// query. Failed backends are excluded and listed in `failed_sources`; an error
/// is returned only if all backends fail. Histories
/// are merged both across sources and within each source across input domains.
/// Unselected backends are never listed as missing.
/// Use [`discover_many_with_backends_report`] to also obtain error details,
/// including when successful backends return no matches.
pub fn discover_many_with_backends(
    backends: &[(&str, &dyn CertificateTransparencyBackend)],
    domains: impl IntoIterator<Item = impl AsRef<str>>,
    timeout: Duration,
) -> Result<Vec<SourcedDomain>> {
    Ok(discover_many_with_backends_report(backends, domains, timeout)?.records)
}

/// Discover with independent backends, returning results and recoverable errors.
///
/// A backend contributes results only if all its domain queries succeed. Failed
/// backends do not prevent the remaining backends from being queried, and are
/// excluded from `missing_from`. A successful empty result counts as success.
/// Invalid inputs or failure of every backend return an error.
pub fn discover_many_with_backends_report(
    backends: &[(&str, &dyn CertificateTransparencyBackend)],
    domains: impl IntoIterator<Item = impl AsRef<str>>,
    timeout: Duration,
) -> Result<DiscoveryReport> {
    let mut names = BTreeSet::new();
    for (name, _) in backends {
        if name.trim().is_empty() || !names.insert(*name) {
            bail!("backend names must be nonempty and unique");
        }
    }
    if backends.is_empty() {
        bail!("at least one backend is required");
    }
    let domains: BTreeSet<String> = domains
        .into_iter()
        .map(|domain| parse_domain(domain.as_ref()))
        .collect::<std::result::Result<_, _>>()
        .map_err(anyhow::Error::msg)?;
    if domains.is_empty() {
        bail!("at least one domain is required");
    }

    let mut records: BTreeMap<String, SourcedDomain> = BTreeMap::new();
    let mut backend_errors = BTreeMap::new();
    for (name, backend) in backends {
        let discovered = match discover_many_with_backend(*backend, &domains, timeout) {
            Ok(discovered) => discovered,
            Err(error) => {
                backend_errors.insert((*name).to_owned(), format!("{error:#}"));
                continue;
            }
        };
        for record in discovered {
            let history = CertificateHistory {
                first_issued: record.first_issued,
                last_issued: record.last_issued,
            };
            let existing = records
                .entry(record.domain.clone())
                .or_insert_with(|| SourcedDomain {
                    record,
                    sources: BTreeMap::new(),
                    missing_from: Vec::new(),
                    failed_sources: Vec::new(),
                });
            existing.record.first_issued = existing.record.first_issued.min(history.first_issued);
            existing.record.last_issued = existing.record.last_issued.max(history.last_issued);
            existing.sources.insert((*name).to_owned(), history);
        }
    }
    if backend_errors.len() == backends.len() {
        let errors = backend_errors
            .iter()
            .map(|(name, error)| format!("backend {name} failed: {error}"))
            .collect::<Vec<_>>()
            .join("; ");
        bail!("all backends failed: {errors}");
    }
    for record in records.values_mut() {
        record.missing_from = names
            .iter()
            .filter(|name| {
                !backend_errors.contains_key(**name) && !record.sources.contains_key(**name)
            })
            .map(|name| (*name).to_owned())
            .collect();
        record.failed_sources = backend_errors.keys().cloned().collect();
    }
    Ok(DiscoveryReport {
        records: records.into_values().collect(),
        backend_errors,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};

    #[derive(Default)]
    struct BatchFixtureBackend {
        queries: RefCell<Vec<String>>,
    }

    impl CertificateTransparencyBackend for BatchFixtureBackend {
        fn discover(&self, domain: &str, timeout: Duration) -> Result<Vec<DiscoveredDomain>> {
            assert_eq!(timeout, Duration::from_secs(15));
            self.queries.borrow_mut().push(domain.into());
            let record = |domain: &str, first: &str, last: &str| -> Result<DiscoveredDomain> {
                Ok(DiscoveredDomain {
                    domain: domain.into(),
                    url: format!("https://{domain}"),
                    wildcard: domain.starts_with("*."),
                    first_issued: first.parse()?,
                    last_issued: last.parse()?,
                })
            };
            match domain {
                "example.com" => Ok(vec![
                    record(
                        "example.com",
                        "2020-01-01T00:00:00Z",
                        "2024-01-01T00:00:00Z",
                    )?,
                    record(
                        "api.example.com",
                        "2022-01-01T00:00:00Z",
                        "2023-01-01T00:00:00Z",
                    )?,
                    record(
                        "*.example.com",
                        "2021-01-01T00:00:00Z",
                        "2024-01-01T00:00:00Z",
                    )?,
                ]),
                "api.example.com" => Ok(vec![record(
                    "api.example.com",
                    "2018-01-01T00:00:00Z",
                    "2025-01-01T00:00:00Z",
                )?]),
                "example.org" => bail!("backend unavailable"),
                _ => Ok(vec![]),
            }
        }
    }

    #[test]
    fn multiple_queries_are_deduplicated_and_overlapping_histories_are_merged() {
        let backend = BatchFixtureBackend::default();
        let records = discover_many_with_backend(
            &backend,
            [
                "EXAMPLE.com.",
                "example.com",
                "*.example.com",
                "api.example.com",
            ],
            Duration::from_secs(15),
        )
        .unwrap();
        assert_eq!(
            *backend.queries.borrow(),
            ["api.example.com", "example.com"]
        );
        let names: Vec<_> = records
            .iter()
            .map(|record| record.domain.as_str())
            .collect();
        assert_eq!(names, ["*.example.com", "api.example.com", "example.com"]);
        assert!(records[0].wildcard);
        assert!(!records[2].wildcard);
        assert_eq!(records[1].first_issued.to_string(), "2018-01-01T00:00:00Z");
        assert_eq!(records[1].last_issued.to_string(), "2025-01-01T00:00:00Z");
        assert_eq!(records[2].first_issued.to_string(), "2020-01-01T00:00:00Z");
        assert_eq!(records[2].last_issued.to_string(), "2024-01-01T00:00:00Z");
    }

    #[test]
    fn batch_inputs_are_fully_validated_before_any_queries() {
        let backend = BatchFixtureBackend::default();
        assert!(
            discover_many_with_backend(
                &backend,
                ["example.com", "https://example.org"],
                Duration::from_secs(15),
            )
            .is_err()
        );
        assert!(
            discover_many_with_backend(
                &backend,
                std::iter::empty::<&str>(),
                Duration::from_secs(15),
            )
            .is_err()
        );
        assert!(backend.queries.borrow().is_empty());
    }

    #[test]
    fn batch_errors_identify_the_failed_query_and_do_not_return_partial_results() {
        let backend = BatchFixtureBackend::default();
        let error = discover_many_with_backend(
            &backend,
            ["example.com", "example.org"],
            Duration::from_secs(15),
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("example.org"));
        assert!(format!("{error:#}").contains("backend unavailable"));
        assert_eq!(*backend.queries.borrow(), ["example.com", "example.org"]);
    }

    #[test]
    fn successful_queries_with_no_matches_return_an_empty_set() {
        let backend = BatchFixtureBackend::default();
        let records = discover_many_with_backend(
            &backend,
            ["nomatches.example", "another.example"],
            Duration::from_secs(15),
        )
        .unwrap();
        assert!(records.is_empty());
        assert_eq!(backend.queries.borrow().len(), 2);
    }

    struct FixtureBackend {
        calls: Cell<usize>,
        fail: bool,
    }

    struct SourceFixtureBackend {
        json: &'static [u8],
        queries: RefCell<Vec<String>>,
    }

    impl CertificateTransparencyBackend for SourceFixtureBackend {
        fn discover(&self, domain: &str, timeout: Duration) -> Result<Vec<DiscoveredDomain>> {
            assert_eq!(timeout, Duration::from_secs(15));
            self.queries.borrow_mut().push(domain.into());
            discover_from_json(domain, self.json)
        }
    }

    #[test]
    fn backend_union_preserves_coverage_and_each_sources_history() {
        let crtsh = BatchFixtureBackend::default();
        let censys = SourceFixtureBackend {
            json: br#"[
                {"name_value":"API.EXAMPLE.COM.\nscan.example.com\n*.api.example.com", "not_before":"2017-01-01T00:00:00Z"},
                {"name_value":"api.example.com", "not_before":"2024-01-01T00:00:00Z"}
            ]"#,
            queries: RefCell::default(),
        };
        let records = discover_many_with_backends(
            &[("crt.sh", &crtsh), ("censys", &censys)],
            ["EXAMPLE.com.", "example.com", "api.example.com"],
            Duration::from_secs(15),
        )
        .unwrap();
        let names: Vec<_> = records
            .iter()
            .map(|record| record.record.domain.as_str())
            .collect();
        assert_eq!(
            names,
            [
                "*.api.example.com",
                "*.example.com",
                "api.example.com",
                "example.com",
                "scan.example.com"
            ]
        );
        assert_eq!(*crtsh.queries.borrow(), ["api.example.com", "example.com"]);
        assert_eq!(*censys.queries.borrow(), ["api.example.com", "example.com"]);
        let api = &records[2];
        assert!(api.missing_from.is_empty());
        assert_eq!(api.sources.len(), 2);
        assert_eq!(api.record.first_issued.to_string(), "2017-01-01T00:00:00Z");
        assert_eq!(api.record.last_issued.to_string(), "2025-01-01T00:00:00Z");
        assert_eq!(
            api.sources["crt.sh"].first_issued.to_string(),
            "2018-01-01T00:00:00Z"
        );
        assert_eq!(
            api.sources["crt.sh"].last_issued.to_string(),
            "2025-01-01T00:00:00Z"
        );
        assert_eq!(
            api.sources["censys"].last_issued.to_string(),
            "2024-01-01T00:00:00Z"
        );
        assert_eq!(records[0].missing_from, ["crt.sh"]);
        assert!(records[0].record.wildcard);
        assert_eq!(records[1].missing_from, ["censys"]);
        assert_eq!(records[4].missing_from, ["crt.sh"]);
        let json = serde_json::to_value(&records).unwrap();
        assert_eq!(json[2]["domain"], "api.example.com");
        assert_eq!(
            json[2]["sources"]["censys"]["first_issued"],
            "2017-01-01T00:00:00Z"
        );
        assert_eq!(json[4]["missing_from"], serde_json::json!(["crt.sh"]));
    }

    #[test]
    fn empty_sources_are_missing_but_unselected_sources_are_not() {
        let populated = BatchFixtureBackend::default();
        let empty = SourceFixtureBackend {
            json: b"[]",
            queries: RefCell::default(),
        };
        let records = discover_with_backends(
            &[("populated", &populated), ("empty", &empty)],
            "example.com",
            Duration::from_secs(15),
        )
        .unwrap();
        assert!(
            records
                .iter()
                .all(|record| record.missing_from == ["empty"])
        );
        let records = discover_with_backends(
            &[("populated", &populated)],
            "example.com",
            Duration::from_secs(15),
        )
        .unwrap();
        assert!(records.iter().all(|record| record.missing_from.is_empty()));
        assert!(
            discover_with_backends(&[("empty", &empty)], "example.com", Duration::from_secs(15),)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn multi_backend_inputs_are_validated_before_queries() {
        let backend = BatchFixtureBackend::default();
        let timeout = Duration::from_secs(15);
        for backends in [
            vec![],
            vec![("", &backend as &dyn CertificateTransparencyBackend)],
            vec![("   ", &backend)],
            vec![("same", &backend), ("same", &backend)],
        ] {
            assert!(discover_with_backends(&backends, "example.com", timeout).is_err());
        }
        let backends = [("fixture", &backend as &dyn CertificateTransparencyBackend)];
        assert!(
            discover_many_with_backends(&backends, ["example.com", "https://example.org"], timeout)
                .is_err()
        );
        assert!(
            discover_many_with_backends(&backends, std::iter::empty::<&str>(), timeout).is_err()
        );
        assert!(backend.queries.borrow().is_empty());
    }

    #[test]
    fn backend_failure_is_recoverable_regardless_of_backend_order() {
        let populated = BatchFixtureBackend::default();
        let failed = FixtureBackend {
            calls: Cell::new(0),
            fail: true,
        };
        for backends in [
            [
                ("crt.sh", &populated as &dyn CertificateTransparencyBackend),
                ("censys", &failed),
            ],
            [("censys", &failed), ("crt.sh", &populated)],
        ] {
            let report = discover_many_with_backends_report(
                &backends,
                ["example.com"],
                Duration::from_secs(15),
            )
            .unwrap();
            assert_eq!(report.records.len(), 3);
            assert_eq!(report.backend_errors.len(), 1);
            assert!(report.backend_errors["censys"].contains("example.com"));
            assert!(report.backend_errors["censys"].contains("fixture backend unavailable"));
            for record in report.records {
                assert!(record.missing_from.is_empty());
                assert_eq!(record.failed_sources, ["censys"]);
                assert_eq!(record.sources.keys().collect::<Vec<_>>(), ["crt.sh"]);
            }
        }
        assert_eq!(failed.calls.get(), 2);
    }

    #[test]
    fn a_failed_batch_discards_only_that_backends_results_and_continues() {
        let failed = BatchFixtureBackend::default();
        let successful = SourceFixtureBackend {
            json: br#"[{"name_value":"scan.example.com", "not_before":"2024-01-01T00:00:00Z"}]"#,
            queries: RefCell::default(),
        };
        let report = discover_many_with_backends_report(
            &[("failed", &failed), ("successful", &successful)],
            ["example.com", "example.org"],
            Duration::from_secs(15),
        )
        .unwrap();
        assert_eq!(report.records.len(), 1);
        assert_eq!(report.records[0].record.domain, "scan.example.com");
        assert_eq!(report.records[0].failed_sources, ["failed"]);
        assert!(report.records[0].missing_from.is_empty());
        assert!(report.backend_errors["failed"].contains("example.org"));
        assert_eq!(*successful.queries.borrow(), ["example.com", "example.org"]);
    }

    #[test]
    fn successful_empty_results_recover_from_failure_and_retain_error_details() {
        let failed = FixtureBackend {
            calls: Cell::new(0),
            fail: true,
        };
        let empty = SourceFixtureBackend {
            json: b"[]",
            queries: RefCell::default(),
        };
        let report = discover_many_with_backends_report(
            &[("failed", &failed), ("empty", &empty)],
            ["example.com"],
            Duration::from_secs(15),
        )
        .unwrap();
        assert!(report.records.is_empty());
        assert_eq!(report.backend_errors.len(), 1);
        assert!(report.backend_errors["failed"].contains("fixture backend unavailable"));
        assert_eq!(empty.queries.borrow().len(), 1);
    }

    #[test]
    fn failure_of_every_backend_remains_an_error_after_trying_them_all() {
        let failed = FixtureBackend {
            calls: Cell::new(0),
            fail: true,
        };
        let other = FixtureBackend {
            calls: Cell::new(0),
            fail: true,
        };
        let error = discover_with_backends(
            &[("one", &failed), ("two", &other)],
            "example.com",
            Duration::from_secs(15),
        )
        .unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("all backends failed"));
        assert!(message.contains("backend one failed"));
        assert!(message.contains("backend two failed"));
        assert!(message.contains("example.com"));
        assert_eq!(failed.calls.get(), 1);
        assert_eq!(other.calls.get(), 1);
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
