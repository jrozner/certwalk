//! crt.sh's JSON certificate transparency backend.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use jiff::{Timestamp, civil::DateTime, tz::TimeZone};
use reqwest::blocking::Client;
use serde::Deserialize;

use crate::{
    CertificateTransparencyBackend, DiscoveredDomain, in_scope, normalize_name, parse_domain,
};

const CRTSH_ENDPOINT: &str = "https://crt.sh/json";

/// Discover certificate identities using crt.sh's public JSON endpoint.
#[derive(Clone, Copy, Debug, Default)]
pub struct CrtSh;

impl CertificateTransparencyBackend for CrtSh {
    fn discover(&self, domain: &str, timeout: Duration) -> Result<Vec<DiscoveredDomain>> {
        discover_at(CRTSH_ENDPOINT, domain, timeout)
    }
}

#[derive(Debug, Deserialize)]
struct Certificate {
    #[serde(default)]
    name_value: Option<String>,
    #[serde(default)]
    common_name: Option<String>,
    not_before: String,
}

fn parse_issued(value: &str) -> Result<Timestamp> {
    if let Ok(timestamp) = value.parse::<Timestamp>() {
        return Ok(timestamp);
    }
    // crt.sh returns UTC timestamps without a timezone suffix.
    for format in ["%Y-%m-%dT%H:%M:%S%.f", "%Y-%m-%d %H:%M:%S%.f"] {
        if let Ok(datetime) = DateTime::strptime(format, value) {
            return Ok(datetime.to_zoned(TimeZone::UTC)?.timestamp());
        }
    }
    bail!("invalid certificate not_before timestamp: {value:?}");
}

/// Parse a crt.sh JSON response and aggregate identities within the requested DNS scope.
pub fn discover_from_json(domain: &str, json: &[u8]) -> Result<Vec<DiscoveredDomain>> {
    let domain = parse_domain(domain).map_err(anyhow::Error::msg)?;
    let certificates: Vec<Certificate> = serde_json::from_slice(json)
        .context("crt.sh returned invalid JSON or an unexpected certificate schema")?;
    let mut domains: BTreeMap<String, DiscoveredDomain> = BTreeMap::new();

    for certificate in certificates {
        let names: BTreeSet<String> = certificate
            .name_value
            .iter()
            .chain(certificate.common_name.iter())
            .flat_map(|value| value.lines())
            .filter_map(normalize_name)
            .filter(|name| in_scope(name, &domain))
            .collect();
        if names.is_empty() {
            continue;
        }
        let issued = parse_issued(&certificate.not_before)?;
        for name in names {
            let record = domains
                .entry(name.clone())
                .or_insert_with(|| DiscoveredDomain {
                    url: format!("https://{name}"),
                    wildcard: name.starts_with("*."),
                    domain: name,
                    first_issued: issued,
                    last_issued: issued,
                });
            record.first_issued = record.first_issued.min(issued);
            record.last_issued = record.last_issued.max(issued);
        }
    }
    Ok(domains.into_values().collect())
}

fn discover_at(endpoint: &str, domain: &str, timeout: Duration) -> Result<Vec<DiscoveredDomain>> {
    let domain = parse_domain(domain).map_err(anyhow::Error::msg)?;
    let client = Client::builder()
        .user_agent(concat!("certwalk/", env!("CARGO_PKG_VERSION")))
        .connect_timeout(Duration::from_secs(10).min(timeout))
        .timeout(timeout)
        .build()
        .context("could not initialize the HTTP client")?;
    let response = client
        .get(endpoint)
        .query(&[("q", &domain)])
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .context("could not query crt.sh (try again or increase --timeout)")?
        .error_for_status()
        .context("crt.sh returned an HTTP error")?;
    let body = response
        .bytes()
        .context("could not read the crt.sh response")?;
    discover_from_json(&domain, &body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn parses_utc_offset_and_fractional_timestamps_without_losing_precision() {
        let expected: Timestamp = "2024-01-01T00:00:00.123456789Z".parse().unwrap();
        for value in [
            "2024-01-01T00:00:00.123456789",
            "2024-01-01 00:00:00.123456789",
            "2024-01-01T00:00:00.123456789Z",
            "2024-01-01T01:00:00.123456789+01:00",
            "2023-12-31T19:00:00.123456789-05:00",
        ] {
            assert_eq!(parse_issued(value).unwrap(), expected, "{value}");
        }
    }

    #[test]
    fn rejects_invalid_dates_and_offsets() {
        for value in [
            "2024-02-30T00:00:00",
            "2024-01-01T25:00:00",
            "2024-01-01T00:00:00+99:00",
            "2024-01-01T00:00:00junk",
            "2024-01-01",
        ] {
            assert!(parse_issued(value).is_err(), "accepted {value}");
        }
    }

    #[test]
    fn deduplicates_names_and_tracks_validity_start_extremes() {
        let json = br#"[
            {"name_value":"WWW.Example.com\n*.example.com\nexample.com\nforeign.test",
             "common_name":"www.example.com", "not_before":"2024-07-01T12:00:00"},
            {"name_value":"www.example.com.\nexample.com", "not_before":"2020-01-01T00:00:00"},
            {"name_value":"www.example.com", "not_before":"2025-01-01T01:00:00+01:00"},
            {"name_value":"www.example.com", "not_before":"2025-01-01T00:00:00Z"}
        ]"#;
        let records = discover_from_json("example.com", json).unwrap();
        assert_eq!(records.len(), 3);
        assert_eq!(records[0].domain, "*.example.com");
        assert!(records[0].wildcard);
        assert_eq!(records[1].domain, "example.com");
        assert!(!records[1].wildcard);
        assert_eq!(records[2].url, "https://www.example.com");
        assert_eq!(records[2].first_issued.to_string(), "2020-01-01T00:00:00Z");
        assert_eq!(records[2].last_issued.to_string(), "2025-01-01T00:00:00Z");
    }

    #[test]
    fn scopes_on_dns_label_boundaries_and_filters_invalid_identities() {
        let json = br#"[{"name_value":"example.com.evil.test\nnotexample.com\nexample.com\napi.example.com\n*.api.example.com\nhttps://example.com\nuser@example.com\n*.*.example.com\n_bad.example.com\n-bad.example.com",
            "common_name":"other.example.com", "not_before":"2024-01-01T00:00:00"}]"#;
        let records = discover_from_json("example.com", json).unwrap();
        let names: Vec<_> = records
            .iter()
            .map(|record| record.domain.as_str())
            .collect();
        assert_eq!(
            names,
            [
                "*.api.example.com",
                "api.example.com",
                "example.com",
                "other.example.com"
            ]
        );
    }

    #[test]
    fn common_name_is_supported_when_name_value_is_absent_or_null() {
        for names in ["", "\"name_value\":null,"] {
            let json = format!(
                "[{{{names}\"common_name\":\"example.com\",\"not_before\":\"2024-01-01T00:00:00.123456\"}}]"
            );
            let records = discover_from_json("example.com", json.as_bytes()).unwrap();
            assert_eq!(records[0].first_issued.subsec_microsecond(), 123456);
        }
    }

    #[test]
    fn rejects_invalid_data_and_accepts_empty_results() {
        assert!(discover_from_json("example.com", b"[]").unwrap().is_empty());
        assert!(discover_from_json("example.com", b"<html>error</html>").is_err());
        assert!(discover_from_json("example.com", b"null").is_err());
        assert!(
            discover_from_json(
                "example.com",
                br#"[{"name_value":"example.com","not_before":"bad"}]"#
            )
            .is_err()
        );
        assert!(discover_from_json("example.com", br#"[{"name_value":"example.com"}]"#).is_err());
    }

    #[test]
    fn validates_and_normalizes_query_domains() {
        assert_eq!(parse_domain(" *.EXAMPLE.com. ").unwrap(), "example.com");
        assert_eq!(
            parse_domain("bücher.example").unwrap(),
            "xn--bcher-kva.example"
        );
        for invalid in [
            "",
            "localhost",
            "https://example.com",
            "example.com/path",
            "example.com:443",
            "%.example.com",
            "127.0.0.1",
            "*.*.example.com",
            "a..example.com",
            "example.com..",
        ] {
            assert!(parse_domain(invalid).is_err(), "accepted {invalid}");
        }
    }

    fn mock_server(status: &str, body: &str) -> (String, thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}/json", listener.local_addr().unwrap());
        let response = format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut request = String::new();
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap() == 0 || line == "\r\n" {
                    break;
                }
                request.push_str(&line);
            }
            stream.write_all(response.as_bytes()).unwrap();
            request
        });
        (endpoint, handle)
    }

    #[test]
    fn http_client_queries_json_endpoint_and_parses_records() {
        let (endpoint, server) = mock_server(
            "200 OK",
            r#"[{"name_value":"example.com","not_before":"2024-01-01T00:00:00"}]"#,
        );
        let records = discover_at(&endpoint, "EXAMPLE.com", Duration::from_secs(5)).unwrap();
        assert_eq!(records.len(), 1);
        let request = server.join().unwrap();
        assert!(request.starts_with("GET /json?q=example.com HTTP/1.1\r\n"));
        assert!(request.to_lowercase().contains("accept: application/json"));
    }

    #[test]
    fn http_errors_are_not_treated_as_empty_results() {
        let (endpoint, server) = mock_server("503 Service Unavailable", "unavailable");
        let error = discover_at(&endpoint, "example.com", Duration::from_secs(5)).unwrap_err();
        assert!(format!("{error:#}").contains("503"));
        server.join().unwrap();
    }
}
