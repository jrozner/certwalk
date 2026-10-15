//! Censys Platform certificate search and free-plan lookup backends.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use jiff::Timestamp;
use reqwest::blocking::Client;
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::{
    CertificateTransparencyBackend, DiscoveredDomain, in_scope, normalize_name, parse_domain,
};

const ASSET_ENDPOINT: &str = "https://api.platform.censys.io/v3/global/asset";

const SEARCH_ENDPOINT: &str = "https://api.platform.censys.io/v3/global/search/query";
const SEARCH_FIELDS: [&str; 2] = ["cert.names", "cert.parsed.validity_period.not_before"];

/// Search certificates for a domain and its subdomains through Censys Platform.
///
/// Requires search API access. All result pages are fetched within the supplied
/// domain query timeout. For Free-compatible asset lookups use [`CensysFree`].
#[derive(Clone)]
pub struct Censys {
    credentials: CensysFree,
}

impl Censys {
    /// Create a search backend from a Platform Personal Access Token.
    pub fn new(token: impl AsRef<str>) -> Result<Self> {
        Ok(Self {
            credentials: CensysFree::new(token)?,
        })
    }

    /// Associate search requests with an organization UUID.
    pub fn with_organization_id(mut self, organization_id: impl AsRef<str>) -> Result<Self> {
        self.credentials = self.credentials.with_organization_id(organization_id)?;
        Ok(self)
    }

    fn discover_at(
        &self,
        endpoint: &str,
        domain: &str,
        timeout: Duration,
    ) -> Result<Vec<DiscoveredDomain>> {
        let started = Instant::now();
        let domain = parse_domain(domain).map_err(anyhow::Error::msg)?;
        let query = format!("cert.names: \"{domain}\"");
        let client = self.credentials.client(timeout)?;
        let mut records = BTreeMap::new();
        let mut page_token: Option<String> = None;
        let mut seen_tokens = BTreeSet::new();
        let mut fetched_hits = 0usize;
        let mut reported_hits = 0f64;
        loop {
            let remaining = timeout
                .checked_sub(started.elapsed())
                .filter(|remaining| !remaining.is_zero())
                .context("Censys domain query timed out before all pages were retrieved")?;
            let payload = SearchRequest {
                query: &query,
                fields: SEARCH_FIELDS,
                page_size: 100,
                page_token: page_token.as_deref(),
            };
            let mut request = client
                .post(endpoint)
                .timeout(remaining)
                .header(CONTENT_TYPE, "application/json")
                .body(serde_json::to_vec(&payload)?);
            if let Some(id) = &self.credentials.organization_id {
                request = request.query(&[("organization_id", id)]);
            }
            let response = request.send().context("could not query Censys search")?;
            let status = response.status();
            if !status.is_success() {
                let hint = match status.as_u16() {
                    401 => "check the Platform Personal Access Token",
                    403 => {
                        "check search API access, account credits, and organization selection; Free accounts can use censys-free"
                    }
                    422 => "check organization selection and query permissions",
                    429 => "Censys rate limit exceeded; retry later",
                    _ => "retry later or check Censys API access",
                };
                bail!("Censys search returned HTTP {status}; {hint}");
            }
            let body = response
                .bytes()
                .context("could not read the Censys search response")?;
            let page: SearchResponse = serde_json::from_slice(&body)
                .context("Censys returned invalid JSON or an unexpected search schema")?;
            let result = page.result;
            if !result.total_hits.is_finite()
                || result.total_hits < 0.0
                || result.total_hits.fract() != 0.0
            {
                bail!("Censys returned an invalid total_hits count");
            }
            reported_hits = reported_hits.max(result.total_hits);
            let hits = match result.hits {
                Some(hits) => hits,
                None if result.total_hits == 0.0 => Vec::new(),
                None => bail!("Censys returned a hit count without search hits"),
            };
            fetched_hits += hits.len();
            for hit in hits {
                let asset = hit
                    .certificate_v1
                    .context("Censys certificate query returned a non-certificate hit")?;
                add_certificate(&mut records, &domain, asset.resource)?;
            }
            match result.next_page_token.filter(|token| !token.is_empty()) {
                Some(token) => {
                    if !seen_tokens.insert(token.clone()) {
                        bail!("Censys repeated a pagination token; results may be incomplete");
                    }
                    page_token = Some(token);
                }
                None => {
                    if (fetched_hits as f64) < reported_hits {
                        bail!(
                            "Censys pagination ended after {fetched_hits} of {reported_hits} reported hits; results are incomplete"
                        );
                    }
                    break;
                }
            }
        }
        Ok(records.into_values().collect())
    }
}

impl CertificateTransparencyBackend for Censys {
    fn discover(&self, domain: &str, timeout: Duration) -> Result<Vec<DiscoveredDomain>> {
        self.discover_at(SEARCH_ENDPOINT, domain, timeout)
    }
}

#[derive(Serialize)]
struct SearchRequest<'a> {
    query: &'a str,
    fields: [&'a str; 2],
    page_size: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    page_token: Option<&'a str>,
}

#[derive(Deserialize)]
struct SearchResponse {
    result: SearchResult,
}

#[derive(Deserialize)]
struct SearchResult {
    hits: Option<Vec<SearchHit>>,
    next_page_token: Option<String>,
    total_hits: f64,
}

#[derive(Deserialize)]
struct SearchHit {
    certificate_v1: Option<Asset<Certificate>>,
}

/// Discover certificate names using Censys Free-compatible asset lookups.
///
/// Looks up the requested domain on HTTPS port 443, then retrieves the observed
/// certificate by SHA-256 fingerprint. This does not enumerate subdomains or
/// historic certificates across the Censys dataset. An organization can be
/// selected with [`Self::with_organization_id`]. The timeout covers both lookups.
#[derive(Clone)]
pub struct CensysFree {
    headers: HeaderMap,
    organization_id: Option<String>,
}

impl CensysFree {
    /// Create a backend from a Censys Platform Personal Access Token.
    pub fn new(token: impl AsRef<str>) -> Result<Self> {
        let token = token.as_ref().trim();
        if token.is_empty() {
            bail!("a Censys Platform Personal Access Token is required");
        }
        let mut authorization = HeaderValue::from_str(&format!("Bearer {token}"))
            .context("invalid Censys Personal Access Token")?;
        authorization.set_sensitive(true);
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, authorization);
        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
        Ok(Self {
            headers,
            organization_id: None,
        })
    }

    /// Associate requests with the supplied organization UUID.
    pub fn with_organization_id(mut self, organization_id: impl AsRef<str>) -> Result<Self> {
        let id = organization_id.as_ref().trim();
        if id.len() != 36
            || !id.bytes().enumerate().all(|(index, byte)| {
                if [8, 13, 18, 23].contains(&index) {
                    byte == b'-'
                } else {
                    byte.is_ascii_hexdigit()
                }
            })
        {
            bail!("Censys organization ID must be a UUID");
        }
        self.organization_id = Some(id.to_owned());
        Ok(self)
    }

    fn discover_at(
        &self,
        endpoint: &str,
        domain: &str,
        timeout: Duration,
    ) -> Result<Vec<DiscoveredDomain>> {
        let started = Instant::now();
        let domain = parse_domain(domain).map_err(anyhow::Error::msg)?;
        let client = self.client(timeout)?;
        let remaining = || {
            timeout
                .checked_sub(started.elapsed())
                .filter(|remaining| !remaining.is_zero())
                .context("Censys domain query timed out before all lookups completed")
        };
        let property: Option<WebProperty> = self
            .lookup(
                &client,
                &format!("{endpoint}/webproperty/{domain}:443"),
                remaining()?,
            )
            .with_context(|| format!("could not look up Censys web property {domain}:443"))?;
        let Some(property) = property else {
            return Ok(Vec::new());
        };
        if normalize_name(&property.hostname).as_deref() != Some(&domain) || property.port != 443 {
            bail!("Censys returned a web property that does not match {domain}:443");
        }
        let Some(reference) = property.cert else {
            return Ok(Vec::new());
        };
        let fingerprint = reference.fingerprint_sha256;
        if fingerprint.len() != 64 || !fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            bail!("Censys web property has an invalid SHA-256 certificate fingerprint");
        }
        let certificate: Certificate = self.lookup(
            &client,
            &format!("{endpoint}/certificate/{}", fingerprint.to_ascii_lowercase()),
            remaining()?,
        ).context("could not look up the Censys web property's certificate")?
            .context("Censys web property references a certificate that was not found; lookup is incomplete")?;
        let mut records = BTreeMap::new();
        add_certificate(&mut records, &domain, certificate)?;
        Ok(records.into_values().collect())
    }

    fn client(&self, timeout: Duration) -> Result<Client> {
        Client::builder()
            .user_agent(crate::USER_AGENT)
            .default_headers(self.headers.clone())
            .connect_timeout(Duration::from_secs(10).min(timeout))
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .context("could not initialize the Censys HTTP client")
    }

    fn lookup<T: DeserializeOwned>(
        &self,
        client: &Client,
        url: &str,
        timeout: Duration,
    ) -> Result<Option<T>> {
        let mut request = client.get(url).timeout(timeout);
        if let Some(id) = &self.organization_id {
            request = request.query(&[("organization_id", id)]);
        }
        let response = request.send().context("could not query Censys")?;
        let status = response.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !status.is_success() {
            let hint = match status.as_u16() {
                401 => "check the Platform Personal Access Token",
                403 => "check lookup API access, account credits, and organization selection",
                422 => "check organization selection and asset identifier",
                429 => "Censys rate limit exceeded; retry later",
                _ => "retry later or check Censys API access",
            };
            bail!("Censys returned HTTP {status}; {hint}");
        }
        let body = response
            .bytes()
            .context("could not read the Censys response")?;
        let asset: AssetResponse<T> = serde_json::from_slice(&body)
            .context("Censys returned invalid JSON or an unexpected lookup schema")?;
        Ok(Some(asset.result.resource))
    }
}

impl CertificateTransparencyBackend for CensysFree {
    fn discover(&self, domain: &str, timeout: Duration) -> Result<Vec<DiscoveredDomain>> {
        self.discover_at(ASSET_ENDPOINT, domain, timeout)
    }
}

#[derive(Deserialize)]
struct AssetResponse<T> {
    result: Asset<T>,
}

#[derive(Deserialize)]
struct Asset<T> {
    resource: T,
}

#[derive(Deserialize)]
struct WebProperty {
    hostname: String,
    port: u16,
    cert: Option<CertificateReference>,
}

#[derive(Deserialize)]
struct CertificateReference {
    fingerprint_sha256: String,
}

#[derive(Deserialize)]
struct Certificate {
    names: Vec<String>,
    parsed: Option<ParsedCertificate>,
}

#[derive(Deserialize)]
struct ParsedCertificate {
    validity_period: Option<ValidityPeriod>,
}

#[derive(Deserialize)]
struct ValidityPeriod {
    not_before: Option<String>,
}

fn add_certificate(
    records: &mut BTreeMap<String, DiscoveredDomain>,
    domain: &str,
    certificate: Certificate,
) -> Result<()> {
    let names: BTreeSet<String> = certificate
        .names
        .iter()
        .filter_map(|name| normalize_name(name))
        .filter(|name| in_scope(name, domain))
        .collect();
    if names.is_empty() {
        return Ok(());
    }
    let not_before = certificate
        .parsed
        .and_then(|parsed| parsed.validity_period)
        .and_then(|validity| validity.not_before)
        .context("Censys certificate is missing its not_before timestamp")?;
    let issued: Timestamp = not_before
        .parse()
        .context("Censys certificate has an invalid not_before timestamp")?;
    for name in names {
        let record = records
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
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::thread;

    const FINGERPRINT: &str = "3daf2843a77b6f4e6af43cd9b6f6746053b8c928e056e8a724808db8905a94cf";

    struct Request {
        first_line: String,
        headers: String,
        body: Vec<u8>,
    }

    fn asset(resource: Value) -> String {
        json!({"result": {"resource": resource, "extensions": {}}}).to_string()
    }

    fn property() -> String {
        asset(json!({"hostname": "example.com", "port": 443,
            "cert": {"fingerprint_sha256": FINGERPRINT}}))
    }

    fn certificate(names: &[&str], issued: &str) -> String {
        asset(json!({"names": names, "parsed": {"validity_period": {"not_before": issued}}}))
    }

    fn search_page(names: &[&str], issued: &str, total: usize, next: &str) -> String {
        json!({"result": {
            "hits": [{"certificate_v1": {"resource": {
                "names": names, "parsed": {"validity_period": {"not_before": issued}}
            }, "extensions": {}}}],
            "total_hits": total, "next_page_token": next
        }})
        .to_string()
    }

    #[test]
    fn search_fetches_all_pages_with_authentication_and_merges_histories() {
        let (endpoint, server) = mock_server(
            vec![
                (
                    200,
                    search_page(
                        &[
                            "API.EXAMPLE.com.",
                            "example.com",
                            "*.example.com",
                            "other.test",
                        ],
                        "2024-01-01T01:00:00.123456789+01:00",
                        2,
                        "next",
                    ),
                ),
                (
                    200,
                    search_page(&["api.example.com"], "2019-01-01T00:00:00Z", 2, ""),
                ),
            ],
            Duration::ZERO,
        );
        let organization = "11111111-2222-3333-4444-555555555555";
        let records = Censys::new("fixture-token")
            .unwrap()
            .with_organization_id(organization)
            .unwrap()
            .discover_at(
                &endpoint.replace("/asset", "/search/query"),
                "EXAMPLE.com.",
                Duration::from_secs(5),
            )
            .unwrap();
        assert_eq!(
            records
                .iter()
                .map(|record| record.domain.as_str())
                .collect::<Vec<_>>(),
            ["*.example.com", "api.example.com", "example.com"]
        );
        assert!(records[0].wildcard);
        assert_eq!(records[1].first_issued.to_string(), "2019-01-01T00:00:00Z");
        assert_eq!(
            records[1].last_issued.to_string(),
            "2024-01-01T00:00:00.123456789Z"
        );
        let requests = server.join().unwrap();
        assert_eq!(requests.len(), 2);
        for (index, request) in requests.into_iter().enumerate() {
            assert_eq!(
                request.first_line,
                format!("POST /v3/global/search/query?organization_id={organization} HTTP/1.1\r\n")
            );
            assert!(request.headers.contains("Bearer fixture-token"));
            assert!(
                request
                    .headers
                    .to_lowercase()
                    .contains("content-type: application/json")
            );
            let payload: Value = serde_json::from_slice(&request.body).unwrap();
            assert_eq!(payload["query"], "cert.names: \"example.com\"");
            assert_eq!(payload["fields"], json!(SEARCH_FIELDS));
            assert_eq!(payload["page_size"], 100);
            if index == 0 {
                assert!(payload.get("page_token").is_none());
            } else {
                assert_eq!(payload["page_token"], "next");
            }
        }
    }

    #[test]
    fn search_accepts_empty_results_and_rejects_malformed_data() {
        for hits in [json!([]), Value::Null] {
            let (endpoint, server) = mock_server(
                vec![(
                    200,
                    json!({"result": {"hits": hits, "total_hits": 0}}).to_string(),
                )],
                Duration::ZERO,
            );
            assert!(
                Censys::new("fixture-token")
                    .unwrap()
                    .discover_at(&endpoint, "example.com", Duration::from_secs(5))
                    .unwrap()
                    .is_empty()
            );
            server.join().unwrap();
        }
        for body in [
            "{}".into(),
            "<html>error</html>".into(),
            search_page(&["example.com"], "bad date", 1, ""),
            json!({"result": {"hits": [{"host_v1": {}}], "total_hits": 1}}).to_string(),
            json!({"result": {"hits": null, "total_hits": 1}}).to_string(),
            json!({"result": {"hits": [], "total_hits": -1}}).to_string(),
            json!({"result": {"hits": [], "total_hits": 1.5}}).to_string(),
        ] {
            let (endpoint, server) = mock_server(vec![(200, body)], Duration::ZERO);
            assert!(
                Censys::new("fixture-token")
                    .unwrap()
                    .discover_at(&endpoint, "example.com", Duration::from_secs(5))
                    .is_err()
            );
            server.join().unwrap();
        }
    }

    #[test]
    fn search_rejects_repeated_tokens_and_truncated_pagination() {
        for responses in [
            vec![
                (
                    200,
                    search_page(&["example.com"], "2024-01-01T00:00:00Z", 3, "same"),
                ),
                (
                    200,
                    search_page(&["example.com"], "2024-01-01T00:00:00Z", 3, "same"),
                ),
            ],
            vec![(
                200,
                search_page(&["example.com"], "2024-01-01T00:00:00Z", 2, ""),
            )],
        ] {
            let (endpoint, server) = mock_server(responses, Duration::ZERO);
            let error = Censys::new("fixture-token")
                .unwrap()
                .discover_at(&endpoint, "example.com", Duration::from_secs(5))
                .unwrap_err();
            assert!(error.to_string().contains("incomplete"));
            server.join().unwrap();
        }
    }

    struct SearchAt<'a>(&'a Censys, &'a str);
    impl CertificateTransparencyBackend for SearchAt<'_> {
        fn discover(&self, domain: &str, timeout: Duration) -> Result<Vec<DiscoveredDomain>> {
            self.0.discover_at(self.1, domain, timeout)
        }
    }

    struct FreeAt<'a>(&'a CensysFree, &'a str);
    impl CertificateTransparencyBackend for FreeAt<'_> {
        fn discover(&self, domain: &str, timeout: Duration) -> Result<Vec<DiscoveredDomain>> {
            self.0.discover_at(self.1, domain, timeout)
        }
    }

    #[test]
    fn free_lookup_continues_after_search_connection_failure_or_failed_page() {
        let search = Censys::new("fixture-token").unwrap();
        let free = CensysFree::new("fixture-token").unwrap();
        for failure in ["connection", "permission", "later-page"] {
            let (search_endpoint, search_server) = if failure == "connection" {
                let listener = TcpListener::bind("127.0.0.1:0").unwrap();
                let endpoint = format!("http://{}/search/query", listener.local_addr().unwrap());
                drop(listener);
                (endpoint, None)
            } else {
                let responses = if failure == "permission" {
                    vec![(403, "denied".into())]
                } else {
                    vec![
                        (
                            200,
                            search_page(
                                &["partial.example.com"],
                                "2019-01-01T00:00:00Z",
                                2,
                                "next",
                            ),
                        ),
                        (503, "unavailable".into()),
                    ]
                };
                let (endpoint, server) = mock_server(responses, Duration::ZERO);
                (endpoint, Some(server))
            };
            let (free_endpoint, free_server) = mock_server(
                vec![
                    (200, property()),
                    (
                        200,
                        certificate(&["api.example.com"], "2024-01-01T00:00:00Z"),
                    ),
                ],
                Duration::ZERO,
            );
            let report = crate::discover_many_with_backends_report(
                &[
                    ("censys", &SearchAt(&search, &search_endpoint)),
                    ("censys-free", &FreeAt(&free, &free_endpoint)),
                ],
                ["example.com"],
                Duration::from_secs(5),
            )
            .unwrap();
            assert_eq!(report.records.len(), 1);
            assert_eq!(report.records[0].record.domain, "api.example.com");
            assert!(report.records[0].sources.contains_key("censys-free"));
            assert_eq!(report.records[0].failed_sources, ["censys"]);
            assert!(report.records[0].missing_from.is_empty());
            assert!(!report.backend_errors["censys"].contains("fixture-token"));
            if failure == "permission" {
                assert!(report.backend_errors["censys"].contains("censys-free"));
            }
            if let Some(server) = search_server {
                server.join().unwrap();
            }
            assert_eq!(free_server.join().unwrap().len(), 2);
        }
    }

    #[test]
    fn search_timeout_covers_all_pages() {
        let (endpoint, server) = mock_server(
            vec![
                (
                    200,
                    search_page(&["example.com"], "2024-01-01T00:00:00Z", 2, "next"),
                ),
                (
                    200,
                    search_page(&["example.com"], "2024-01-01T00:00:00Z", 2, ""),
                ),
            ],
            Duration::from_millis(180),
        );
        let error = Censys::new("fixture-token")
            .unwrap()
            .discover_at(&endpoint, "example.com", Duration::from_millis(300))
            .unwrap_err();
        assert!(
            error.chain().any(|cause| cause
                .downcast_ref::<reqwest::Error>()
                .is_some_and(|error| error.is_timeout()))
                || format!("{error:#}").contains("timed out")
        );
        server.join().unwrap();
    }

    fn mock_server(
        responses: Vec<(u16, String)>,
        delay: Duration,
    ) -> (String, thread::JoinHandle<Vec<Request>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let endpoint = format!("http://{}/v3/global/asset", listener.local_addr().unwrap());
        let handle = thread::spawn(move || {
            let mut requests = Vec::new();
            for (status, body) in responses {
                let deadline = Instant::now() + Duration::from_secs(5);
                let mut stream = loop {
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(
                                Instant::now() < deadline,
                                "client did not request expected asset"
                            );
                            thread::sleep(Duration::from_millis(5));
                        }
                        Err(error) => panic!("mock server failed: {error}"),
                    }
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut first_line = String::new();
                reader.read_line(&mut first_line).unwrap();
                let mut headers = String::new();
                let mut length = 0;
                loop {
                    let mut line = String::new();
                    assert_ne!(reader.read_line(&mut line).unwrap(), 0);
                    if line == "\r\n" {
                        break;
                    }
                    if let Some((name, value)) = line.split_once(':')
                        && name.eq_ignore_ascii_case("content-length")
                    {
                        length = value.trim().parse::<usize>().unwrap();
                    }
                    headers.push_str(&line);
                }
                let mut payload = vec![0; length];
                reader.read_exact(&mut payload).unwrap();
                requests.push(Request {
                    first_line,
                    headers,
                    body: payload,
                });
                thread::sleep(delay);
                let response = format!(
                    "HTTP/1.1 {status} Response\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
            }
            requests
        });
        (endpoint, handle)
    }

    #[test]
    fn uses_only_lookup_endpoints_and_returns_normalized_scoped_certificate_names() {
        let (endpoint, server) = mock_server(
            vec![
                (200, property()),
                (
                    200,
                    certificate(
                        &[
                            "API.EXAMPLE.com.",
                            "api.example.com",
                            "example.com",
                            "*.example.com",
                            "foreign.test",
                            "notexample.com",
                            "example.com.evil.test",
                            "user@example.com",
                            "bücher.example.com",
                            "127.0.0.1",
                        ],
                        "2024-01-01T01:00:00.123456789+01:00",
                    ),
                ),
            ],
            Duration::ZERO,
        );
        let organization = "11111111-2222-3333-4444-555555555555";
        let records = CensysFree::new("fixture-token")
            .unwrap()
            .with_organization_id(organization)
            .unwrap()
            .discover_at(&endpoint, "*.EXAMPLE.com.", Duration::from_secs(5))
            .unwrap();
        let names: Vec<_> = records
            .iter()
            .map(|record| record.domain.as_str())
            .collect();
        assert_eq!(
            names,
            [
                "*.example.com",
                "api.example.com",
                "example.com",
                "xn--bcher-kva.example.com"
            ]
        );
        assert!(records[0].wildcard);
        assert!(!records[1].wildcard);
        assert_eq!(records[1].url, "https://api.example.com");
        for record in records {
            assert_eq!(
                record.first_issued.to_string(),
                "2024-01-01T00:00:00.123456789Z"
            );
            assert_eq!(record.last_issued, record.first_issued);
        }
        let requests = server.join().unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(
            requests[0].first_line,
            format!(
                "GET /v3/global/asset/webproperty/example.com:443?organization_id={organization} HTTP/1.1\r\n"
            )
        );
        assert_eq!(
            requests[1].first_line,
            format!(
                "GET /v3/global/asset/certificate/{FINGERPRINT}?organization_id={organization} HTTP/1.1\r\n"
            )
        );
        for request in requests {
            assert!(request.headers.contains("Bearer fixture-token"));
            assert!(
                request
                    .headers
                    .to_lowercase()
                    .contains("accept: application/json")
            );
            assert!(
                request
                    .headers
                    .to_lowercase()
                    .contains(&format!("user-agent: {}", crate::USER_AGENT.to_lowercase()))
            );
            assert!(request.body.is_empty());
        }
    }

    #[test]
    fn absent_web_properties_or_certificates_return_no_matches_without_an_organization() {
        for (status, body) in [
            (404, "not found".into()),
            (200, asset(json!({"hostname": "example.com", "port": 443}))),
            (
                200,
                asset(json!({"hostname": "example.com", "port": 443, "cert": null})),
            ),
        ] {
            let (endpoint, server) = mock_server(vec![(status, body)], Duration::ZERO);
            let records = CensysFree::new("fixture-token")
                .unwrap()
                .discover_at(&endpoint, "example.com", Duration::from_secs(5))
                .unwrap();
            assert!(records.is_empty());
            assert_eq!(
                server.join().unwrap()[0].first_line,
                "GET /v3/global/asset/webproperty/example.com:443 HTTP/1.1\r\n"
            );
        }
    }

    #[test]
    fn validates_credentials_and_marks_authorization_sensitive() {
        for token in ["", "  ", "invalid\ntoken"] {
            assert!(CensysFree::new(token).is_err());
        }
        let backend = CensysFree::new("fixture-token").unwrap();
        assert!(backend.headers[AUTHORIZATION].is_sensitive());
        assert!(backend.clone().with_organization_id("bad-id").is_err());
        assert!(
            backend
                .discover("https://example.com", Duration::from_secs(5))
                .is_err()
        );
    }

    #[test]
    fn reports_http_failures_from_either_lookup_without_exposing_credentials() {
        for status in [401, 403, 422, 429, 503] {
            for second in [false, true] {
                let mut responses = Vec::new();
                if second {
                    responses.push((200, property()));
                }
                responses.push((status, "error".into()));
                let (endpoint, server) = mock_server(responses, Duration::ZERO);
                let error = CensysFree::new("fixture-token")
                    .unwrap()
                    .discover_at(&endpoint, "example.com", Duration::from_secs(5))
                    .unwrap_err();
                let message = format!("{error:#}");
                assert!(message.contains(&status.to_string()));
                assert!(!message.contains("fixture-token"));
                assert!(!message.contains("search API"));
                assert_eq!(server.join().unwrap().len(), if second { 2 } else { 1 });
            }
        }
    }

    #[test]
    fn a_missing_referenced_certificate_is_an_error_rather_than_no_matches() {
        let (endpoint, server) = mock_server(
            vec![(200, property()), (404, "not found".into())],
            Duration::ZERO,
        );
        let error = CensysFree::new("fixture-token")
            .unwrap()
            .discover_at(&endpoint, "example.com", Duration::from_secs(5))
            .unwrap_err();
        assert!(error.to_string().contains("lookup is incomplete"));
        assert_eq!(server.join().unwrap().len(), 2);
    }

    #[test]
    fn rejects_malformed_or_mismatched_web_properties_and_invalid_fingerprints() {
        let invalid = [
            "<html>error</html>".into(),
            "{}".into(),
            asset(json!({"hostname": "other.test", "port": 443})),
            asset(json!({"hostname": "example.com", "port": 80})),
            asset(json!({"hostname": "example.com", "port": 443, "cert": {}})),
            asset(
                json!({"hostname": "example.com", "port": 443, "cert": {"fingerprint_sha256": "../search/query"}}),
            ),
            asset(
                json!({"hostname": "example.com", "port": 443, "cert": {"fingerprint_sha256": "g".repeat(64)}}),
            ),
        ];
        for body in invalid {
            let (endpoint, server) = mock_server(vec![(200, body)], Duration::ZERO);
            assert!(
                CensysFree::new("fixture-token")
                    .unwrap()
                    .discover_at(&endpoint, "example.com", Duration::from_secs(5))
                    .is_err()
            );
            assert_eq!(server.join().unwrap().len(), 1);
        }
    }

    #[test]
    fn rejects_malformed_certificates_or_missing_dates() {
        let invalid = [
            "<html>error</html>".into(),
            "{}".into(),
            certificate(&["example.com"], "bad timestamp"),
            asset(json!({"names": ["example.com"]})),
            asset(json!({"parsed": {"validity_period": {"not_before": "2024-01-01T00:00:00Z"}}})),
        ];
        for body in invalid {
            let (endpoint, server) =
                mock_server(vec![(200, property()), (200, body)], Duration::ZERO);
            assert!(
                CensysFree::new("fixture-token")
                    .unwrap()
                    .discover_at(&endpoint, "example.com", Duration::from_secs(5))
                    .is_err()
            );
            assert_eq!(server.join().unwrap().len(), 2);
        }
    }

    #[test]
    fn certificate_with_no_in_scope_names_returns_no_matches() {
        let (endpoint, server) = mock_server(
            vec![
                (200, property()),
                (200, certificate(&["other.test"], "2024-01-01T00:00:00Z")),
            ],
            Duration::ZERO,
        );
        assert!(
            CensysFree::new("fixture-token")
                .unwrap()
                .discover_at(&endpoint, "example.com", Duration::from_secs(5))
                .unwrap()
                .is_empty()
        );
        server.join().unwrap();
    }

    #[test]
    fn timeout_covers_both_lookups_of_a_domain_query() {
        let (endpoint, server) = mock_server(
            vec![
                (200, property()),
                (200, certificate(&["example.com"], "2024-01-01T00:00:00Z")),
            ],
            Duration::from_millis(180),
        );
        let error = CensysFree::new("fixture-token")
            .unwrap()
            .discover_at(&endpoint, "example.com", Duration::from_millis(300))
            .unwrap_err();
        assert!(
            error.chain().any(|cause| cause
                .downcast_ref::<reqwest::Error>()
                .is_some_and(|error| error.is_timeout()))
                || format!("{error:#}").contains("timed out")
        );
        server.join().unwrap();
    }
}
