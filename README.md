# certwalk

A Rust 2024 CLI that discovers domains and their subdomains from certificate
transparency data, deduplicates certificate identities, and reports their
certificate history. Certificate transparency sources are supplied through a
backend trait.

## Install

Install a current stable Rust toolchain, then run:

```sh
cargo install --path .
```

Or use `cargo run --` in place of `certwalk` during development.

## Usage

```sh
# Print a table of URLs, wildcard flags, and first/latest issuance dates.
certwalk example.com

# Search several domains and merge their results.
certwalk example.com example.org

# Select Censys lookup discovery (works with a Free account and CENSYS_API_TOKEN).
certwalk example.com --backend censys-free

# Use Censys certificate search (requires search API access).
certwalk example.com --backend censys

# Union both backends, with source coverage in the table and saved JSON.
certwalk example.com --backend crt.sh,censys --output domains.json
# Equivalent repeated options:
certwalk example.com -b crt.sh -b censys

# Combine crt.sh with Free-compatible Censys lookups.
certwalk example.com -b crt.sh -b censys-free

# Read one domain per line from a file, or from stdin.
certwalk --input targets.txt
cat targets.txt | certwalk --input -

# Combine positional domains with a file.
certwalk example.com --input targets.txt

# Print the table and also save the complete results as JSON.
certwalk example.com --output domains.json

# Print JSON to stdout.
certwalk example.com --format json

# Write one concrete HTTPS URL per line, while retaining metadata in JSON.
certwalk example.com --format urls --output domains.json > urls.txt

# Emit bare concrete hostnames.
certwalk example.com --format domains > domains.txt

# Increase the timeout per backend/domain query (default: 60 seconds).
certwalk example.com --timeout 120
```

Positional arguments work well for short lists. Use `--input FILE` (or `-i FILE`)
for larger lists, with one bare domain per line. Blank lines and lines beginning
with `#` are ignored, and surrounding whitespace is trimmed. Invalid entries
report the file or stdin line number.

Input domains are normalized and deduplicated before any requests. Selected
backends are also deduplicated. Queries run sequentially, with `--timeout`
applied to each backend/domain query. All results are merged into
one set: overlapping identities retain their earliest and latest certificate
dates across queries. Empty input is an error. Backends run independently: if a
backend query fails, all results from that backend are discarded, a warning is
printed to stderr, and the remaining backends continue. A run succeeds if at
least one backend completes all input domains, even if it returns no matches.
If every backend fails, the command exits unsuccessfully without writing output.

Plain URL output can be piped to a tool that accepts URLs on stdin, for example:

```sh
certwalk example.com --format urls | feroxbuster --stdin -w wordlist.txt
```

## Output

Results are sorted by normalized domain name. JSON is an array of records:

```json
[
  {
    "domain": "*.example.com",
    "url": "https://*.example.com",
    "wildcard": true,
    "first_issued": "2020-01-01T00:00:00Z",
    "last_issued": "2025-01-01T00:00:00Z",
    "sources": {
      "crt.sh": {
        "first_issued": "2020-01-01T00:00:00Z",
        "last_issued": "2025-01-01T00:00:00Z"
      }
    },
    "missing_from": [],
    "failed_sources": []
  },
  {
    "domain": "www.example.com",
    "url": "https://www.example.com",
    "wildcard": false,
    "first_issued": "2021-01-01T00:00:00Z",
    "last_issued": "2025-01-01T00:00:00Z",
    "sources": {
      "crt.sh": {
        "first_issued": "2021-01-01T00:00:00Z",
        "last_issued": "2025-01-01T00:00:00Z"
      }
    },
    "missing_from": [],
    "failed_sources": []
  }
]
```

- `first_issued` and `last_issued` are the minimum and maximum certificate
  **validity start** values observed in the returned data. They
  approximate issuance, rather than recording exact signing or CT submission
  times. Timestamps use Jiff and are normalized to UTC, retaining fractional
  seconds when present.
- Names are normalized to lowercase ASCII (IDNs use Punycode), and restricted
  to the requested domains and their subdomains. Trailing DNS dots are removed;
  malformed hostnames and IP addresses are ignored.
- `sources` maps each backend that returned the identity to its own observed
  date range. The top-level dates span all those sources. `missing_from` lists
  successful backends that returned no match for that identity in this run.
  `failed_sources` lists selected backends that failed; their coverage is unknown,
  so they are never listed in `missing_from`. Unselected backends are omitted.
  Table output shows `SOURCES`, `MISSING_FROM`, and `FAILED_SOURCES` columns,
  using `-` for empty lists. URL/domain lists retain
  their plain format; use `--output FILE` to save source metadata alongside them.
- `*.example.com` and `example.com` remain separate records with separate date
  histories. Wildcards remain in table/JSON output; URL/domain lists omit them
  because a wildcard does not identify a concrete host.
- URLs use HTTPS as a candidate scheme. Certificate records do not establish
  DNS resolution, reachability, or an available web service. A wildcard URL is
  a pattern, not a request target. This tool discovers names; downstream tools
  discover paths.
- `--output FILE` always writes the full JSON array, regardless of the stdout
  format, and overwrites an existing file. No matches produce an empty array
  in JSON, an empty list in URL/domain formats, or just the table header.
- Results depend on the selected backend's available data and are not guaranteed
  to contain every certificate ever issued.
- Recoverable backend failures are reported as warnings on stderr. A nonzero
  exit status indicates that all backends failed, or that input/output failed.
  JSON stays an array; when successful sources return no matches, warnings on
  stderr still identify failed backends. `--timeout` sets the request timeout
  in seconds (default: 60).

## Backends

The CLI defaults to crt.sh. Select `crt.sh`, `censys` (certificate search), or
`censys-free` (HTTPS property and certificate lookups). Use a comma-separated
list such as `--backend crt.sh,censys-free`, or repeat the option
(`-b crt.sh -b censys-free`). `crtsh` is accepted as an alias for `crt.sh`.

The library's `discover` and `discover_many` functions also default to crt.sh.
Use `discover_with_backend` or `discover_many_with_backend` for a single custom
backend, or the plural `discover_with_backends` / `discover_many_with_backends`
functions to return `SourcedDomain` records with source coverage. Existing
single-backend library functions still return `DiscoveredDomain` records.
The plural functions tolerate individual backend failures; the single-backend
functions return an error if any input query fails. For error details alongside
successful results, use `discover_many_with_backends_report`, which returns a
`DiscoveryReport` containing `records` and `backend_errors`. This also preserves
failure details when successful backends return an empty set.

### Combining datasets

A union is useful for domain discovery: all backends normalize DNS identities
and use certificate validity starts, so exact normalized names can be merged.
Wildcard patterns remain distinct from concrete hosts. Results are a union of
**names**, not a comparison of individual certificates; matching names do not
mean both providers have the same certificates. Per-source date ranges preserve
differences in the histories each provider returned.

Coverage can differ because the providers collect and index different records.
[Censys's certificate dataset](https://docs.censys.com/docs/platform-certificate-dataset)
includes certificates seen in Internet scans as well as CT log submissions.
`missing_from` therefore means “not returned by this source for these queries,”
not proven absence from its complete dataset. The `censys-free` backend uses only
HTTPS property and certificate lookups, so its results cover the certificates
associated with the input hostnames rather than a domain-wide search. A missing
`censys-free` match can simply mean the identity was not on those certificates.
Backend errors indicate unknown coverage and appear in `failed_sources`,
separately from missing matches.

### crt.sh

The `CrtSh` implementation in `src/crtsh.rs` queries
`https://crt.sh/json?q=DOMAIN`, including historic and expired certificates.
It extracts names from newline-separated `name_value` identities and
`common_name`, and uses `not_before` for certificate validity starts. Its
HTTP requests use a 10-second connection timeout, bounded by the supplied
request timeout. crt.sh can be slow or temporarily unavailable; retry the
command if a request fails.

The provider-specific `crtsh::discover_from_json` helper parses crt.sh responses
for offline use and fixtures. It is also re-exported at the crate root.

### Censys

The `Censys` implementation in `src/censys.rs`, selected with `--backend censys`,
uses the [Censys Platform search API](https://docs.censys.com/reference/v3-globaldata-search-query).
It searches `cert.names` for the requested domain and its subdomains, requests
certificate names and `cert.parsed.validity_period.not_before`, and follows all
result pages. No expiration filter is applied, so results can include historic
and expired certificates.

This requires search API access; Free accounts should select `censys-free`.
Set `CENSYS_API_TOKEN` and, for an organization with search access,
`CENSYS_ORGANIZATION_ID`. Each search page may consume account credits.
The timeout covers every page of a domain query. HTTP failures, malformed data,
missing dates, repeated tokens, and truncated pagination fail that backend
rather than contributing incomplete results to the union.

### Censys Free

The `CensysFree` implementation in `src/censys.rs`, selected with
`--backend censys-free`, uses lookup endpoints available
to [Censys Free users](https://docs.censys.com/reference/get-started). It makes
up to two sequential requests per input hostname:

1. [Look up the web property](https://docs.censys.com/reference/v3-globaldata-asset-webproperty)
   identified by `DOMAIN:443`.
2. If that property has a certificate, [look up the certificate](https://docs.censys.com/reference/v3-globaldata-asset-certificate)
   by its SHA-256 fingerprint and extract its names and validity start.

Names are normalized and filtered to the requested domain and its subdomains,
then aggregated into the same output records as other backends. The backend
uses no search endpoints and makes no direct connections to the target website.
An absent web property (HTTP 404) or a property without a certificate produces
no matches. An unavailable referenced certificate, malformed response, or other
HTTP failure returns an error instead.

Lookup discovery has narrower coverage than certificate search: it sees only
the certificate currently recorded for each supplied hostname's HTTPS property.
It does not enumerate all subdomains, ports, or historic certificates, and it
does not recursively look up discovered names. A wildcard remains a wildcard;
it cannot reveal the concrete hosts behind it. Supply known subdomains as
additional inputs for more coverage. For historical discovery, use crt.sh
(the default) or combine it with `--backend crt.sh,censys-free`.

Supply a Platform Personal Access Token when constructing the backend. A Free
account is sufficient; an organization ID is optional. See
[Censys API access and authentication](https://docs.censys.com/reference/get-started).
Lookups still consume account credits. The timeout covers the entire domain
query, including both lookups. First/latest dates describe only the certificates
returned by these lookups; for one certificate they are the same validity start.

For the CLI, export `CENSYS_API_TOKEN` with your Platform Personal Access Token
and select `--backend censys-free` (or `--backend crt.sh,censys-free`). Optionally set
`CENSYS_ORGANIZATION_ID` to your organization UUID. Credentials are required only
when either Censys backend is selected. Missing or invalid credentials mark that
backend as failed while other selected backends can still contribute results.

Use the backend through the library API:

```rust
use std::time::Duration;
use certwalk::{CensysFree, discover_many_with_backend};

fn main() -> anyhow::Result<()> {
    let backend = CensysFree::new(std::env::var("CENSYS_API_TOKEN")?)?;
    let records = discover_many_with_backend(
        &backend,
        ["example.com", "example.org"],
        Duration::from_secs(60),
    )?;
    println!("{}", serde_json::to_string_pretty(&records)?);
    Ok(())
}
```

For an organization account, call `with_organization_id` with the organization
UUID after construction. This adds the `organization_id` query parameter to each
request. Without it, Censys selects the account's default wallet.

To combine sources through the library:

```rust
use std::time::Duration;
use certwalk::{CensysFree, CrtSh, discover_many_with_backends_report};

fn main() -> anyhow::Result<()> {
    let censys = CensysFree::new(std::env::var("CENSYS_API_TOKEN")?)?;
    let report = discover_many_with_backends_report(
        &[("crt.sh", &CrtSh), ("censys-free", &censys)],
        ["example.com", "example.org"],
        Duration::from_secs(60),
    )?;
    for (backend, error) in &report.backend_errors {
        eprintln!("warning: backend {backend} failed: {error}");
    }
    println!("{}", serde_json::to_string_pretty(&report.records)?);
    Ok(())
}
```

Backend names in the plural library APIs must be nonempty and unique. These
names identify sources in results, including custom backend implementations.
For paid search in these examples, construct `Censys` instead of `CensysFree`
and name its source `censys`.

## Development

```sh
cargo fmt --all -- --check
cargo build --locked --release
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
```

Tests use local fixtures and do not depend on external backend availability.

GitHub Actions runs these checks on pushes and pull requests, and also supports
manual runs. Dependabot checks Cargo dependencies and GitHub Actions weekly.

## Adding backends

Implement the public `CertificateTransparencyBackend` trait to return
`Vec<DiscoveredDomain>` from another certificate transparency source. The trait
defines normalization, DNS scope, deduplication, sorting, wildcard, and timestamp
requirements so each backend supplies the same output format.

Library callers can supply an implementation through `discover_with_backend`:

```rust
use std::time::Duration;
use certwalk::{CertificateTransparencyBackend, DiscoveredDomain, discover_with_backend};

fn discover_domains(
    backend: &dyn CertificateTransparencyBackend,
    domain: &str,
) -> anyhow::Result<Vec<DiscoveredDomain>> {
    discover_with_backend(backend, domain, Duration::from_secs(60))
}
```

Each backend handles its own requests, source schema, timestamp parsing, and
aggregation, returning the shared `DiscoveredDomain` model used by all output
formats.
