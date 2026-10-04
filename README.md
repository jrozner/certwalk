# certwalk

A Rust 2024 CLI that discovers a domain and its subdomains from certificate
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

# Print the table and also save the complete results as JSON.
certwalk example.com --output domains.json

# Print JSON to stdout.
certwalk example.com --format json

# Write one concrete HTTPS URL per line, while retaining metadata in JSON.
certwalk example.com --format urls --output domains.json > urls.txt

# Emit bare concrete hostnames.
certwalk example.com --format domains > domains.txt

# Increase the request timeout for large queries (default: 60 seconds).
certwalk example.com --timeout 120
```

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
    "last_issued": "2025-01-01T00:00:00Z"
  },
  {
    "domain": "www.example.com",
    "url": "https://www.example.com",
    "wildcard": false,
    "first_issued": "2021-01-01T00:00:00Z",
    "last_issued": "2025-01-01T00:00:00Z"
  }
]
```

- `first_issued` and `last_issued` are the minimum and maximum certificate
  **validity start** values observed in the returned data. They
  approximate issuance, rather than recording exact signing or CT submission
  times. Timestamps use Jiff and are normalized to UTC, retaining fractional
  seconds when present.
- Names are normalized to lowercase ASCII (IDNs use Punycode), and restricted
  to the requested domain and its subdomains. Trailing DNS dots are removed;
  malformed hostnames and IP addresses are ignored.
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
- Backend and file errors are written to stderr and return a nonzero exit
  status. `--timeout` sets the request timeout in seconds (default: 60).

## Backends

The CLI and the library's `discover` function currently use crt.sh as the default
backend. Library callers can supply other implementations through
`discover_with_backend`; the CLI currently has no backend selection option.

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
