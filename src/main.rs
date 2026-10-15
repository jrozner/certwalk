use std::fs;
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, Result};
use certwalk::{
    Censys, CensysFree, CertificateTransparencyBackend, CrtSh, SourcedDomain,
    discover_many_with_backends_report, parse_domain,
};
use clap::{Parser, ValueEnum};

#[derive(Debug, Parser)]
#[command(
    version,
    about = "Discover domains and certificate history from certificate transparency data"
)]
struct Cli {
    /// Domains to search, including their subdomains (e.g. example.com example.org)
    #[arg(value_parser = parse_domain, required_unless_present = "input", num_args = 1..)]
    domains: Vec<String>,

    /// Read additional domains from a newline-separated file; use - for stdin
    #[arg(short, long, value_name = "FILE")]
    input: Option<PathBuf>,

    /// Backends to query; repeat this option or use a comma-separated list
    #[arg(
        short,
        long = "backend",
        value_enum,
        value_delimiter = ',',
        default_value = "crt.sh"
    )]
    backends: Vec<Backend>,

    /// Format for stdout; urls/domains omit wildcard identities
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Table)]
    format: OutputFormat,

    /// Also save the complete domain set as JSON to this file
    #[arg(short, long, value_name = "FILE")]
    output: Option<PathBuf>,

    /// HTTP request timeout in seconds for each backend/domain query
    #[arg(long, default_value_t = 60, value_parser = clap::value_parser!(u64).range(1..))]
    timeout: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum Backend {
    #[value(name = "crt.sh", alias = "crtsh")]
    CrtSh,
    Censys,
    CensysFree,
}

impl Backend {
    fn name(self) -> &'static str {
        match self {
            Self::CrtSh => "crt.sh",
            Self::Censys => "censys",
            Self::CensysFree => "censys-free",
        }
    }
}

type SelectedBackend = (Backend, Box<dyn CertificateTransparencyBackend>);

struct UnavailableBackend(String);

impl CertificateTransparencyBackend for UnavailableBackend {
    fn discover(
        &self,
        _domain: &str,
        _timeout: Duration,
    ) -> Result<Vec<certwalk::DiscoveredDomain>> {
        anyhow::bail!("{}", self.0)
    }
}

fn build_backend(
    selection: Backend,
    censys_token: Option<&str>,
    censys_organization_id: Option<&str>,
) -> Result<Box<dyn CertificateTransparencyBackend>> {
    if selection == Backend::CrtSh {
        return Ok(Box::new(CrtSh));
    }
    let token = censys_token.with_context(|| {
        format!(
            "set CENSYS_API_TOKEN to use the {} backend",
            selection.name()
        )
    })?;
    match selection {
        Backend::CrtSh => unreachable!(),
        Backend::Censys => {
            let mut backend = Censys::new(token).context("invalid CENSYS_API_TOKEN")?;
            if let Some(id) = censys_organization_id {
                backend = backend
                    .with_organization_id(id)
                    .context("invalid CENSYS_ORGANIZATION_ID")?;
            }
            Ok(Box::new(backend))
        }
        Backend::CensysFree => {
            let mut backend = CensysFree::new(token).context("invalid CENSYS_API_TOKEN")?;
            if let Some(id) = censys_organization_id {
                backend = backend
                    .with_organization_id(id)
                    .context("invalid CENSYS_ORGANIZATION_ID")?;
            }
            Ok(Box::new(backend))
        }
    }
}

fn build_backends(
    selected: &[Backend],
    mut build: impl FnMut(Backend) -> Result<Box<dyn CertificateTransparencyBackend>>,
) -> Vec<SelectedBackend> {
    let mut backends: Vec<SelectedBackend> = Vec::new();
    for selection in selected {
        if backends.iter().any(|(name, _)| name == selection) {
            continue;
        }
        let backend = build(*selection)
            .unwrap_or_else(|error| Box::new(UnavailableBackend(format!("{error:#}"))));
        backends.push((*selection, backend));
    }
    backends
}

fn optional_env(name: &str) -> Result<Option<String>> {
    match std::env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => {
            anyhow::bail!("{name} must contain valid Unicode")
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum OutputFormat {
    Table,
    Json,
    Urls,
    Domains,
}

fn write_output(
    mut writer: impl Write,
    format: OutputFormat,
    records: &[SourcedDomain],
) -> Result<()> {
    match format {
        OutputFormat::Table => {
            let width = records
                .iter()
                .map(|record| record.record.url.len())
                .max()
                .unwrap_or(3)
                .max(3);
            writeln!(
                writer,
                "{:<width$}  {:<8}  {:<32}  {:<32}  {:<25}  {:<25}  FAILED_SOURCES",
                "URL", "WILDCARD", "FIRST_ISSUED", "LAST_ISSUED", "SOURCES", "MISSING_FROM"
            )?;
            for record in records {
                writeln!(
                    writer,
                    "{:<width$}  {:<8}  {:<32}  {:<32}  {:<25}  {:<25}  {}",
                    record.record.url,
                    record.record.wildcard,
                    record.record.first_issued.to_string(),
                    record.record.last_issued.to_string(),
                    record
                        .sources
                        .keys()
                        .map(String::as_str)
                        .collect::<Vec<_>>()
                        .join(","),
                    if record.missing_from.is_empty() {
                        "-".into()
                    } else {
                        record.missing_from.join(",")
                    },
                    if record.failed_sources.is_empty() {
                        "-".into()
                    } else {
                        record.failed_sources.join(",")
                    }
                )?;
            }
        }
        OutputFormat::Json => {
            // Serialize before writing so broken pipes remain ordinary I/O errors.
            writer.write_all(&serde_json::to_vec_pretty(records)?)?;
            writeln!(writer)?;
        }
        OutputFormat::Urls | OutputFormat::Domains => {
            for record in records
                .iter()
                .map(|record| &record.record)
                .filter(|record| !record.wildcard)
            {
                let value = match format {
                    OutputFormat::Urls => &record.url,
                    _ => &record.domain,
                };
                writeln!(writer, "{value}")?;
            }
        }
    }
    writer.flush()?;
    Ok(())
}

fn run(cli: Cli) -> Result<()> {
    let mut domains = cli.domains;
    if let Some(path) = cli.input {
        let source = path.display().to_string();
        let additional = if path == std::path::Path::new("-") {
            read_domains(io::stdin().lock(), "stdin")?
        } else {
            let file = fs::File::open(&path).with_context(|| format!("could not open {source}"))?;
            read_domains(BufReader::new(file), &source)?
        };
        domains.extend(additional);
    }
    let backends = build_backends(&cli.backends, |selection| {
        if selection == Backend::CrtSh {
            return build_backend(selection, None, None);
        }
        let token = optional_env("CENSYS_API_TOKEN")?;
        let organization = optional_env("CENSYS_ORGANIZATION_ID")?;
        build_backend(selection, token.as_deref(), organization.as_deref())
    });
    let named_backends: Vec<_> = backends
        .iter()
        .map(|(name, backend)| (name.name(), backend.as_ref()))
        .collect();
    let report = discover_many_with_backends_report(
        &named_backends,
        &domains,
        Duration::from_secs(cli.timeout),
    )?;
    for (name, error) in &report.backend_errors {
        eprintln!("warning: backend {name} failed: {error}");
    }
    let records = report.records;
    if let Some(path) = cli.output {
        let mut json = serde_json::to_vec_pretty(&records)?;
        json.push(b'\n');
        fs::write(&path, json).with_context(|| format!("could not write {}", path.display()))?;
    }
    write_output(BufWriter::new(io::stdout().lock()), cli.format, &records)
        .context("could not write stdout")
}

fn read_domains(reader: impl BufRead, source: &str) -> Result<Vec<String>> {
    let mut domains = Vec::new();
    for (index, line) in reader.lines().enumerate() {
        let line = line.with_context(|| format!("could not read {source}:{}", index + 1))?;
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let domain = parse_domain(line)
            .map_err(anyhow::Error::msg)
            .with_context(|| format!("invalid domain at {source}:{}", index + 1))?;
        domains.push(domain);
    }
    Ok(domains)
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            if error.chain().any(|cause| {
                cause
                    .downcast_ref::<io::Error>()
                    .is_some_and(|error| error.kind() == io::ErrorKind::BrokenPipe)
            }) {
                return ExitCode::SUCCESS;
            }
            eprintln!("error: {error:#}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use certwalk::{CertificateHistory, DiscoveredDomain};
    use jiff::Timestamp;

    fn record(domain: &str, issued: Timestamp) -> SourcedDomain {
        SourcedDomain {
            record: DiscoveredDomain {
                domain: domain.into(),
                url: format!("https://{domain}"),
                wildcard: domain.starts_with("*."),
                first_issued: issued,
                last_issued: issued,
            },
            sources: [(
                "crt.sh".into(),
                CertificateHistory {
                    first_issued: issued,
                    last_issued: issued,
                },
            )]
            .into(),
            missing_from: vec![],
            failed_sources: vec![],
        }
    }

    fn records() -> Vec<SourcedDomain> {
        let issued = "2024-01-01T00:00:00Z".parse().unwrap();
        ["*.example.com", "example.com", "www.example.com"]
            .into_iter()
            .map(|domain| record(domain, issued))
            .collect()
    }

    #[test]
    fn json_output_retains_wildcards_and_timestamp_metadata() {
        let mut output = Vec::new();
        write_output(&mut output, OutputFormat::Json, &records()).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(json.as_array().unwrap().len(), 3);
        assert_eq!(json[0]["domain"], "*.example.com");
        assert_eq!(json[0]["wildcard"], true);
        assert_eq!(json[1]["first_issued"], "2024-01-01T00:00:00Z");
        assert_eq!(json[1]["last_issued"], "2024-01-01T00:00:00Z");
        assert_eq!(
            json[1]["sources"]["crt.sh"]["first_issued"],
            "2024-01-01T00:00:00Z"
        );
        assert_eq!(json[1]["missing_from"], serde_json::json!([]));
        assert_eq!(json[1]["failed_sources"], serde_json::json!([]));
        assert_eq!(output.last(), Some(&b'\n'));
    }

    #[test]
    fn json_and_table_output_preserve_fractional_seconds_in_utc() {
        let records = [record(
            "example.com",
            "2024-01-01T01:00:00.123456789+01:00".parse().unwrap(),
        )];
        let mut json = Vec::new();
        write_output(&mut json, OutputFormat::Json, &records).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&json).unwrap();
        let expected = "2024-01-01T00:00:00.123456789Z";
        assert_eq!(json[0]["first_issued"], expected);
        assert_eq!(json[0]["last_issued"], expected);
        let mut table = Vec::new();
        write_output(&mut table, OutputFormat::Table, &records).unwrap();
        assert_eq!(
            String::from_utf8(table).unwrap().matches(expected).count(),
            2
        );
    }

    #[test]
    fn target_lists_omit_wildcards_without_inventing_hosts() {
        let mut urls = Vec::new();
        write_output(&mut urls, OutputFormat::Urls, &records()).unwrap();
        assert_eq!(
            String::from_utf8(urls).unwrap(),
            "https://example.com\nhttps://www.example.com\n"
        );
        let mut domains = Vec::new();
        write_output(&mut domains, OutputFormat::Domains, &records()).unwrap();
        assert_eq!(
            String::from_utf8(domains).unwrap(),
            "example.com\nwww.example.com\n"
        );
    }

    #[test]
    fn table_contains_all_requested_fields_and_empty_json_is_an_array() {
        let mut table = Vec::new();
        write_output(&mut table, OutputFormat::Table, &records()).unwrap();
        let table = String::from_utf8(table).unwrap();
        assert!(table.contains("WILDCARD"));
        assert!(table.contains("FIRST_ISSUED"));
        assert!(table.contains("LAST_ISSUED"));
        assert!(table.contains("SOURCES"));
        assert!(table.contains("MISSING_FROM"));
        assert!(table.contains("FAILED_SOURCES"));
        assert!(table.contains("https://*.example.com"));
        let mut empty = Vec::new();
        write_output(&mut empty, OutputFormat::Json, &[]).unwrap();
        assert_eq!(empty, b"[]\n");
    }

    #[test]
    fn clap_validates_input_and_parses_output_options() {
        let cli = Cli::try_parse_from([
            "certwalk",
            "EXAMPLE.com.",
            "--format",
            "urls",
            "-o",
            "domains.json",
        ])
        .unwrap();
        assert_eq!(cli.domains, ["example.com"]);
        assert!(matches!(cli.format, OutputFormat::Urls));
        assert_eq!(cli.output, Some(PathBuf::from("domains.json")));
        assert!(Cli::try_parse_from(["certwalk", "example.com", "--timeout", "0"]).is_err());
        assert!(Cli::try_parse_from(["certwalk", "https://example.com"]).is_err());
        assert!(Cli::try_parse_from(["certwalk"]).is_err());
    }

    #[test]
    fn clap_defaults_to_crtsh_and_accepts_repeated_or_comma_separated_backends() {
        let cli = Cli::try_parse_from(["certwalk", "example.com"]).unwrap();
        assert_eq!(cli.backends, [Backend::CrtSh]);
        let cli = Cli::try_parse_from(["certwalk", "example.com", "--backend", "censys"]).unwrap();
        assert_eq!(cli.backends, [Backend::Censys]);
        let cli =
            Cli::try_parse_from(["certwalk", "example.com", "-b", "crt.sh,censys,censys-free"])
                .unwrap();
        assert_eq!(
            cli.backends,
            [Backend::CrtSh, Backend::Censys, Backend::CensysFree]
        );
        for arguments in [
            vec!["--backend", "crt.sh,censys"],
            vec!["-b", "crt.sh", "--backend", "censys"],
        ] {
            let cli = Cli::try_parse_from(["certwalk", "example.com"].into_iter().chain(arguments))
                .unwrap();
            assert_eq!(cli.backends, [Backend::CrtSh, Backend::Censys]);
        }
        assert_eq!(
            Cli::try_parse_from(["certwalk", "example.com", "-b", "crtsh"])
                .unwrap()
                .backends,
            [Backend::CrtSh]
        );
        assert!(Cli::try_parse_from(["certwalk", "example.com", "-b", "unknown"]).is_err());
    }

    #[test]
    fn backend_setup_deduplicates_selections_and_requires_credentials_only_for_censys() {
        let backends = build_backends(&[Backend::CrtSh, Backend::CrtSh], |selection| {
            build_backend(selection, Some("invalid\ntoken"), Some("bad-id"))
        });
        assert_eq!(backends.len(), 1);
        let error = build_backend(Backend::Censys, None, None).err().unwrap();
        assert!(error.to_string().contains("CENSYS_API_TOKEN"));
        for token in ["", "  ", "invalid\ntoken"] {
            assert!(build_backend(Backend::Censys, Some(token), None).is_err());
            assert!(build_backend(Backend::CensysFree, Some(token), None).is_err());
        }
        assert!(build_backend(Backend::Censys, Some("fixture-token"), Some("bad-id")).is_err());
        assert!(build_backend(Backend::CensysFree, Some("fixture-token"), Some("bad-id")).is_err());
        let backends = build_backends(
            &[Backend::Censys, Backend::CrtSh, Backend::Censys],
            |selection| {
                build_backend(
                    selection,
                    Some("fixture-token"),
                    Some("11111111-2222-3333-4444-555555555555"),
                )
            },
        );
        assert_eq!(
            backends.iter().map(|(name, _)| *name).collect::<Vec<_>>(),
            [Backend::Censys, Backend::CrtSh]
        );
    }

    #[test]
    fn table_shows_present_and_missing_sources() {
        let mut records = records();
        records[1].missing_from.push("censys".into());
        records[1].failed_sources.push("censys-free".into());
        let mut table = Vec::new();
        write_output(&mut table, OutputFormat::Table, &records).unwrap();
        let table = String::from_utf8(table).unwrap();
        let row = table
            .lines()
            .find(|line| line.starts_with("https://example.com "))
            .unwrap();
        assert!(row.contains("crt.sh"));
        assert!(row.split_whitespace().any(|value| value == "censys"));
        assert!(row.ends_with("censys-free"));
        let mut json = Vec::new();
        write_output(&mut json, OutputFormat::Json, &records).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&json).unwrap();
        assert_eq!(json[1]["missing_from"], serde_json::json!(["censys"]));
        assert_eq!(
            json[1]["failed_sources"],
            serde_json::json!(["censys-free"])
        );
    }

    #[test]
    fn missing_credentials_do_not_prevent_other_backends_from_being_built() {
        let backends = build_backends(
            &[Backend::Censys, Backend::CrtSh, Backend::CensysFree],
            |selection| build_backend(selection, None, None),
        );
        assert_eq!(backends.len(), 3);
        for (selection, backend) in backends
            .iter()
            .filter(|(selection, _)| *selection != Backend::CrtSh)
        {
            let error = backend
                .discover("example.com", Duration::from_secs(1))
                .unwrap_err();
            assert!(error.to_string().contains("CENSYS_API_TOKEN"));
            assert!(error.to_string().contains(selection.name()));
        }
    }

    #[test]
    fn clap_accepts_multiple_domains_files_stdin_and_combined_inputs() {
        let cli = Cli::try_parse_from(["certwalk", "example.com", "EXAMPLE.org."]).unwrap();
        assert_eq!(cli.domains, ["example.com", "example.org"]);
        for source in ["targets.txt", "-"] {
            let cli = Cli::try_parse_from(["certwalk", "--input", source]).unwrap();
            assert!(cli.domains.is_empty());
            assert_eq!(cli.input, Some(PathBuf::from(source)));
        }
        let cli = Cli::try_parse_from([
            "certwalk",
            "example.com",
            "example.org",
            "-i",
            "targets.txt",
        ])
        .unwrap();
        assert_eq!(cli.domains, ["example.com", "example.org"]);
        assert_eq!(cli.input, Some(PathBuf::from("targets.txt")));
        assert!(Cli::try_parse_from(["certwalk", "--input"]).is_err());
    }

    #[test]
    fn line_input_accepts_crlf_whitespace_comments_and_normalized_domains() {
        let input = "# targets\r\n  EXAMPLE.com.  \r\n\n *.example.org\n bücher.example\n";
        let domains = read_domains(input.as_bytes(), "targets.txt").unwrap();
        assert_eq!(
            domains,
            ["example.com", "example.org", "xn--bcher-kva.example"]
        );
        assert!(
            read_domains(b"\n# only comments\n".as_slice(), "stdin")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn line_input_errors_include_the_source_and_line_number() {
        let error = read_domains(
            b"example.com\n# comment\nhttps://example.org\n".as_slice(),
            "targets.txt",
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("targets.txt:3"));
        assert!(format!("{error:#}").contains("expected a DNS domain"));
        let error = read_domains(b"example.com\n\xff\n".as_slice(), "stdin").unwrap_err();
        assert!(format!("{error:#}").contains("stdin:2"));
    }
}
