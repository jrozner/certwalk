use std::fs;
use std::io::{self, BufWriter, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, Result};
use certwalk::{DiscoveredDomain, discover, parse_domain};
use clap::{Parser, ValueEnum};

#[derive(Debug, Parser)]
#[command(
    version,
    about = "Discover domains and certificate history from certificate transparency data"
)]
struct Cli {
    /// Domain to search, including its subdomains (e.g. example.com)
    #[arg(value_parser = parse_domain)]
    domain: String,

    /// Format for stdout; urls/domains omit wildcard identities
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Table)]
    format: OutputFormat,

    /// Also save the complete domain set as JSON to this file
    #[arg(short, long, value_name = "FILE")]
    output: Option<PathBuf>,

    /// HTTP request timeout in seconds
    #[arg(long, default_value_t = 60, value_parser = clap::value_parser!(u64).range(1..))]
    timeout: u64,
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
    records: &[DiscoveredDomain],
) -> Result<()> {
    match format {
        OutputFormat::Table => {
            let width = records
                .iter()
                .map(|record| record.url.len())
                .max()
                .unwrap_or(3)
                .max(3);
            writeln!(
                writer,
                "{:<width$}  {:<8}  {:<32}  LAST_ISSUED",
                "URL", "WILDCARD", "FIRST_ISSUED"
            )?;
            for record in records {
                writeln!(
                    writer,
                    "{:<width$}  {:<8}  {:<32}  {}",
                    record.url,
                    record.wildcard,
                    record.first_issued.to_string(),
                    record.last_issued
                )?;
            }
        }
        OutputFormat::Json => {
            // Serialize before writing so broken pipes remain ordinary I/O errors.
            writer.write_all(&serde_json::to_vec_pretty(records)?)?;
            writeln!(writer)?;
        }
        OutputFormat::Urls | OutputFormat::Domains => {
            for record in records.iter().filter(|record| !record.wildcard) {
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
    let records = discover(&cli.domain, Duration::from_secs(cli.timeout))?;
    if let Some(path) = cli.output {
        let mut json = serde_json::to_vec_pretty(&records)?;
        json.push(b'\n');
        fs::write(&path, json).with_context(|| format!("could not write {}", path.display()))?;
    }
    write_output(BufWriter::new(io::stdout().lock()), cli.format, &records)
        .context("could not write stdout")
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
    use jiff::Timestamp;

    fn record(domain: &str, issued: Timestamp) -> DiscoveredDomain {
        DiscoveredDomain {
            domain: domain.into(),
            url: format!("https://{domain}"),
            wildcard: domain.starts_with("*."),
            first_issued: issued,
            last_issued: issued,
        }
    }

    fn records() -> Vec<DiscoveredDomain> {
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
        assert_eq!(cli.domain, "example.com");
        assert!(matches!(cli.format, OutputFormat::Urls));
        assert_eq!(cli.output, Some(PathBuf::from("domains.json")));
        assert!(Cli::try_parse_from(["certwalk", "example.com", "--timeout", "0"]).is_err());
        assert!(Cli::try_parse_from(["certwalk", "https://example.com"]).is_err());
        assert!(Cli::try_parse_from(["certwalk"]).is_err());
    }
}
