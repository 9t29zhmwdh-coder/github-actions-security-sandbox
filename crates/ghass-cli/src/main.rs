use anyhow::Result;
use clap::{Parser, Subcommand};
use ghass_core::{models::Severity, report};
use std::path::PathBuf;
use tabled::{Table, Tabled};

#[derive(Parser)]
#[command(
    name = "ghass",
    version = "0.1.0",
    author = "RayStudio",
    about = "GitHub Actions Security Sandbox Simulator: static workflow analysis and attack simulation"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Scan {
        #[arg(help = "Path to a workflow file or directory to scan")]
        path: PathBuf,
        #[arg(long, default_value = "table", help = "Output format: table, json, md, html, sarif")]
        format: String,
        #[arg(long, help = "Write output to FILE instead of stdout")]
        output: Option<PathBuf>,
        #[arg(long, default_value = "low", help = "Minimum severity: critical, high, medium, low, info")]
        min_severity: String,
    },
}

#[derive(Tabled)]
struct FindingRow {
    #[tabled(rename = "Severity")]
    severity: String,
    #[tabled(rename = "Type")]
    finding_type: String,
    #[tabled(rename = "Job")]
    job: String,
    #[tabled(rename = "Title")]
    title: String,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Scan {
            path,
            format,
            output,
            min_severity,
        } => {
            let mut scan = ghass_scan::scan_path(&path)?;

            let min_score = parse_severity_score(&min_severity);
            scan.findings.retain(|f| f.severity.score() >= min_score);
            scan.finding_count = scan.findings.len();
            rebuild_summary(&mut scan);

            eprintln!(
                "Scanned {} workflow(s). Found {} finding(s) at {} and above.",
                scan.workflow_count, scan.finding_count, min_severity
            );

            let content = match format.as_str() {
                "json" => report::to_json(&scan)?,
                "md" => report::to_markdown(&scan),
                "html" => report::to_html_stub(&scan),
                "sarif" => report::to_sarif_stub(&scan),
                _ => render_table(&scan),
            };

            match output {
                Some(out) => {
                    std::fs::write(&out, &content)?;
                    eprintln!("Report written to {}", out.display());
                }
                None => println!("{}", content),
            }
        }
    }

    Ok(())
}

fn render_table(scan: &ghass_core::models::ScanReport) -> String {
    if scan.findings.is_empty() {
        return "No findings at or above the minimum severity threshold.".to_string();
    }
    let rows: Vec<FindingRow> = scan
        .findings
        .iter()
        .map(|f| FindingRow {
            severity: f.severity.to_string(),
            finding_type: f.finding_type.to_string(),
            job: f.job_id.clone().unwrap_or_else(|| "-".to_string()),
            title: f.title.clone(),
        })
        .collect();
    Table::new(rows).to_string()
}

fn rebuild_summary(scan: &mut ghass_core::models::ScanReport) {
    scan.summary.critical_count = scan
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Critical)
        .count();
    scan.summary.high_count = scan
        .findings
        .iter()
        .filter(|f| f.severity == Severity::High)
        .count();
    scan.summary.medium_count = scan
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Medium)
        .count();
    scan.summary.low_count = scan
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Low)
        .count();
    scan.summary.informational_count = scan
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Informational)
        .count();
}

fn parse_severity_score(s: &str) -> u8 {
    match s.to_lowercase().as_str() {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "info" | "informational" => 0,
        _ => 1,
    }
}
