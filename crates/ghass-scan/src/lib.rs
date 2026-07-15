pub mod analyzers;
mod line_index;
pub mod parser;
#[cfg(test)]
mod test_support;

use anyhow::Result;
use ghass_core::models::{Finding, FindingSummary, ScanReport, Severity};
use ghass_core::rules::RuleSet;
use std::path::Path;
use walkdir::WalkDir;

pub fn scan_path(path: &Path, custom_rules: Option<&RuleSet>) -> Result<ScanReport> {
    let workflows = collect_workflows(path)?;

    let mut findings: Vec<Finding> = workflows
        .iter()
        .flat_map(|wf| analyzers::run_all(wf, custom_rules))
        .collect();

    findings.sort_by_key(|f| std::cmp::Reverse(f.severity.score()));

    let summary = build_summary(&findings);

    Ok(ScanReport {
        scanned_at: chrono::Utc::now(),
        workflow_count: workflows.len(),
        finding_count: findings.len(),
        findings,
        summary,
    })
}

fn collect_workflows(path: &Path) -> Result<Vec<ghass_core::models::WorkflowFile>> {
    if path.is_file() {
        return Ok(vec![parser::parse_workflow_file(path)?]);
    }

    let mut workflows = vec![];
    for entry in WalkDir::new(path)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let p = entry.path();
        if p.is_file() {
            let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("");
            if ext == "yml" || ext == "yaml" {
                if let Ok(wf) = parser::parse_workflow_file(p) {
                    workflows.push(wf);
                }
            }
        }
    }
    Ok(workflows)
}

fn build_summary(findings: &[Finding]) -> FindingSummary {
    FindingSummary {
        critical_count: findings
            .iter()
            .filter(|f| f.severity == Severity::Critical)
            .count(),
        high_count: findings
            .iter()
            .filter(|f| f.severity == Severity::High)
            .count(),
        medium_count: findings
            .iter()
            .filter(|f| f.severity == Severity::Medium)
            .count(),
        low_count: findings
            .iter()
            .filter(|f| f.severity == Severity::Low)
            .count(),
        informational_count: findings
            .iter()
            .filter(|f| f.severity == Severity::Informational)
            .count(),
    }
}
