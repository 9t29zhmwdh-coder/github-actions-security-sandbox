use ghass_core::models::FindingType;
use std::path::PathBuf;

fn example_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples")
        .join(name)
}

#[test]
fn hardened_workflow_produces_no_findings() {
    let report = ghass_scan::scan_path(&example_path("hardened_workflow.yml"), None).unwrap();

    assert_eq!(
        report.finding_count, 0,
        "expected the hardened example to be clean, got: {:?}",
        report.findings
    );
}

#[test]
fn vulnerable_workflow_produces_all_documented_finding_types() {
    let report = ghass_scan::scan_path(&example_path("vulnerable_workflow.yml"), None).unwrap();

    let types: Vec<&FindingType> = report.findings.iter().map(|f| &f.finding_type).collect();

    assert!(types.contains(&&FindingType::ScriptInjection));
    assert!(types.contains(&&FindingType::PwnRequest));
    assert!(types.contains(&&FindingType::ExcessivePermissions));
    assert!(types.contains(&&FindingType::SecretExposure));
    assert!(types.contains(&&FindingType::UnpinnedAction));
    assert!(types.contains(&&FindingType::SelfHostedRunner));
    assert_eq!(report.summary.critical_count, 2);
    assert_eq!(report.finding_count, 8);
}
