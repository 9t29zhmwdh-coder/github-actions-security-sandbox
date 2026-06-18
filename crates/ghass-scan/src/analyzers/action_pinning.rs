use ghass_core::models::{Finding, FindingType, Severity, WorkflowFile};

pub fn analyze(workflow: &WorkflowFile) -> Vec<Finding> {
    let mut findings = vec![];

    for job in &workflow.jobs {
        for step in &job.steps {
            if let Some(uses) = &step.uses {
                if let Some(finding) =
                    check_pinning(&workflow.path, &job.id, step.name.as_deref(), uses)
                {
                    findings.push(finding);
                }
            }
        }
    }

    findings
}

fn check_pinning(
    workflow_path: &str,
    job_id: &str,
    step_name: Option<&str>,
    uses: &str,
) -> Option<Finding> {
    if uses.starts_with("./") || uses.starts_with("../") {
        return None;
    }
    if uses.contains("/.github/workflows/") {
        return None;
    }

    let at_pos = uses.rfind('@')?;
    let action_ref = &uses[..at_pos];
    let version = &uses[at_pos + 1..];

    if version.len() == 40 && version.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }

    let (severity, description) = if matches!(version, "main" | "master" | "latest") {
        (
            Severity::High,
            format!(
                "Action '{}' is pinned to mutable branch '{}'. \
                 A compromised upstream repository or tag move can inject arbitrary code \
                 into your workflow without notice.",
                uses, version
            ),
        )
    } else {
        (
            Severity::Medium,
            format!(
                "Action '{}' uses semantic version tag '{}'. \
                 Tags are mutable and can be reassigned by the action author. \
                 Pin to a full 40-character commit SHA for reproducible builds.",
                uses, version
            ),
        )
    };

    Some(Finding {
        workflow: workflow_path.to_string(),
        job_id: Some(job_id.to_string()),
        step_name: step_name.map(String::from),
        finding_type: FindingType::UnpinnedAction,
        severity,
        title: format!("Action not pinned to a commit SHA: {}", uses),
        description,
        evidence: uses.to_string(),
        remediation: format!(
            "Replace with a SHA-pinned reference: `uses: {}@<40-hex-SHA>  # was: {}`",
            action_ref, version
        ),
        cwe: Some(
            "CWE-829: Inclusion of Functionality from Untrusted Control Sphere".to_string(),
        ),
    })
}
