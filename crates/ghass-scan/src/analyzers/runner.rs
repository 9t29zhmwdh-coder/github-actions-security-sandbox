use ghass_core::models::{Finding, FindingType, Severity, WorkflowFile};

pub fn analyze(workflow: &WorkflowFile) -> Vec<Finding> {
    let mut findings = vec![];

    for job in &workflow.jobs {
        if job.runs_on.to_lowercase().contains("self-hosted") {
            findings.push(Finding {
                workflow: workflow.path.clone(),
                job_id: Some(job.id.clone()),
                step_name: None,
                finding_type: FindingType::SelfHostedRunner,
                severity: Severity::Medium,
                title: format!("Self-hosted runner in job '{}'", job.id),
                description: format!(
                    "Job '{}' runs on a self-hosted runner ({}). \
                     Self-hosted runners are persistent, reachable from within your network, \
                     and retain state between workflow runs. A compromised workflow can \
                     pivot to internal systems, read cached credentials, or tamper \
                     with build artifacts.",
                    job.id, job.runs_on
                ),
                evidence: format!("runs-on: {}", job.runs_on),
                remediation: "Run self-hosted runners in ephemeral containers \
                    to prevent state persistence between jobs. Isolate runners in a \
                    dedicated network segment. For workflows triggered by external \
                    contributors, prefer GitHub-hosted runners. \
                    Use Just-in-Time (JIT) runners where possible."
                    .to_string(),
                cwe: Some("CWE-653: Insufficient Isolation or Compartmentalization".to_string()),
            });
        }
    }

    findings
}
