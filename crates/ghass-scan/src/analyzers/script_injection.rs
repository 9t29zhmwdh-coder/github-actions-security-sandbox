use ghass_core::models::{Finding, FindingType, Severity, WorkflowFile};

const KNOWN_INJECTION_PATTERNS: &[&str] = &[
    "${{ github.event.issue.title }}",
    "${{ github.event.issue.body }}",
    "${{ github.event.pull_request.title }}",
    "${{ github.event.pull_request.body }}",
    "${{ github.event.comment.body }}",
    "${{ github.event.discussion.title }}",
    "${{ github.event.discussion.body }}",
    "${{ github.head_ref }}",
];

const INJECTION_PREFIXES: &[&str] = &[
    "${{ github.event.",
    "${{ inputs.",
];

pub fn analyze(workflow: &WorkflowFile) -> Vec<Finding> {
    let mut findings = vec![];

    for job in &workflow.jobs {
        for step in &job.steps {
            if let Some(run_script) = &step.run {
                let evidence = find_injection_evidence(run_script);
                if !evidence.is_empty() {
                    findings.push(Finding {
                        workflow: workflow.path.clone(),
                        job_id: Some(job.id.clone()),
                        step_name: step.name.clone(),
                        finding_type: FindingType::ScriptInjection,
                        severity: Severity::Critical,
                        title: "Script injection via untrusted context expression".to_string(),
                        description: format!(
                            "Job '{}' interpolates untrusted GitHub context data directly into a run \
                             step. An attacker who controls the trigger input (issue title, PR body, \
                             comment) can inject arbitrary shell commands that execute with full \
                             GITHUB_TOKEN permissions.",
                            job.id
                        ),
                        evidence: evidence.join(", "),
                        remediation: "Store the context expression in an intermediate environment \
                            variable and reference the variable in the shell command. \
                            Example: set `env: PR_TITLE: ${{ github.event.pull_request.title }}` \
                            and use `$PR_TITLE` in the run step instead."
                            .to_string(),
                        cwe: Some("CWE-78: OS Command Injection".to_string()),
                    });
                }
            }
        }
    }

    findings
}

fn find_injection_evidence(script: &str) -> Vec<String> {
    let mut found: Vec<String> = KNOWN_INJECTION_PATTERNS
        .iter()
        .filter(|p| script.contains(*p))
        .map(|p| p.to_string())
        .collect();

    if found.is_empty() {
        for prefix in INJECTION_PREFIXES {
            if script.contains(prefix) {
                found.push(format!("{}...}}", prefix));
                break;
            }
        }
    }

    found
}
