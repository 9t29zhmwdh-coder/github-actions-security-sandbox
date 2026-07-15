use ghass_core::models::{Finding, FindingType, Severity, WorkflowFile};

pub fn analyze(workflow: &WorkflowFile) -> Vec<Finding> {
    let mut findings = vec![];

    for job in &workflow.jobs {
        for step in &job.steps {
            findings.extend(check_secrets_to_third_party(workflow, job.id.as_str(), step));
            findings.extend(check_secret_in_run_env(workflow, job.id.as_str(), step));
        }
    }

    findings
}

fn check_secrets_to_third_party(
    workflow: &WorkflowFile,
    job_id: &str,
    step: &ghass_core::models::Step,
) -> Vec<Finding> {
    let mut findings = vec![];

    let Some(uses) = &step.uses else {
        return findings;
    };

    if is_first_party(uses) {
        return findings;
    }

    for (key, value) in &step.with {
        if value.contains("${{ secrets.") {
            findings.push(Finding {
                workflow: workflow.path.clone(),
                job_id: Some(job_id.to_string()),
                step_name: step.name.clone(),
                finding_type: FindingType::SecretExposure,
                severity: Severity::High,
                title: format!("Secret passed to third-party action: {}", uses),
                description: format!(
                    "Job '{}' passes a repository secret via parameter '{}' to third-party \
                     action '{}'. A compromised or malicious action version can exfiltrate \
                     the secret to an external endpoint.",
                    job_id, key, uses
                ),
                evidence: format!("with.{}: {}", key, value),
                remediation: format!(
                    "Pin '{}' to a verified commit SHA before passing secrets. \
                     Review the action source code at the pinned commit and consider \
                     whether a first-party alternative exists.",
                    uses
                ),
                cwe: Some("CWE-522: Insufficiently Protected Credentials".to_string()),
                line: step.line,
            });
        }
    }

    findings
}

fn check_secret_in_run_env(
    workflow: &WorkflowFile,
    job_id: &str,
    step: &ghass_core::models::Step,
) -> Vec<Finding> {
    let mut findings = vec![];

    if step.run.is_none() {
        return findings;
    }

    for (key, value) in &step.env {
        if value.contains("${{ secrets.") {
            findings.push(Finding {
                workflow: workflow.path.clone(),
                job_id: Some(job_id.to_string()),
                step_name: step.name.clone(),
                finding_type: FindingType::SecretExposure,
                severity: Severity::Informational,
                title: format!("Secret stored in environment variable: {}", key),
                description: format!(
                    "Job '{}' stores a secret in environment variable '{}' for use in a run \
                     step. This is the recommended pattern, but the secret must not be printed, \
                     echoed, or written to any log output.",
                    job_id, key
                ),
                evidence: format!("env.{}: {}", key, value),
                remediation: "Ensure the variable value is never echoed or printed. \
                    Use `echo '::add-mask::value'` to register additional values for masking \
                    if the secret is transformed before use."
                    .to_string(),
                cwe: Some("CWE-532: Insertion of Sensitive Information into Log File".to_string()),
                line: step.line,
            });
        }
    }

    findings
}

fn is_first_party(uses: &str) -> bool {
    uses.starts_with("actions/")
        || uses.starts_with("github/")
        || uses.starts_with("./")
        || uses.starts_with("../")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{job, uses_step, workflow_with};

    #[test]
    fn flags_secret_passed_to_third_party_action() {
        let mut step = uses_step("some-org/build-action@main");
        step.with = vec![(
            "api-key".to_string(),
            "${{ secrets.BUILD_API_KEY }}".to_string(),
        )];
        let wf = workflow_with(vec![job("build", vec![step])]);

        let findings = analyze(&wf);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].finding_type, FindingType::SecretExposure);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn does_not_flag_secret_passed_to_first_party_action() {
        let mut step = uses_step("actions/checkout@v4");
        step.with = vec![("token".to_string(), "${{ secrets.GITHUB_TOKEN }}".to_string())];
        let wf = workflow_with(vec![job("build", vec![step])]);

        assert!(analyze(&wf).is_empty());
    }

    #[test]
    fn does_not_flag_local_action() {
        let mut step = uses_step("./local-action");
        step.with = vec![("token".to_string(), "${{ secrets.GITHUB_TOKEN }}".to_string())];
        let wf = workflow_with(vec![job("build", vec![step])]);

        assert!(analyze(&wf).is_empty());
    }

    #[test]
    fn flags_multiple_secrets_in_a_single_step() {
        let mut step = uses_step("some-org/build-action@main");
        step.with = vec![
            ("api-key".to_string(), "${{ secrets.API_KEY }}".to_string()),
            ("token".to_string(), "${{ secrets.GITHUB_TOKEN }}".to_string()),
        ];
        let wf = workflow_with(vec![job("build", vec![step])]);

        assert_eq!(analyze(&wf).len(), 2);
    }

    #[test]
    fn flags_secret_stored_in_run_step_env_as_informational() {
        let mut step = crate::test_support::run_step("echo \"$API_KEY\"");
        step.env = vec![("API_KEY".to_string(), "${{ secrets.API_KEY }}".to_string())];
        let wf = workflow_with(vec![job("build", vec![step])]);

        let findings = analyze(&wf);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Informational);
    }

    #[test]
    fn does_not_flag_env_secret_without_a_run_script() {
        let mut step = uses_step("actions/checkout@v4");
        step.env = vec![("API_KEY".to_string(), "${{ secrets.API_KEY }}".to_string())];
        let wf = workflow_with(vec![job("build", vec![step])]);

        assert!(analyze(&wf).is_empty());
    }

    #[test]
    fn step_without_secrets_produces_no_finding() {
        let mut step = uses_step("some-org/build-action@main");
        step.with = vec![("ref".to_string(), "${{ github.sha }}".to_string())];
        let wf = workflow_with(vec![job("build", vec![step])]);

        assert!(analyze(&wf).is_empty());
    }
}
