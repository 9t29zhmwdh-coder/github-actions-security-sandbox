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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{job, run_step, workflow_with};

    #[test]
    fn flags_known_pattern_in_run_step() {
        let wf = workflow_with(vec![job(
            "build",
            vec![run_step(
                "echo ${{ github.event.pull_request.title }}",
            )],
        )]);

        let findings = analyze(&wf);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].finding_type, FindingType::ScriptInjection);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(
            findings[0].evidence,
            "${{ github.event.pull_request.title }}"
        );
    }

    #[test]
    fn flags_generic_event_prefix_when_no_known_pattern_matches() {
        let wf = workflow_with(vec![job(
            "build",
            vec![run_step("echo ${{ github.event.review.body }}")],
        )]);

        let findings = analyze(&wf);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].evidence, "${{ github.event....}");
    }

    #[test]
    fn flags_inputs_prefix() {
        let wf = workflow_with(vec![job(
            "build",
            vec![run_step("echo ${{ inputs.untrusted }}")],
        )]);

        let findings = analyze(&wf);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].evidence, "${{ inputs....}");
    }

    #[test]
    fn safe_workflow_using_intermediate_env_var_is_not_flagged() {
        let mut step = run_step("echo \"$PR_TITLE\"");
        step.env = vec![(
            "PR_TITLE".to_string(),
            "${{ github.event.pull_request.title }}".to_string(),
        )];
        let wf = workflow_with(vec![job("build", vec![step])]);

        // env values are not scanned by this analyzer, only the run script text.
        let findings = analyze(&wf);

        assert!(findings.is_empty());
    }

    #[test]
    fn step_without_run_script_is_ignored() {
        let wf = workflow_with(vec![job(
            "build",
            vec![crate::test_support::uses_step("actions/checkout@v4")],
        )]);

        assert!(analyze(&wf).is_empty());
    }

    #[test]
    fn clean_run_script_produces_no_finding() {
        let wf = workflow_with(vec![job("build", vec![run_step("echo hello")])]);

        assert!(analyze(&wf).is_empty());
    }
}
