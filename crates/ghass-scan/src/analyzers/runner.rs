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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{job, workflow_with};

    fn job_with_runner(runs_on: &str) -> ghass_core::models::Job {
        let mut j = job("build", vec![]);
        j.runs_on = runs_on.to_string();
        j
    }

    #[test]
    fn flags_self_hosted_runner() {
        let wf = workflow_with(vec![job_with_runner("self-hosted")]);

        let findings = analyze(&wf);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].finding_type, FindingType::SelfHostedRunner);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn flags_self_hosted_case_insensitively() {
        let wf = workflow_with(vec![job_with_runner("Self-Hosted")]);

        assert_eq!(analyze(&wf).len(), 1);
    }

    #[test]
    fn flags_self_hosted_with_extra_labels() {
        let wf = workflow_with(vec![job_with_runner("[self-hosted, linux, x64]")]);

        assert_eq!(analyze(&wf).len(), 1);
    }

    #[test]
    fn does_not_flag_github_hosted_runner() {
        let wf = workflow_with(vec![job_with_runner("ubuntu-latest")]);

        assert!(analyze(&wf).is_empty());
    }

    #[test]
    fn multiple_jobs_are_each_evaluated() {
        let wf = workflow_with(vec![
            job_with_runner("self-hosted"),
            job_with_runner("windows-latest"),
        ]);

        assert_eq!(analyze(&wf).len(), 1);
    }
}
