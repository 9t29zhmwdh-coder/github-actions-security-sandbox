use ghass_core::models::{Finding, FindingType, Severity, WorkflowFile};

/// Neither the workflow nor a job declares permissions: the token gets the
/// repository default, which is read/write in older repositories and organisations.
fn detect_missing_permissions(workflow: &WorkflowFile) -> Vec<Finding> {
    if workflow.global_permissions.is_some() {
        return vec![];
    }
    workflow.jobs.iter()
        .filter(|job| job.permissions.is_none() && !job.is_reusable_call)
        .map(|job| Finding {
            workflow: workflow.path.clone(),
            job_id: Some(job.id.clone()),
            step_name: None,
            finding_type: FindingType::ExcessivePermissions,
            severity: Severity::Low,
            title: format!("No permissions declared for job '{}'", job.id),
            description: "Without a `permissions:` block the GITHUB_TOKEN gets the repository \
                default, which is read/write in repositories created before February 2023 and \
                wherever an organisation keeps that setting."
                .to_string(),
            evidence: format!("jobs.{}: no permissions, no workflow-level permissions", job.id),
            remediation: "Add `permissions: contents: read` at the top of the workflow and \
                widen it per job where needed."
                .to_string(),
            cwe: Some("CWE-250: Execution with Unnecessary Privileges".to_string()),
            line: job.line,
        })
        .collect()
}

pub fn analyze(workflow: &WorkflowFile) -> Vec<Finding> {
    let mut findings = vec![];

    findings.extend(detect_pwn_request(workflow));
    findings.extend(detect_global_write_permissions(workflow));
    findings.extend(detect_job_write_all(workflow));
    findings.extend(detect_missing_permissions(workflow));

    findings
}

fn detect_pwn_request(workflow: &WorkflowFile) -> Vec<Finding> {
    let mut findings = vec![];

    if !workflow.triggers.iter().any(|t| t == "pull_request_target") {
        return findings;
    }

    for job in &workflow.jobs {
        for step in &job.steps {
            if let Some(uses) = &step.uses {
                if uses.starts_with("actions/checkout") {
                    let pr_head_ref = step.with.iter().find(|(k, v)| k == "ref" && is_pr_code_ref(v));

                    if let Some((_, ref_value)) = pr_head_ref {
                        findings.push(Finding {
                            workflow: workflow.path.clone(),
                            job_id: Some(job.id.clone()),
                            step_name: step.name.clone(),
                            finding_type: FindingType::PwnRequest,
                            severity: Severity::Critical,
                            title: "Pwn Request: pull_request_target checks out the pull request's code"
                                .to_string(),
                            description: format!(
                                "Workflow is triggered by 'pull_request_target' and job '{}' checks \
                                 out the PR contributor's code. The untrusted code runs with full \
                                 write permissions and access to all repository secrets. \
                                 This is the classic Pwn Request attack vector.",
                                job.id
                            ),
                            evidence: format!(
                                "trigger=pull_request_target, checkout ref={}",
                                ref_value
                            ),
                            remediation: "Never check out PR head code in pull_request_target \
                                workflows. Use a two-workflow pattern: a pull_request workflow \
                                runs the untrusted code with no secrets; a separate \
                                pull_request_target workflow handles write operations after \
                                downloading artifacts from the first run."
                                .to_string(),
                            cwe: Some(
                                "CWE-913: Improper Control of Dynamically-Managed Code Resources"
                                    .to_string(),
                            ),
                            line: step.line,
                        });
                    }
                }
            }
        }
    }

    // `gh pr checkout` or fetching `pull/N/head` in a run step does the same.
    for job in &workflow.jobs {
        for step in &job.steps {
            let Some(run) = &step.run else { continue };
            if !(run.contains("gh pr checkout") || run.contains("refs/pull/")
                || (run.contains("git fetch") && run.contains("pull/")))
            {
                continue;
            }
            findings.push(Finding {
                workflow: workflow.path.clone(),
                job_id: Some(job.id.clone()),
                step_name: step.name.clone(),
                finding_type: FindingType::PwnRequest,
                severity: Severity::Critical,
                title: "Pwn Request: pull_request_target fetches PR code in a run step".to_string(),
                description: format!(
                    "Workflow is triggered by 'pull_request_target' and job '{}' fetches the \
                     contributor's code with a shell command. Whatever runs afterwards executes \
                     their code with write permissions and access to the repository secrets.",
                    job.id
                ),
                evidence: run.lines().find(|l| l.contains("pull") || l.contains("pr checkout")).unwrap_or(run).trim().to_string(),
                remediation: "Run untrusted code only in a `pull_request` workflow without secrets."
                    .to_string(),
                cwe: Some("CWE-913: Improper Control of Dynamically-Managed Code Resources".to_string()),
                line: step.line,
            });
        }
    }

    findings
}

/// A checkout ref that points at the contributor's code: the head branch or
/// SHA, the PR number, or GitHub's merge ref `refs/pull/N/merge`.
fn is_pr_code_ref(value: &str) -> bool {
    ["github.event.pull_request.head", "github.head_ref", "refs/pull/",
     "github.event.pull_request.number", "github.event.number", "merge_commit_sha"]
        .iter()
        .any(|needle| value.contains(needle))
}

fn detect_global_write_permissions(workflow: &WorkflowFile) -> Vec<Finding> {
    let mut findings = vec![];

    let Some(perms) = &workflow.global_permissions else {
        return findings;
    };

    if perms.write_all {
        findings.push(Finding {
            workflow: workflow.path.clone(),
            job_id: None,
            step_name: None,
            finding_type: FindingType::ExcessivePermissions,
            severity: Severity::High,
            title: "Workflow-level permission: write-all".to_string(),
            description: "The workflow grants write access to all scopes at the top level. \
                All jobs inherit these permissions, including jobs that do not require write access."
                .to_string(),
            evidence: "permissions: write-all".to_string(),
            remediation: "Apply the principle of least privilege. Set \
                `permissions: {}` at the workflow level to deny all by default, \
                then grant only the specific permissions each job requires."
                .to_string(),
            cwe: Some("CWE-250: Execution with Unnecessary Privileges".to_string()),
            line: None,
        });
    }

    if perms.contents.as_deref() == Some("write") {
        findings.push(Finding {
            workflow: workflow.path.clone(),
            job_id: None,
            step_name: None,
            finding_type: FindingType::ExcessivePermissions,
            severity: Severity::High,
            title: "Workflow-level permission: contents write".to_string(),
            description: "The workflow grants write access to repository contents at the \
                workflow level. All jobs can push commits, create tags, and modify releases."
                .to_string(),
            evidence: "permissions.contents: write".to_string(),
            remediation: "Move contents write permission to the specific job that requires it \
                and set it to read at the workflow level."
                .to_string(),
            cwe: Some("CWE-250: Execution with Unnecessary Privileges".to_string()),
            line: None,
        });
    }

    if perms.pull_requests.as_deref() == Some("write") {
        findings.push(Finding {
            workflow: workflow.path.clone(),
            job_id: None,
            step_name: None,
            finding_type: FindingType::ExcessivePermissions,
            severity: Severity::Medium,
            title: "Workflow-level permission: pull-requests write".to_string(),
            description:
                "The workflow grants write access to pull requests at the workflow level."
                    .to_string(),
            evidence: "permissions.pull-requests: write".to_string(),
            remediation: "Scope pull-requests write to the specific job that posts comments \
                or labels."
                .to_string(),
            cwe: Some("CWE-250: Execution with Unnecessary Privileges".to_string()),
            line: None,
        });
    }

    findings
}

fn detect_job_write_all(workflow: &WorkflowFile) -> Vec<Finding> {
    let mut findings = vec![];

    for job in &workflow.jobs {
        if let Some(perms) = &job.permissions {
            // Scoping write to the one job that needs it (a release job) is the
            // recommended practice. It becomes dangerous when outsiders decide
            // what the job runs: triggers carrying a fork's code or text.
            let untrusted_trigger = workflow.triggers.iter().any(|t| {
                matches!(t.as_str(), "pull_request_target" | "issue_comment" | "issues" | "workflow_run" | "discussion_comment")
            });
            for (scope, value, severity) in [
                ("contents", perms.contents.as_deref(), Severity::High),
                ("pull-requests", perms.pull_requests.as_deref(), Severity::Medium),
            ] {
                if untrusted_trigger && value == Some("write") && !perms.write_all {
                    findings.push(Finding {
                        workflow: workflow.path.clone(),
                        job_id: Some(job.id.clone()),
                        step_name: None,
                        finding_type: FindingType::ExcessivePermissions,
                        severity,
                        title: format!("Job-level permission: {scope} write in '{}'", job.id),
                        description: format!(
                            "Job '{}' grants {scope}: write in a workflow that outsiders can \
                             trigger ({}). Any injection or checked-out fork code in the job \
                             can use that write access.",
                            job.id,
                            workflow.triggers.join(", ")
                        ),
                        evidence: format!("jobs.{}.permissions.{scope}: write", job.id),
                        remediation: "Grant write only to the job that needs it, and keep \
                            third-party actions out of that job where possible."
                            .to_string(),
                        cwe: Some("CWE-250: Execution with Unnecessary Privileges".to_string()),
                        line: job.line,
                    });
                }
            }
            if perms.write_all {
                findings.push(Finding {
                    workflow: workflow.path.clone(),
                    job_id: Some(job.id.clone()),
                    step_name: None,
                    finding_type: FindingType::ExcessivePermissions,
                    severity: Severity::High,
                    title: format!("Job-level permission: write-all in '{}'", job.id),
                    description: format!(
                        "Job '{}' explicitly grants write-all permissions. \
                         This gives every step in the job unrestricted write access.",
                        job.id
                    ),
                    evidence: format!("jobs.{}.permissions: write-all", job.id),
                    remediation: "Replace write-all with explicit per-scope permissions \
                        matching only what the job steps actually need."
                        .to_string(),
                    cwe: Some("CWE-250: Execution with Unnecessary Privileges".to_string()),
                    line: job.line,
                });
            }
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{job, perms, uses_step, workflow_with, workflow_with_triggers};

    fn checkout_step_with_pr_head_ref() -> ghass_core::models::Step {
        let mut step = uses_step("actions/checkout@v4");
        step.with = vec![(
            "ref".to_string(),
            "${{ github.event.pull_request.head.ref }}".to_string(),
        )];
        step
    }

    #[test]
    fn detects_pwn_request_pattern() {
        let wf = workflow_with_triggers(
            vec!["pull_request_target".to_string()],
            vec![job("build", vec![checkout_step_with_pr_head_ref()])],
        );

        let findings: Vec<_> = analyze(&wf).into_iter()
            .filter(|f| f.finding_type == FindingType::PwnRequest)
            .collect();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn no_pwn_request_without_pull_request_target_trigger() {
        let wf = workflow_with(vec![job("build", vec![checkout_step_with_pr_head_ref()])]);

        assert!(detect_pwn_request(&wf).is_empty());
    }

    #[test]
    fn no_pwn_request_when_checkout_uses_default_ref() {
        let wf = workflow_with_triggers(
            vec!["pull_request_target".to_string()],
            vec![job("build", vec![uses_step("actions/checkout@v4")])],
        );

        assert!(detect_pwn_request(&wf).is_empty());
    }

    #[test]
    fn no_pwn_request_when_trigger_present_but_no_checkout_step() {
        let wf = workflow_with_triggers(
            vec!["pull_request_target".to_string()],
            vec![job("build", vec![uses_step("actions/setup-node@v4")])],
        );

        assert!(detect_pwn_request(&wf).is_empty());
    }

    #[test]
    fn flags_global_write_all() {
        let mut wf = workflow_with(vec![]);
        wf.global_permissions = Some(perms(None, None, true));

        let findings = detect_global_write_permissions(&wf);

        assert_eq!(findings.len(), 1);
        assert!(findings[0].evidence.contains("write-all"));
    }

    #[test]
    fn flags_global_contents_write() {
        let mut wf = workflow_with(vec![]);
        wf.global_permissions = Some(perms(Some("write"), None, false));

        let findings = detect_global_write_permissions(&wf);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn flags_global_pull_requests_write_as_medium() {
        let mut wf = workflow_with(vec![]);
        wf.global_permissions = Some(perms(None, Some("write"), false));

        let findings = detect_global_write_permissions(&wf);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn flags_contents_and_pull_requests_write_together() {
        let mut wf = workflow_with(vec![]);
        wf.global_permissions = Some(perms(Some("write"), Some("write"), false));

        assert_eq!(detect_global_write_permissions(&wf).len(), 2);
    }

    #[test]
    fn no_findings_without_global_permissions_block() {
        let wf = workflow_with(vec![]);

        assert!(detect_global_write_permissions(&wf).is_empty());
    }

    #[test]
    fn read_only_global_permissions_produce_no_finding() {
        let mut wf = workflow_with(vec![]);
        wf.global_permissions = Some(perms(Some("read"), Some("read"), false));

        assert!(detect_global_write_permissions(&wf).is_empty());
    }

    #[test]
    fn flags_job_level_write_all() {
        let mut j = job("build", vec![]);
        j.permissions = Some(perms(None, None, true));
        let wf = workflow_with(vec![j]);

        let findings = detect_job_write_all(&wf);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].job_id.as_deref(), Some("build"));
    }

    #[test]
    fn job_without_write_all_is_not_flagged() {
        let mut j = job("build", vec![]);
        j.permissions = Some(perms(Some("read"), None, false));
        let wf = workflow_with(vec![j]);

        assert!(detect_job_write_all(&wf).is_empty());
    }

    #[test]
    fn pwn_request_via_merge_ref_or_pr_number() {
        for r in ["refs/pull/${{ github.event.pull_request.number }}/merge", "${{ github.event.pull_request.head.sha }}"] {
            let mut step = crate::test_support::uses_step("actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11");
            step.with.push(("ref".into(), r.into()));
            let wf = workflow_with_triggers(vec!["pull_request_target".into()], vec![job("t", vec![step])]);
            assert!(analyze(&wf).iter().any(|f| f.finding_type == FindingType::PwnRequest), "{r}");
        }
    }

    #[test]
    fn pwn_request_via_gh_pr_checkout() {
        let wf = workflow_with_triggers(
            vec!["pull_request_target".into()],
            vec![job("t", vec![crate::test_support::run_step("gh pr checkout ${{ github.event.number }}\nnpm test")])],
        );
        assert!(analyze(&wf).iter().any(|f| f.finding_type == FindingType::PwnRequest));
    }

    #[test]
    fn job_level_contents_write_is_flagged_only_under_untrusted_triggers() {
        let mut j = job("deploy", vec![]);
        j.permissions = Some(perms(Some("write"), None, false));
        let release = workflow_with_triggers(vec!["push".into()], vec![j.clone()]);
        assert!(!analyze(&release).iter().any(|f| f.title.contains("contents write")), "a release job needs it");
        let exposed = workflow_with_triggers(vec!["issue_comment".into()], vec![j]);
        assert!(analyze(&exposed).iter().any(|f| f.severity == Severity::High && f.title.contains("contents write")));
    }

    #[test]
    fn missing_permissions_are_a_low_finding_but_an_empty_block_is_fine() {
        let wf = workflow_with(vec![job("t", vec![])]);
        let found = analyze(&wf);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].severity, Severity::Low);

        let mut declared = workflow_with(vec![job("t", vec![])]);
        declared.global_permissions = Some(Default::default());
        assert!(analyze(&declared).is_empty());
    }
}
