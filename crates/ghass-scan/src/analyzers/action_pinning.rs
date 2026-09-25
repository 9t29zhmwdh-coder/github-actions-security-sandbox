use ghass_core::models::{Finding, FindingType, Severity, WorkflowFile};

pub fn analyze(workflow: &WorkflowFile) -> Vec<Finding> {
    let mut findings = vec![];

    for job in &workflow.jobs {
        for step in &job.steps {
            if let Some(uses) = &step.uses {
                if let Some(finding) = check_pinning(
                    &workflow.path,
                    &job.id,
                    step.name.as_deref(),
                    uses,
                    step.line,
                ) {
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
    line: Option<usize>,
) -> Option<Finding> {
    if uses.starts_with("./") || uses.starts_with("../") {
        return None;
    }
    if uses.contains("/.github/workflows/") {
        return None;
    }

    // `docker://image@sha256:<64 hex>` is pinned; a tag or no tag at all
    // (which means `latest`) can change under you. This was inverted: a bare
    // image passed and a digest-pinned one was flagged.
    if let Some(image) = uses.strip_prefix("docker://") {
        if let Some((_, digest)) = image.split_once("@sha256:") {
            if digest.len() == 64 && digest.chars().all(|c| c.is_ascii_hexdigit()) {
                return None;
            }
        }
        let tag = image.rsplit_once(':').map(|(_, t)| t).filter(|t| !t.contains('/'));
        let (severity, what) = match tag {
            None | Some("latest") => (Severity::High, "no fixed version (implicitly `latest`)".to_string()),
            Some(t) => (Severity::Medium, format!("the mutable tag `{t}`")),
        };
        return Some(Finding {
            workflow: workflow_path.to_string(),
            job_id: Some(job_id.to_string()),
            step_name: step_name.map(String::from),
            finding_type: FindingType::UnpinnedAction,
            severity,
            title: format!("Docker image not pinned to a digest: {}", uses),
            description: format!("'{uses}' uses {what}. The image behind it can be replaced at any time."),
            evidence: uses.to_string(),
            remediation: "Pin the image by digest: `docker://image@sha256:<64 hex>`.".to_string(),
            cwe: Some("CWE-829: Inclusion of Functionality from Untrusted Control Sphere".to_string()),
            line,
        });
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
        line,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{job, uses_step, workflow_with};

    #[test]
    fn flags_mutable_branch_reference_as_high() {
        let wf = workflow_with(vec![job(
            "build",
            vec![uses_step("some-org/build-action@main")],
        )]);

        let findings = analyze(&wf);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].finding_type, FindingType::UnpinnedAction);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn flags_master_and_latest_as_high() {
        for reference in ["some-org/a@master", "some-org/b@latest"] {
            let wf = workflow_with(vec![job("build", vec![uses_step(reference)])]);
            let findings = analyze(&wf);
            assert_eq!(findings[0].severity, Severity::High, "{reference}");
        }
    }

    #[test]
    fn flags_semantic_version_tag_as_medium() {
        let wf = workflow_with(vec![job("build", vec![uses_step("actions/checkout@v4")])]);

        let findings = analyze(&wf);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn does_not_flag_full_commit_sha() {
        let sha = "a".repeat(40);
        let wf = workflow_with(vec![job(
            "build",
            vec![uses_step(&format!("actions/checkout@{sha}"))],
        )]);

        assert!(analyze(&wf).is_empty());
    }

    #[test]
    fn does_not_flag_local_action_reference() {
        let wf = workflow_with(vec![job("build", vec![uses_step("./local-action")])]);

        assert!(analyze(&wf).is_empty());
    }

    #[test]
    fn does_not_flag_reusable_workflow_reference() {
        let wf = workflow_with(vec![job(
            "build",
            vec![uses_step(
                "org/repo/.github/workflows/reusable.yml@main",
            )],
        )]);

        assert!(analyze(&wf).is_empty());
    }

    #[test]
    fn docker_image_without_tag_is_latest_and_flagged() {
        let wf = workflow_with(vec![job("build", vec![uses_step("docker://alpine")])]);
        let findings = analyze(&wf);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn docker_image_pinned_by_digest_is_not_flagged() {
        let digest = "0".repeat(64);
        let wf = workflow_with(vec![job("build", vec![uses_step(&format!("docker://alpine@sha256:{digest}"))])]);
        assert!(analyze(&wf).is_empty());
    }

    #[test]
    fn docker_image_with_tag_is_medium() {
        let wf = workflow_with(vec![job("build", vec![uses_step("docker://ghcr.io/org/tool:1.2")])]);
        assert_eq!(analyze(&wf)[0].severity, Severity::Medium);
    }

    #[test]
    fn flags_unpinned_docker_reference() {
        let wf = workflow_with(vec![job(
            "build",
            vec![uses_step("docker://alpine@latest")],
        )]);

        assert_eq!(analyze(&wf).len(), 1);
    }

    #[test]
    fn step_without_uses_is_ignored() {
        let wf = workflow_with(vec![job(
            "build",
            vec![crate::test_support::run_step("echo hi")],
        )]);

        assert!(analyze(&wf).is_empty());
    }
}
