use ghass_core::models::{Finding, FindingType, Severity, WorkflowFile};

/// Context fields an outsider can set, after GitHub Security Lab's list of
/// untrusted input. `*` stands for one array element or map key.
const UNTRUSTED_FIELDS: &[&str] = &[
    "github.event.issue.title",
    "github.event.issue.body",
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.event.comment.body",
    "github.event.review.body",
    "github.event.review_comment.body",
    "github.event.pages.*.page_name",
    "github.event.commits.*.message",
    "github.event.commits.*.author.email",
    "github.event.commits.*.author.name",
    "github.event.head_commit.message",
    "github.event.head_commit.author.email",
    "github.event.head_commit.author.name",
    "github.event.pull_request.head.ref",
    "github.event.pull_request.head.label",
    "github.event.pull_request.head.repo.default_branch",
    "github.event.workflow_run.head_branch",
    "github.event.workflow_run.head_commit.message",
    "github.event.workflow_run.head_commit.author.email",
    "github.event.workflow_run.head_commit.author.name",
    "github.event.discussion.title",
    "github.event.discussion.body",
    "github.head_ref",
];

/// Values set by whoever triggers the workflow (dispatch or caller inputs):
/// only people with write access, so Medium: poor practice, not an outsider's
/// way in.
const INPUT_PREFIXES: &[&str] = &["inputs.", "github.event.inputs."];

pub fn analyze(workflow: &WorkflowFile) -> Vec<Finding> {
    let mut findings = vec![];

    for job in &workflow.jobs {
        for step in &job.steps {
            // `actions/github-script` runs its `script` input as JavaScript; an
            // expression there is code injection just like in `run`.
            let script = step.uses.as_deref()
                .filter(|u| u.starts_with("actions/github-script"))
                .and_then(|_| step.with.iter().find(|(k, _)| k == "script").map(|(_, v)| v.as_str()));
            for (sink, text) in [("run", step.run.as_deref()), ("github-script", script)] {
                let Some(text) = text else { continue };
                let (untrusted, inputs) = classify(text);
                if untrusted.is_empty() && inputs.is_empty() {
                    continue;
                }
                let critical = !untrusted.is_empty();
                let evidence: Vec<String> = untrusted.into_iter().chain(inputs).collect();
                findings.push(Finding {
                    workflow: workflow.path.clone(),
                    job_id: Some(job.id.clone()),
                    step_name: step.name.clone(),
                    finding_type: FindingType::ScriptInjection,
                    severity: if critical { Severity::Critical } else { Severity::Medium },
                    title: "Script injection via untrusted context expression".to_string(),
                    description: format!(
                        "Job '{}' interpolates {} directly into a {} step. The value is pasted into \
                         the {} before it runs, so whoever controls it ({}) can run arbitrary \
                         commands with the job's GITHUB_TOKEN and secrets.",
                        job.id,
                        if critical { "data an outsider controls" } else { "workflow inputs" },
                        sink,
                        if sink == "run" { "shell script" } else { "JavaScript" },
                        if critical { "anyone who can open an issue, a pull request or a comment" } else { "whoever triggers the workflow" },
                    ),
                    evidence: evidence.join(", "),
                    remediation: "Pass the value through an environment variable and use the \
                        variable instead: `env: TITLE: ${{ github.event.issue.title }}` and \
                        `\"$TITLE\"` in the shell (or `process.env.TITLE` in github-script)."
                        .to_string(),
                    cwe: Some("CWE-78: OS Command Injection".to_string()),
                    line: step.line,
                });
            }
        }
    }

    findings
}

/// The `${{ ... }}` expressions in `text`, spaces or not.
fn expressions(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("${{") {
        let after = &rest[start + 3..];
        let Some(end) = after.find("}}") else { break };
        out.push(after[..end].trim());
        rest = &after[end + 2..];
    }
    out
}

/// Context paths inside one expression: `format('{0}', github.event.issue.title)`
/// yields `github.event.issue.title`; `commits[0].message` becomes `commits.*.message`.
fn paths(expr: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut in_string = false;
    let mut chars = expr.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\'' {
            in_string = !in_string;
            continue;
        }
        if in_string {
            continue;
        }
        if c.is_alphanumeric() || c == '_' || c == '-' || c == '.' || c == '*' {
            current.push(c);
        } else if c == '[' {
            // index or key access: one element, whatever it is
            for d in chars.by_ref() {
                if d == ']' { break; }
            }
            current.push_str(".*");
        } else if !current.is_empty() {
            out.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    out.into_iter().map(|p| p.replace("..", ".")).filter(|p| p.contains('.')).collect()
}

fn matches_field(path: &str, field: &str) -> bool {
    let p: Vec<&str> = path.split('.').collect();
    let f: Vec<&str> = field.split('.').collect();
    let same = |a: &str, b: &str| a == b || a == "*" || b == "*";
    // The field itself, or an object that contains it (`toJSON(github.event.issue)`).
    p.len() <= f.len() && p.iter().zip(&f).all(|(a, b)| same(a, b))
        && (p.len() == f.len() || p.len() >= 2)
}

/// (untrusted outsider data, workflow inputs) found in `text`.
fn classify(text: &str) -> (Vec<String>, Vec<String>) {
    let mut untrusted = Vec::new();
    let mut inputs = Vec::new();
    for expr in expressions(text) {
        for path in paths(expr) {
            let shown = format!("${{{{ {} }}}}", expr);
            if UNTRUSTED_FIELDS.iter().any(|f| matches_field(&path, f)) {
                if !untrusted.contains(&shown) { untrusted.push(shown); }
            } else if INPUT_PREFIXES.iter().any(|pre| path.starts_with(pre)) && !inputs.contains(&shown) {
                inputs.push(shown);
            }
        }
    }
    (untrusted, inputs)
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
        assert_eq!(findings[0].evidence, "${{ github.event.review.body }}");
    }

    #[test]
    fn flags_inputs_prefix() {
        let wf = workflow_with(vec![job(
            "build",
            vec![run_step("echo ${{ inputs.untrusted }}")],
        )]);

        let findings = analyze(&wf);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].evidence, "${{ inputs.untrusted }}");
        assert_eq!(findings[0].severity, Severity::Medium);
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

    #[test]
    fn expressions_without_spaces_are_found() {
        let wf = workflow_with(vec![job("b", vec![run_step("echo ${{github.event.issue.title}}")])]);
        assert_eq!(analyze(&wf).len(), 1);
    }

    #[test]
    fn values_an_outsider_cannot_set_are_not_flagged() {
        let script = "gh pr view ${{ github.event.pull_request.number }} && git checkout ${{ github.event.pull_request.head.sha }} && echo ${{ github.event.repository.full_name }}";
        let wf = workflow_with(vec![job("b", vec![run_step(script)])]);
        assert!(analyze(&wf).is_empty(), "{:?}", analyze(&wf));
    }

    #[test]
    fn whole_event_objects_and_array_elements_count() {
        for script in ["echo '${{ toJSON(github.event.pull_request) }}'", "echo \"${{ github.event.commits[0].message }}\""] {
            let wf = workflow_with(vec![job("b", vec![run_step(script)])]);
            assert_eq!(analyze(&wf).len(), 1, "{script}");
        }
    }

    #[test]
    fn github_script_is_a_sink_too() {
        let mut step = crate::test_support::uses_step("actions/github-script@60a0d83039c74a4aee543508d2ffcb1c3799cdea");
        step.with.push(("script".into(), "console.log('${{ github.event.issue.title }}')".into()));
        let findings = analyze(&workflow_with(vec![job("b", vec![step])]));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
    }
}
