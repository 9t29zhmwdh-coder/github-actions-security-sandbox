use ghass_core::models::{Finding, FindingType, WorkflowFile};
use ghass_core::rules::{MatchContext, Rule, RuleSet};

pub fn analyze(workflow: &WorkflowFile, rules: &RuleSet) -> Vec<Finding> {
    rules
        .rules
        .iter()
        .flat_map(|rule| evaluate_rule(rule, workflow))
        .collect()
}

fn evaluate_rule(rule: &Rule, workflow: &WorkflowFile) -> Vec<Finding> {
    let mut findings = vec![];

    if rule.condition.touches_step() {
        for job in &workflow.jobs {
            for step in &job.steps {
                let ctx = MatchContext {
                    workflow,
                    job: Some(job),
                    step: Some(step),
                };
                if rule.condition.eval(&ctx) {
                    findings.push(build_finding(rule, workflow, Some(job.id.clone()), step.name.clone()));
                }
            }
        }
    } else if rule.condition.touches_job() {
        for job in &workflow.jobs {
            let ctx = MatchContext {
                workflow,
                job: Some(job),
                step: None,
            };
            if rule.condition.eval(&ctx) {
                findings.push(build_finding(rule, workflow, Some(job.id.clone()), None));
            }
        }
    } else {
        let ctx = MatchContext {
            workflow,
            job: None,
            step: None,
        };
        if rule.condition.eval(&ctx) {
            findings.push(build_finding(rule, workflow, None, None));
        }
    }

    findings
}

fn build_finding(
    rule: &Rule,
    workflow: &WorkflowFile,
    job_id: Option<String>,
    step_name: Option<String>,
) -> Finding {
    Finding {
        workflow: workflow.path.clone(),
        job_id,
        step_name,
        finding_type: FindingType::Custom(rule.id.clone()),
        severity: rule.severity.clone(),
        title: rule.title.clone(),
        description: rule.description.clone(),
        evidence: format!("custom rule '{}' matched", rule.id),
        remediation: rule.remediation.clone(),
        cwe: rule.cwe.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghass_core::models::{Job, Permissions, Severity, Step};
    use ghass_core::rules::Condition;

    fn workflow_with(jobs: Vec<Job>) -> WorkflowFile {
        WorkflowFile {
            path: "wf.yml".to_string(),
            name: "test".to_string(),
            triggers: vec!["push".to_string()],
            jobs,
            global_permissions: None,
        }
    }

    #[test]
    fn step_scoped_rule_reports_once_per_matching_step() {
        let step_a = Step {
            name: Some("a".to_string()),
            uses: Some("docker://alpine:3.19".to_string()),
            run: None,
            env: vec![],
            with: vec![],
        };
        let step_b = Step {
            name: Some("b".to_string()),
            uses: Some("actions/checkout@v4".to_string()),
            run: None,
            env: vec![],
            with: vec![],
        };
        let j = Job {
            id: "build".to_string(),
            runs_on: "ubuntu-latest".to_string(),
            permissions: None,
            steps: vec![step_a, step_b],
            is_reusable_call: false,
        };
        let wf = workflow_with(vec![j]);
        let rule = Rule {
            id: "no-docker-actions".to_string(),
            title: "Docker actions forbidden".to_string(),
            severity: Severity::Medium,
            description: String::new(),
            remediation: String::new(),
            cwe: None,
            condition: Condition::UsesMatches(r"^docker://".to_string()),
        };
        let rules = RuleSet { rules: vec![rule] };

        let findings = analyze(&wf, &rules);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].step_name, Some("a".to_string()));
        assert_eq!(findings[0].finding_type, FindingType::Custom("no-docker-actions".to_string()));
    }

    #[test]
    fn job_scoped_rule_reports_once_per_job_not_per_step() {
        let steps = vec![
            Step { name: Some("s1".to_string()), uses: None, run: None, env: vec![], with: vec![] },
            Step { name: Some("s2".to_string()), uses: None, run: None, env: vec![], with: vec![] },
        ];
        let j = Job {
            id: "build".to_string(),
            runs_on: "self-hosted".to_string(),
            permissions: Some(Permissions { write_all: true, ..Default::default() }),
            steps,
            is_reusable_call: false,
        };
        let wf = workflow_with(vec![j]);
        let rule = Rule {
            id: "no-writeall-self-hosted".to_string(),
            title: "write-all on self-hosted".to_string(),
            severity: Severity::High,
            description: String::new(),
            remediation: String::new(),
            cwe: None,
            condition: Condition::All(vec![
                Condition::RunsOnContains("self-hosted".to_string()),
                Condition::JobWriteAll,
            ]),
        };
        let rules = RuleSet { rules: vec![rule] };

        let findings = analyze(&wf, &rules);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].job_id, Some("build".to_string()));
        assert_eq!(findings[0].step_name, None);
    }

    #[test]
    fn workflow_scoped_rule_reports_once_for_the_whole_workflow() {
        let wf = workflow_with(vec![]);
        let rule = Rule {
            id: "push-trigger-used".to_string(),
            title: "push trigger present".to_string(),
            severity: Severity::Low,
            description: String::new(),
            remediation: String::new(),
            cwe: None,
            condition: Condition::TriggerEquals("push".to_string()),
        };
        let rules = RuleSet { rules: vec![rule] };

        let findings = analyze(&wf, &rules);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].job_id, None);
    }

    #[test]
    fn no_findings_when_nothing_matches() {
        let wf = workflow_with(vec![]);
        let rule = Rule {
            id: "never-matches".to_string(),
            title: "x".to_string(),
            severity: Severity::Low,
            description: String::new(),
            remediation: String::new(),
            cwe: None,
            condition: Condition::TriggerEquals("release".to_string()),
        };
        let rules = RuleSet { rules: vec![rule] };
        assert!(analyze(&wf, &rules).is_empty());
    }
}
