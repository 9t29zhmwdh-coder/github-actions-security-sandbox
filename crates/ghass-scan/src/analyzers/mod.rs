pub mod action_pinning;
pub mod custom_rules;
pub mod permissions;
pub mod runner;
pub mod script_injection;
pub mod secrets;

use ghass_core::models::{Finding, WorkflowFile};
use ghass_core::rules::RuleSet;

pub fn run_all(workflow: &WorkflowFile, custom_rules: Option<&RuleSet>) -> Vec<Finding> {
    let mut findings = vec![];
    findings.extend(script_injection::analyze(workflow));
    findings.extend(permissions::analyze(workflow));
    findings.extend(action_pinning::analyze(workflow));
    findings.extend(secrets::analyze(workflow));
    findings.extend(runner::analyze(workflow));
    if let Some(rules) = custom_rules {
        findings.extend(self::custom_rules::analyze(workflow, rules));
    }
    findings
}
