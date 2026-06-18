pub mod action_pinning;
pub mod permissions;
pub mod runner;
pub mod script_injection;
pub mod secrets;

use ghass_core::models::{Finding, WorkflowFile};

pub fn run_all(workflow: &WorkflowFile) -> Vec<Finding> {
    let mut findings = vec![];
    findings.extend(script_injection::analyze(workflow));
    findings.extend(permissions::analyze(workflow));
    findings.extend(action_pinning::analyze(workflow));
    findings.extend(secrets::analyze(workflow));
    findings.extend(runner::analyze(workflow));
    findings
}
