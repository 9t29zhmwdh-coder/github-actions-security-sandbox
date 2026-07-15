#![cfg(test)]

use ghass_core::models::{Job, Permissions, Step, WorkflowFile};

pub fn workflow_with(jobs: Vec<Job>) -> WorkflowFile {
    workflow_with_triggers(vec!["push".to_string()], jobs)
}

pub fn workflow_with_triggers(triggers: Vec<String>, jobs: Vec<Job>) -> WorkflowFile {
    WorkflowFile {
        path: "wf.yml".to_string(),
        name: "test".to_string(),
        triggers,
        jobs,
        global_permissions: None,
    }
}

pub fn job(id: &str, steps: Vec<Step>) -> Job {
    Job {
        id: id.to_string(),
        runs_on: "ubuntu-latest".to_string(),
        permissions: None,
        steps,
        is_reusable_call: false,
        line: None,
    }
}

pub fn run_step(run: &str) -> Step {
    Step {
        name: Some("step".to_string()),
        uses: None,
        run: Some(run.to_string()),
        env: vec![],
        with: vec![],
        line: None,
    }
}

pub fn uses_step(uses: &str) -> Step {
    Step {
        name: Some("step".to_string()),
        uses: Some(uses.to_string()),
        run: None,
        env: vec![],
        with: vec![],
        line: None,
    }
}

pub fn perms(contents: Option<&str>, pull_requests: Option<&str>, write_all: bool) -> Permissions {
    Permissions {
        contents: contents.map(String::from),
        pull_requests: pull_requests.map(String::from),
        write_all,
    }
}
