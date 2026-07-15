use crate::line_index::LineIndex;
use anyhow::{Context, Result};
use ghass_core::models::{Job, Permissions, Step, WorkflowFile};
use serde_yaml::Value;
use std::path::Path;

pub fn parse_workflow_file(path: &Path) -> Result<WorkflowFile> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read {}", path.display()))?;
    parse_workflow_str(&content, &path.to_string_lossy())
}

pub fn parse_workflow_str(content: &str, path: &str) -> Result<WorkflowFile> {
    let value: Value = serde_yaml::from_str(content)
        .with_context(|| format!("Invalid YAML in {}", path))?;

    let line_index = LineIndex::build(content);
    let name = value["name"].as_str().unwrap_or(path).to_string();
    let triggers = extract_triggers(&value);
    let jobs = extract_jobs(&value, &line_index);
    let global_permissions = extract_permissions(&value["permissions"]);

    Ok(WorkflowFile {
        path: path.to_string(),
        name,
        triggers,
        jobs,
        global_permissions,
    })
}

fn extract_triggers(value: &Value) -> Vec<String> {
    match &value["on"] {
        Value::String(s) => vec![s.clone()],
        Value::Sequence(seq) => seq
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect(),
        Value::Mapping(map) => map
            .keys()
            .filter_map(|k| k.as_str().map(String::from))
            .collect(),
        _ => vec![],
    }
}

fn extract_jobs(value: &Value, line_index: &LineIndex) -> Vec<Job> {
    let mut jobs = vec![];
    if let Value::Mapping(map) = &value["jobs"] {
        for (key, job_val) in map {
            let id = key.as_str().unwrap_or("unknown").to_string();
            let runs_on = extract_runs_on(job_val);
            let permissions = extract_permissions(&job_val["permissions"]);
            let steps = extract_steps(job_val, &id, line_index);
            let is_reusable_call = job_val["uses"].as_str().is_some();
            let line = line_index.job_line(&id);
            jobs.push(Job {
                id,
                runs_on,
                permissions,
                steps,
                is_reusable_call,
                line,
            });
        }
    }
    jobs
}

fn extract_runs_on(job: &Value) -> String {
    match &job["runs-on"] {
        Value::String(s) => s.clone(),
        Value::Sequence(seq) => seq
            .iter()
            .filter_map(|v| v.as_str())
            .collect::<Vec<_>>()
            .join(", "),
        _ => "unknown".to_string(),
    }
}

fn extract_steps(job: &Value, job_id: &str, line_index: &LineIndex) -> Vec<Step> {
    let mut steps = vec![];
    if let Value::Sequence(seq) = &job["steps"] {
        for (index, step_val) in seq.iter().enumerate() {
            let name = step_val["name"].as_str().map(String::from);
            let uses = step_val["uses"].as_str().map(String::from);
            let run = step_val["run"].as_str().map(String::from);
            let env = extract_string_map(&step_val["env"]);
            let with = extract_string_map(&step_val["with"]);
            let line = line_index.step_line(job_id, index);
            steps.push(Step {
                name,
                uses,
                run,
                env,
                with,
                line,
            });
        }
    }
    steps
}

fn extract_string_map(value: &Value) -> Vec<(String, String)> {
    let mut result = vec![];
    if let Value::Mapping(map) = value {
        for (k, v) in map {
            if let (Some(key), Some(val)) = (k.as_str(), v.as_str()) {
                result.push((key.to_string(), val.to_string()));
            }
        }
    }
    result
}

fn extract_permissions(value: &Value) -> Option<Permissions> {
    match value {
        Value::String(s) if s == "write-all" => Some(Permissions {
            write_all: true,
            ..Default::default()
        }),
        Value::String(_) => Some(Permissions::default()),
        Value::Mapping(_) => {
            let contents = value["contents"].as_str().map(String::from);
            let pull_requests = value["pull-requests"].as_str().map(String::from);
            if contents.is_none() && pull_requests.is_none() {
                None
            } else {
                Some(Permissions {
                    contents,
                    pull_requests,
                    write_all: false,
                })
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_name_and_string_trigger() {
        let wf = parse_workflow_str("name: CI\non: push\njobs: {}", "wf.yml").unwrap();

        assert_eq!(wf.name, "CI");
        assert_eq!(wf.triggers, vec!["push".to_string()]);
        assert!(wf.jobs.is_empty());
    }

    #[test]
    fn falls_back_to_path_when_name_is_missing() {
        let wf = parse_workflow_str("on: push\njobs: {}", "wf.yml").unwrap();

        assert_eq!(wf.name, "wf.yml");
    }

    #[test]
    fn parses_sequence_trigger() {
        let wf = parse_workflow_str("on: [push, pull_request]\njobs: {}", "wf.yml").unwrap();

        assert_eq!(
            wf.triggers,
            vec!["push".to_string(), "pull_request".to_string()]
        );
    }

    #[test]
    fn parses_mapping_trigger() {
        let yaml = "on:\n  push:\n    branches: [main]\n  pull_request_target: {}\njobs: {}";
        let wf = parse_workflow_str(yaml, "wf.yml").unwrap();

        assert_eq!(wf.triggers.len(), 2);
        assert!(wf.triggers.contains(&"push".to_string()));
        assert!(wf.triggers.contains(&"pull_request_target".to_string()));
    }

    #[test]
    fn missing_trigger_yields_empty_vec() {
        let wf = parse_workflow_str("jobs: {}", "wf.yml").unwrap();

        assert!(wf.triggers.is_empty());
    }

    #[test]
    fn parses_job_with_steps_env_and_with() {
        let yaml = "\
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4
        with:
          ref: main
      - name: Run
        run: echo hi
        env:
          FOO: bar
";
        let wf = parse_workflow_str(yaml, "wf.yml").unwrap();

        assert_eq!(wf.jobs.len(), 1);
        let job = &wf.jobs[0];
        assert_eq!(job.id, "build");
        assert_eq!(job.runs_on, "ubuntu-latest");
        assert_eq!(job.steps.len(), 2);
        assert_eq!(job.steps[0].uses.as_deref(), Some("actions/checkout@v4"));
        assert_eq!(
            job.steps[0].with,
            vec![("ref".to_string(), "main".to_string())]
        );
        assert_eq!(job.steps[1].run.as_deref(), Some("echo hi"));
        assert_eq!(
            job.steps[1].env,
            vec![("FOO".to_string(), "bar".to_string())]
        );
    }

    #[test]
    fn parses_sequence_runs_on() {
        let yaml = "jobs:\n  build:\n    runs-on: [self-hosted, linux]\n    steps: []";
        let wf = parse_workflow_str(yaml, "wf.yml").unwrap();

        assert_eq!(wf.jobs[0].runs_on, "self-hosted, linux");
    }

    #[test]
    fn job_without_runs_on_defaults_to_unknown() {
        let yaml = "jobs:\n  build:\n    steps: []";
        let wf = parse_workflow_str(yaml, "wf.yml").unwrap();

        assert_eq!(wf.jobs[0].runs_on, "unknown");
    }

    #[test]
    fn job_without_steps_block_yields_empty_steps() {
        let yaml = "jobs:\n  build:\n    runs-on: ubuntu-latest";
        let wf = parse_workflow_str(yaml, "wf.yml").unwrap();

        assert!(wf.jobs[0].steps.is_empty());
    }

    #[test]
    fn detects_reusable_workflow_call() {
        let yaml =
            "jobs:\n  call:\n    uses: org/repo/.github/workflows/reusable.yml@main";
        let wf = parse_workflow_str(yaml, "wf.yml").unwrap();

        assert!(wf.jobs[0].is_reusable_call);
    }

    #[test]
    fn workflow_without_jobs_block_yields_empty_jobs() {
        let wf = parse_workflow_str("on: push", "wf.yml").unwrap();

        assert!(wf.jobs.is_empty());
    }

    #[test]
    fn global_permissions_write_all_string() {
        let wf = parse_workflow_str("permissions: write-all\njobs: {}", "wf.yml").unwrap();

        assert!(wf.global_permissions.unwrap().write_all);
    }

    #[test]
    fn global_permissions_other_string_yields_default() {
        let wf = parse_workflow_str("permissions: read-all\njobs: {}", "wf.yml").unwrap();

        let perms = wf.global_permissions.unwrap();
        assert!(!perms.write_all);
        assert!(perms.contents.is_none());
    }

    #[test]
    fn global_permissions_mapping() {
        let yaml = "permissions:\n  contents: write\n  pull-requests: read\njobs: {}";
        let wf = parse_workflow_str(yaml, "wf.yml").unwrap();

        let perms = wf.global_permissions.unwrap();
        assert_eq!(perms.contents.as_deref(), Some("write"));
        assert_eq!(perms.pull_requests.as_deref(), Some("read"));
        assert!(!perms.write_all);
    }

    #[test]
    fn empty_permissions_mapping_yields_none() {
        let wf = parse_workflow_str("permissions: {}\njobs: {}", "wf.yml").unwrap();

        assert!(wf.global_permissions.is_none());
    }

    #[test]
    fn missing_permissions_block_yields_none() {
        let wf = parse_workflow_str("jobs: {}", "wf.yml").unwrap();

        assert!(wf.global_permissions.is_none());
    }

    #[test]
    fn invalid_yaml_returns_error() {
        let result = parse_workflow_str("jobs: [this is not: valid", "wf.yml");

        assert!(result.is_err());
    }

    #[test]
    fn parsed_jobs_and_steps_carry_line_numbers() {
        let yaml = "\
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4
      - name: Run
        run: echo hi
";
        let wf = parse_workflow_str(yaml, "wf.yml").unwrap();

        assert_eq!(wf.jobs[0].line, Some(2));
        assert_eq!(wf.jobs[0].steps[0].line, Some(5));
        assert_eq!(wf.jobs[0].steps[1].line, Some(7));
    }

    #[test]
    fn job_level_permissions_are_parsed_independently_of_global() {
        let yaml = "jobs:\n  build:\n    permissions:\n      contents: write";
        let wf = parse_workflow_str(yaml, "wf.yml").unwrap();

        assert_eq!(
            wf.jobs[0].permissions.as_ref().unwrap().contents.as_deref(),
            Some("write")
        );
        assert!(wf.global_permissions.is_none());
    }
}
