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

    let name = value["name"].as_str().unwrap_or(path).to_string();
    let triggers = extract_triggers(&value);
    let jobs = extract_jobs(&value);
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

fn extract_jobs(value: &Value) -> Vec<Job> {
    let mut jobs = vec![];
    if let Value::Mapping(map) = &value["jobs"] {
        for (key, job_val) in map {
            let id = key.as_str().unwrap_or("unknown").to_string();
            let runs_on = extract_runs_on(job_val);
            let permissions = extract_permissions(&job_val["permissions"]);
            let steps = extract_steps(job_val);
            let is_reusable_call = job_val["uses"].as_str().is_some();
            jobs.push(Job {
                id,
                runs_on,
                permissions,
                steps,
                is_reusable_call,
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

fn extract_steps(job: &Value) -> Vec<Step> {
    let mut steps = vec![];
    if let Value::Sequence(seq) = &job["steps"] {
        for step_val in seq {
            let name = step_val["name"].as_str().map(String::from);
            let uses = step_val["uses"].as_str().map(String::from);
            let run = step_val["run"].as_str().map(String::from);
            let env = extract_string_map(&step_val["env"]);
            let with = extract_string_map(&step_val["with"]);
            steps.push(Step {
                name,
                uses,
                run,
                env,
                with,
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
