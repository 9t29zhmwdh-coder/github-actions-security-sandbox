//! Custom policy rules: org-specific checks defined in a YAML file, evaluated
//! against a parsed workflow alongside the built-in analyzers.
//!
//! A rule matches at exactly one granularity (step, job, or workflow),
//! inferred from which condition leaves it uses, so a job-level rule
//! (e.g. "no self-hosted runner in job X") reports once per job instead of
//! once per step in that job.

use crate::models::{Job, Severity, Step, WorkflowFile};
use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::collections::HashSet;
use std::path::Path;

#[derive(Debug, Deserialize, Default)]
pub struct RuleSet {
    #[serde(default)]
    pub rules: Vec<Rule>,
}

#[derive(Debug, Deserialize)]
pub struct Rule {
    pub id: String,
    pub title: String,
    pub severity: Severity,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub remediation: String,
    #[serde(default)]
    pub cwe: Option<String>,
    #[serde(rename = "match")]
    pub condition: Condition,
}

#[derive(Debug)]
pub enum Condition {
    UsesMatches(String),
    RunContains(String),
    EnvKeyContains(String),
    RunsOnContains(String),
    JobWriteAll,
    WorkflowWriteAll,
    TriggerEquals(String),
    All(Vec<Condition>),
    Any(Vec<Condition>),
    Not(Box<Condition>),
}

/// serde_yaml's derive represents a data-carrying enum variant with a YAML
/// tag (`!uses_matches foo`), not the `{uses_matches: foo}` map most people
/// would actually write. This impl deserializes via `serde_yaml::Value` so
/// rule authors can use the natural single-key-map syntax instead.
impl<'de> Deserialize<'de> for Condition {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = serde_yaml::Value::deserialize(deserializer)?;
        condition_from_value(&value).map_err(serde::de::Error::custom)
    }
}

fn condition_from_value(value: &serde_yaml::Value) -> std::result::Result<Condition, String> {
    match value {
        serde_yaml::Value::String(s) => match s.as_str() {
            "job_write_all" => Ok(Condition::JobWriteAll),
            "workflow_write_all" => Ok(Condition::WorkflowWriteAll),
            other => Err(format!("unknown condition '{}'", other)),
        },
        serde_yaml::Value::Mapping(map) => {
            if map.len() != 1 {
                return Err("a condition map must have exactly one key".to_string());
            }
            let (key, val) = map.iter().next().expect("checked len == 1 above");
            let key = key.as_str().ok_or("condition key must be a string")?;
            match key {
                "uses_matches" => Ok(Condition::UsesMatches(value_as_string(val)?)),
                "run_contains" => Ok(Condition::RunContains(value_as_string(val)?)),
                "env_key_contains" => Ok(Condition::EnvKeyContains(value_as_string(val)?)),
                "runs_on_contains" => Ok(Condition::RunsOnContains(value_as_string(val)?)),
                "trigger_equals" => Ok(Condition::TriggerEquals(value_as_string(val)?)),
                "all" => Ok(Condition::All(value_as_condition_list(val)?)),
                "any" => Ok(Condition::Any(value_as_condition_list(val)?)),
                "not" => Ok(Condition::Not(Box::new(condition_from_value(val)?))),
                other => Err(format!("unknown condition '{}'", other)),
            }
        }
        other => Err(format!(
            "a condition must be a string or a single-key map, got {:?}",
            other
        )),
    }
}

fn value_as_string(value: &serde_yaml::Value) -> std::result::Result<String, String> {
    value
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| "expected a string condition value".to_string())
}

fn value_as_condition_list(
    value: &serde_yaml::Value,
) -> std::result::Result<Vec<Condition>, String> {
    let seq = value
        .as_sequence()
        .ok_or_else(|| "expected a list of conditions".to_string())?;
    seq.iter().map(condition_from_value).collect()
}

pub struct MatchContext<'a> {
    pub workflow: &'a WorkflowFile,
    pub job: Option<&'a Job>,
    pub step: Option<&'a Step>,
}

impl Condition {
    /// A rule using any of these leaves is evaluated once per step.
    pub fn touches_step(&self) -> bool {
        match self {
            Condition::UsesMatches(_) | Condition::RunContains(_) | Condition::EnvKeyContains(_) => {
                true
            }
            Condition::All(cs) | Condition::Any(cs) => cs.iter().any(Condition::touches_step),
            Condition::Not(c) => c.touches_step(),
            _ => false,
        }
    }

    /// A rule using any of these leaves (and no step leaf) is evaluated once per job.
    pub fn touches_job(&self) -> bool {
        match self {
            Condition::RunsOnContains(_) | Condition::JobWriteAll => true,
            Condition::All(cs) | Condition::Any(cs) => cs.iter().any(Condition::touches_job),
            Condition::Not(c) => c.touches_job(),
            _ => false,
        }
    }

    pub fn eval(&self, ctx: &MatchContext) -> bool {
        match self {
            Condition::UsesMatches(pattern) => ctx
                .step
                .and_then(|s| s.uses.as_deref())
                .map(|uses| regex_matches(pattern, uses))
                .unwrap_or(false),
            Condition::RunContains(needle) => ctx
                .step
                .and_then(|s| s.run.as_deref())
                .is_some_and(|run| run.contains(needle.as_str())),
            Condition::EnvKeyContains(needle) => ctx
                .step
                .is_some_and(|s| s.env.iter().any(|(k, _)| k.contains(needle.as_str()))),
            Condition::RunsOnContains(needle) => ctx.job.is_some_and(|j| {
                j.runs_on.to_lowercase().contains(&needle.to_lowercase())
            }),
            Condition::JobWriteAll => ctx
                .job
                .and_then(|j| j.permissions.as_ref())
                .is_some_and(|p| p.write_all),
            Condition::WorkflowWriteAll => ctx
                .workflow
                .global_permissions
                .as_ref()
                .is_some_and(|p| p.write_all),
            Condition::TriggerEquals(trigger) => {
                ctx.workflow.triggers.iter().any(|t| t == trigger)
            }
            Condition::All(cs) => cs.iter().all(|c| c.eval(ctx)),
            Condition::Any(cs) => cs.iter().any(|c| c.eval(ctx)),
            Condition::Not(c) => !c.eval(ctx),
        }
    }

    /// Walks the condition tree looking for `uses_matches` patterns so they
    /// can be validated once at load time instead of failing silently
    /// (regex compile errors are swallowed to `false` in `eval`) at scan time.
    fn regex_patterns(&self) -> Vec<&str> {
        match self {
            Condition::UsesMatches(pattern) => vec![pattern.as_str()],
            Condition::All(cs) | Condition::Any(cs) => {
                cs.iter().flat_map(Condition::regex_patterns).collect()
            }
            Condition::Not(c) => c.regex_patterns(),
            _ => vec![],
        }
    }
}

fn regex_matches(pattern: &str, haystack: &str) -> bool {
    regex::Regex::new(pattern)
        .map(|re| re.is_match(haystack))
        .unwrap_or(false)
}

impl RuleSet {
    pub fn load(path: &Path) -> Result<RuleSet> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading rules file {}", path.display()))?;
        let rules: RuleSet = serde_yaml::from_str(&raw)
            .with_context(|| format!("parsing rules file {}", path.display()))?;
        rules.validate()?;
        Ok(rules)
    }

    fn validate(&self) -> Result<()> {
        let mut seen_ids = HashSet::new();
        for rule in &self.rules {
            if !seen_ids.insert(rule.id.as_str()) {
                bail!("duplicate rule id '{}' in rules file", rule.id);
            }
            for pattern in rule.condition.regex_patterns() {
                regex::Regex::new(pattern)
                    .with_context(|| format!("rule '{}': invalid regex '{}'", rule.id, pattern))?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Permissions;

    fn workflow(triggers: Vec<&str>, global_write_all: bool) -> WorkflowFile {
        WorkflowFile {
            path: "workflow.yml".to_string(),
            name: "test".to_string(),
            triggers: triggers.into_iter().map(String::from).collect(),
            jobs: vec![],
            global_permissions: Some(Permissions {
                write_all: global_write_all,
                ..Default::default()
            }),
        }
    }

    fn job(id: &str, runs_on: &str, steps: Vec<Step>) -> Job {
        Job {
            id: id.to_string(),
            runs_on: runs_on.to_string(),
            permissions: None,
            steps,
            is_reusable_call: false,
            line: None,
        }
    }

    fn step(uses: Option<&str>, run: Option<&str>) -> Step {
        Step {
            name: Some("a step".to_string()),
            uses: uses.map(String::from),
            run: run.map(String::from),
            env: vec![],
            with: vec![],
            line: None,
        }
    }

    #[test]
    fn load_rejects_duplicate_ids() {
        let yaml = r#"
rules:
  - id: dup
    title: A
    severity: Low
    match: workflow_write_all
  - id: dup
    title: B
    severity: Low
    match: workflow_write_all
"#;
        let dir = std::env::temp_dir().join(format!("ghass-rules-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("dup.yml");
        std::fs::write(&path, yaml).unwrap();
        assert!(RuleSet::load(&path).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn load_rejects_invalid_regex() {
        let yaml = r#"
rules:
  - id: bad-regex
    title: A
    severity: Low
    match:
      uses_matches: "(unclosed"
"#;
        let dir = std::env::temp_dir().join(format!("ghass-rules-test-re-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("bad.yml");
        std::fs::write(&path, yaml).unwrap();
        assert!(RuleSet::load(&path).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn workflow_level_condition_ignores_jobs_and_steps() {
        let cond = Condition::TriggerEquals("pull_request_target".to_string());
        assert!(!cond.touches_step());
        assert!(!cond.touches_job());
        let wf = workflow(vec!["pull_request_target"], false);
        let ctx = MatchContext { workflow: &wf, job: None, step: None };
        assert!(cond.eval(&ctx));
    }

    #[test]
    fn job_level_condition_matches_self_hosted_runner() {
        let cond = Condition::RunsOnContains("self-hosted".to_string());
        assert!(cond.touches_job());
        assert!(!cond.touches_step());
        let wf = workflow(vec!["push"], false);
        let j = job("build", "self-hosted", vec![]);
        let ctx = MatchContext { workflow: &wf, job: Some(&j), step: None };
        assert!(cond.eval(&ctx));
    }

    #[test]
    fn step_level_condition_matches_uses_regex() {
        let cond = Condition::UsesMatches(r"^docker://".to_string());
        assert!(cond.touches_step());
        let wf = workflow(vec!["push"], false);
        let s = step(Some("docker://alpine:3.19"), None);
        let ctx = MatchContext { workflow: &wf, job: None, step: Some(&s) };
        assert!(cond.eval(&ctx));
        let s2 = step(Some("actions/checkout@v4"), None);
        let ctx2 = MatchContext { workflow: &wf, job: None, step: Some(&s2) };
        assert!(!cond.eval(&ctx2));
    }

    #[test]
    fn all_requires_every_leaf_to_match() {
        let cond = Condition::All(vec![
            Condition::TriggerEquals("push".to_string()),
            Condition::WorkflowWriteAll,
        ]);
        let wf_matches = workflow(vec!["push"], true);
        let wf_no_match = workflow(vec!["push"], false);
        let ctx1 = MatchContext { workflow: &wf_matches, job: None, step: None };
        let ctx2 = MatchContext { workflow: &wf_no_match, job: None, step: None };
        assert!(cond.eval(&ctx1));
        assert!(!cond.eval(&ctx2));
    }

    #[test]
    fn not_inverts_the_inner_condition() {
        let cond = Condition::Not(Box::new(Condition::TriggerEquals("push".to_string())));
        let wf = workflow(vec!["pull_request"], false);
        let ctx = MatchContext { workflow: &wf, job: None, step: None };
        assert!(cond.eval(&ctx));
    }
}
