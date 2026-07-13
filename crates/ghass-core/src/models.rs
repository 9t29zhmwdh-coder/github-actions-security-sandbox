use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowFile {
    pub path: String,
    pub name: String,
    pub triggers: Vec<String>,
    pub jobs: Vec<Job>,
    pub global_permissions: Option<Permissions>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Job {
    pub id: String,
    pub runs_on: String,
    pub permissions: Option<Permissions>,
    pub steps: Vec<Step>,
    pub is_reusable_call: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Step {
    pub name: Option<String>,
    pub uses: Option<String>,
    pub run: Option<String>,
    pub env: Vec<(String, String)>,
    pub with: Vec<(String, String)>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Permissions {
    pub contents: Option<String>,
    pub pull_requests: Option<String>,
    pub write_all: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Informational,
}

impl Severity {
    pub fn score(&self) -> u8 {
        match self {
            Severity::Critical => 4,
            Severity::High => 3,
            Severity::Medium => 2,
            Severity::Low => 1,
            Severity::Informational => 0,
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
            Severity::Informational => "INFO",
        };
        write!(f, "{}", s)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FindingType {
    ScriptInjection,
    UnpinnedAction,
    ExcessivePermissions,
    SecretExposure,
    SelfHostedRunner,
    PwnRequest,
    /// Matched a user-authored rule from a custom rules YAML file; carries the rule id.
    Custom(String),
}

impl std::fmt::Display for FindingType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FindingType::ScriptInjection => write!(f, "Script Injection"),
            FindingType::UnpinnedAction => write!(f, "Unpinned Action"),
            FindingType::ExcessivePermissions => write!(f, "Excessive Permissions"),
            FindingType::SecretExposure => write!(f, "Secret Exposure"),
            FindingType::SelfHostedRunner => write!(f, "Self-Hosted Runner"),
            FindingType::PwnRequest => write!(f, "Pwn Request"),
            FindingType::Custom(id) => write!(f, "Custom Rule: {}", id),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub workflow: String,
    pub job_id: Option<String>,
    pub step_name: Option<String>,
    pub finding_type: FindingType,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub evidence: String,
    pub remediation: String,
    pub cwe: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScanReport {
    pub scanned_at: DateTime<Utc>,
    pub workflow_count: usize,
    pub finding_count: usize,
    pub findings: Vec<Finding>,
    pub summary: FindingSummary,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct FindingSummary {
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub informational_count: usize,
}
