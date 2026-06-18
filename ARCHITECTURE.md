<div align="center">
  <img src="RayStudio.png" alt="RayStudio Logo" width="120"/>
  <h1>Architecture</h1>
</div>

## Workspace Layout

```
github-actions-security-sandbox/
├── crates/
│   ├── ghass-core/      Domain models, severity types, report serialization
│   ├── ghass-scan/      YAML parser, security analyzers
│   └── ghass-cli/       CLI binary (ghass)
├── examples/            Sample vulnerable and hardened workflow files
├── reports/             Sample report outputs (JSON, Markdown)
├── docs/                Threat model, attack vector reference
└── .github/workflows/   CI pipeline and usage template
```

## Data Flow

```
Input (YAML file or directory)
        |
        v
  ghass-scan::collect_workflows()
        |
        v
  ghass-scan::parser::parse_workflow_file()
        |  Produces: Vec<WorkflowFile>
        v
  ghass-scan::analyzers::run_all()
        |  Runs: script_injection, permissions,
        |        action_pinning, secrets, runner
        |  Produces: Vec<Finding>
        v
  Sort by severity (Critical first)
        |
        v
  ghass-core::report::to_*()
        |  Formats: table, json, md, html, sarif
        v
  stdout or file
```

## Crate Responsibilities

### ghass-core

Pure domain layer. No I/O, no YAML parsing.

- `models.rs`: `WorkflowFile`, `Job`, `Step`, `Permissions`, `Finding`, `ScanReport`, `FindingType`, `Severity`
- `report.rs`: Serialization functions (`to_json`, `to_markdown`, `to_html_stub`, `to_sarif_stub`)

### ghass-scan

All analysis logic. Depends only on `ghass-core`, `serde_yaml`, `walkdir`.

- `parser.rs`: Converts raw YAML `Value` tree into typed `WorkflowFile` structures
- `analyzers/script_injection.rs`: Detects untrusted context expressions in `run:` steps
- `analyzers/permissions.rs`: Detects Pwn Request patterns and excessive permission grants
- `analyzers/action_pinning.rs`: Checks all `uses:` references for SHA pinning
- `analyzers/secrets.rs`: Detects secrets passed to third-party actions or logged in env vars
- `analyzers/runner.rs`: Flags self-hosted runner usage

### ghass-cli

Thin CLI wrapper. Parses arguments via `clap`, calls `ghass_scan::scan_path`, applies severity filter, renders output.

- `main.rs`: Single-file binary with `scan` subcommand

## Finding Lifecycle

1. Parser produces `WorkflowFile` with normalized fields
2. Each analyzer receives `&WorkflowFile` and returns `Vec<Finding>`
3. All findings are merged and sorted by `severity.score()` descending
4. Severity filter is applied in the CLI layer (not in the scan library)
5. Report functions serialize the filtered `ScanReport`

## Adding a New Analyzer

1. Create `crates/ghass-scan/src/analyzers/<name>.rs`
2. Implement `pub fn analyze(workflow: &WorkflowFile) -> Vec<Finding>`
3. Register it in `crates/ghass-scan/src/analyzers/mod.rs` under `run_all`
4. Add a test case with a minimal workflow YAML string
