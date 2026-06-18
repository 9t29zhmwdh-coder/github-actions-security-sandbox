# Contributing

Contributions are welcome. Please read the guidelines before opening a PR.

## Development Setup

```bash
git clone https://github.com/9t29zhmwdh-coder/github-actions-security-sandbox
cd github-actions-security-sandbox
cargo build --workspace
cargo test --workspace
cargo clippy --workspace -- -D warnings
```

## Adding an Analyzer

1. Create `crates/ghass-scan/src/analyzers/<name>.rs`
2. Implement `pub fn analyze(workflow: &WorkflowFile) -> Vec<Finding>`
3. Register in `crates/ghass-scan/src/analyzers/mod.rs`
4. Add at least one unit test using `parse_workflow_str`
5. Add a corresponding entry to the attack vectors table in README.md

## Code Style

- No Clippy warnings (`cargo clippy -- -D warnings` must pass)
- No em-dash or en-dash characters in source code or documentation
- All new findings must include `cwe`, `evidence`, `remediation`
- Public APIs must be documented with doc comments

## Pull Request Requirements

- CI must be green on both ubuntu-latest and windows-latest
- At least one test covering the new analyzer
- Update CHANGELOG.md with a description of the change
