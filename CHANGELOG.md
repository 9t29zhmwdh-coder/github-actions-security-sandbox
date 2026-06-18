# Changelog

## [0.1.0] (2026-06-18)

### Added

- YAML workflow parser supporting triggers, jobs, steps, permissions, env and with blocks
- Script injection analyzer: detects untrusted context expressions in run steps
- Pwn Request analyzer: detects pull_request_target combined with PR head checkout
- Excessive permissions analyzer: write-all, contents write, pull-requests write
- Action pinning analyzer: flags branch references, semantic tags, validates SHA format
- Secret exposure analyzer: secrets to third-party actions, secrets in env vars
- Self-hosted runner analyzer
- Output formats: table (tabled), JSON (serde_json), Markdown, HTML stub, SARIF 2.1.0 stub
- Severity filter via `--min-severity` flag
- Vulnerable and hardened example workflow files for testing
- Sample reports (JSON, Markdown)
- Threat model and attack vectors documentation
- GitHub Actions usage template for repo-level integration
- CI pipeline (ubuntu-latest + windows-latest)
