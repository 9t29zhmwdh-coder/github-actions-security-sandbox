# Changelog

## [0.1.3] (2026-07-10)

### Fixed

- Removed em-dashes from README.md, replaced with colons for readability
- Changed the language-switch link from a blockquote to plain text to match the rest of the portfolio

## [0.1.2] (2026-07-10)

### Changed

- Moved the "New here? -> beginners guide" callout in README.md above the intro (previously only appeared near Requirements)

### Added

- Added the "New here?" beginner guide callout to README.de.md (was missing)

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
