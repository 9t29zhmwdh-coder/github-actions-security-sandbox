# Changelog

## [0.1.7] (2026-07-12)

### Security

- Fixed two inaccurate claims in SECURITY.md: `dtolnay/rust-toolchain` was pinned to the mutable `stable` tag, not a commit SHA as the policy claimed, and `Cargo.lock` was gitignored, not committed as claimed. Both are now fixed for real: the action is pinned to its current `stable` commit, and `Cargo.lock` is committed for reproducible builds.
- Switched vulnerability reporting from a public GitHub issue label to GitHub Security Advisories (private reporting), matching the portfolio's standard practice.
- Added a `cargo audit` job to CI to actually catch known-vulnerable dependencies, closing the gap behind the policy's supply-chain security claim.

## [0.1.6] (2026-07-12)

### Added

- Dual-Licensing skeleton: LICENSE.COMMERCIAL, COMMERCIAL.md, and ENTERPRISE_FEATURES.md, documenting the licensing model for a future Enterprise Edition ahead of any actual feature split. The existing MIT LICENSE and all currently released code are unchanged; nothing in this repository is restricted by this addition.

## [0.1.5] (2026-07-11)

### Added

- Documented Dual-Licensing readiness assessment in ROADMAP.md.

## [0.1.4] (2026-07-11)

### Fixed

- Updated SHA-pinned actions/checkout and Swatinem/rust-cache to their latest major versions in CI, since GitHub is deprecating the Node.js 20 runtime and the previously pinned checkout version (v4.2.2) was being forced onto Node 24 and crashing during post-run cleanup.

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
