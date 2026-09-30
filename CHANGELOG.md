# Changelog

## [0.4.2] - 2026-09-30

### Changed

Dependency and CI updates merged since v0.4.1, each with green checks:

- chore(ci): bump the actions group with 3 updates (#45)

---

## [0.4.1] - 2026-09-27

### Changed

Dependency and CI updates merged since v0.4.0, each with green checks:

- chore(deps): bump clap in the cargo group across 1 directory (#38)
- chore(ci): bump the actions group across 1 directory with 6 updates (#41)

---

## [0.4.0] - 2026-09-25

Checked against crafted workflows (real attacks and safe patterns) and against the workflows of 30 repositories; two real attack paths were missed and several findings were wrong.

### Fixed

- **Script injection in `actions/github-script` was not detected.** Its `script` input runs as JavaScript; an expression there is code injection just like in `run`.
- **Expressions without spaces were missed** (`${{github.event.issue.title}}`): matching looked for exact strings. Expressions are now parsed, including `format(...)`, `toJSON(github.event.pull_request)` and `commits[0].message`.
- **Every `github.event.*` value counted as injection**, including values nobody outside can set (`pull_request.number`, `head.sha`, `repository.full_name`). Only the fields GitHub Security Lab lists as attacker-controlled are Critical now; workflow inputs, which only writers can set, are Medium.
- **Pwn Request via the merge ref was missed** (`refs/pull/N/merge`, `github.event.number`, `merge_commit_sha`), as was fetching PR code in a shell step (`gh pr checkout`, `git fetch … pull/…`).
- **Docker pinning was inverted:** `docker://alpine` (implicitly `latest`) passed and an image pinned by `sha256` digest was flagged.
- `permissions: {}` (the strictest setting) and blocks with other scopes such as `packages: write` were read as "no permissions declared".

### Added

- Job-level `contents: write` / `pull-requests: write` in workflows that outsiders can trigger (`pull_request_target`, `issue_comment`, `issues`, `workflow_run`, `discussion_comment`). A release job with scoped write access stays clean, as recommended.
- Low finding when neither the workflow nor a job declares `permissions:`: the token then gets the repository default, read/write in older repositories.

## [0.3.7] - 2026-08-03

### Changed

- `tabled` 0.15 to 0.21. The derive attributes and `Table::new` are unchanged across the jump, and the findings table renders exactly as before.
- `github/codeql-action` 4.37.3 to 4.37.4 and `actions/attest` 4.2.0 to 4.2.1, merged separately and carried by this version. All pinned SHAs were checked against the tags their comments name.

### Added

- A test that holds the exact rendered findings table. That table is what a user sees after a scan, so a bump that shifts a border character or a column width is visible to everyone and to no compiler. It was written and made to pass under 0.15 first, then run unchanged under 0.21.

---

## [0.3.6] - 2026-07-31

### Changed

- Both READMEs now open with three named workflow mistakes and what each one hands an attacker, rather than with the vulnerability classes the scanner detects. A short paragraph is honest that a private repository with trusted contributors has little of this surface, so the findings there stay theoretical.

---

## [0.3.5] - 2026-07-29

### Security

- The release workflow no longer grants `contents: write` for its whole run. The permission moves to the one job that publishes the release, and everything else runs with `contents: read`. OpenSSF Scorecard scores the Token-Permissions check 0 out of 10 whenever any workflow holds a top-level write permission, regardless of how little of the run needs it, so this single line was what held the check at zero.

---

## [0.3.4] - 2026-07-29

### Changed

Dependency and workflow updates merged since 0.3.3:

- chore(ci): bump the actions group across 1 directory with 3 updates
- chore(deps): bump the cargo group across 1 directory with 7 updates

---

## [0.3.3] - 2026-07-29

### Changed

- CodeQL moved from GitHub's default setup to an advanced setup with a committed `.github/workflows/codeql.yml`. The default setup decides on its own when to run and skips pull requests that touch no code of a given language, so a dependency pull request changing only `Cargo.lock` reported `skipping` on the required `Analyze` checks and could never be merged. The workflow runs on every pull request regardless of what changed and uses the `security-extended` query suite, which the default setup does not allow choosing. Required checks are unchanged.
- The Cargo group in `.github/dependabot.yml` is limited to `minor` and `patch` updates. Without that limit a major bump lands inside a grouped pull request that reads as routine, which is how a breaking change slips in unreviewed.

---

## [0.3.2] - 2026-07-28

### Added

- `.github/dependabot.yml`, covering GitHub Actions and Cargo with grouped weekly updates. The file was missing, and without it there are no version updates at all: repository security alerts only fire for disclosed vulnerabilities. Follows `engineering-standards` v0.10.0.

### Fixed

- `actions/checkout` pins were inconsistent across workflows. All now use v7.0.1 with the full version in the comment, per `standards/ci-cd.md` section 2.


### Note

- Version 0.3.1 was tagged and released on 2026-07-20 without the crate manifests being bumped; they stayed on 0.3.0. This release corrects that: the manifests now carry the version, inherited from a single `[workspace.package]`. `release-process.md` section 2 asks for the version to be bumped in every file that carries one and for the intended tag to be checked against existing ones before tagging, which is what surfaced this.

## [0.3.1] - 2026-07-20

### Changed

- OpenSSF Scorecard workflow and badge.
- `copilot-instructions.md` for consistent AI-assisted contributions.
- Unified the EN/DE language-switch link format and restored a missing README section in German.
- Split the README's security/CI badges onto their own line, separate from the platform/tech/AI badges (they were rendering as a single merged line).

## [0.3.0] (2026-07-15)

### Added

- Full SARIF 2.1.0 output (`ghass scan --format sarif`): each result now includes a best-effort `region.startLine`, resolved by a new text-based line index (`ghass_scan::line_index`) that maps parsed jobs/steps back to their source line without needing a span-aware YAML parser. Results also carry a stable `partialFingerprints` hash so tools consuming this output (e.g. GitHub code scanning) can dedupe the same finding across repeated scans. This replaces the previous stub, which always emitted an empty `results` array.
- `Job`, `Step`, and `Finding` now carry a `line: Option<usize>` field.

### Fixed

- The SARIF `tool.driver.version` field was hardcoded to `"0.1.0"` regardless of the actual release; it now reads `env!("CARGO_PKG_VERSION")` like the rest of the CLI.
- `examples/hardened_workflow.yml`'s "expected findings: none" example workflow actually produced one `UnpinnedAction` finding, because its placeholder commit SHA was 41 hex characters instead of 40. Fixed the fixture; added a regression test (`ghass-scan/tests/scan_examples.rs`) asserting the hardened example stays clean.

### Testing

- Added 78 unit/integration tests for the 6 previously-untested analyzer modules, the parser, and the report formatters (none of this had test coverage before this release cycle, aside from the custom rule engine).

## [0.2.0] (2026-07-13)

### Added

- Custom rule engine: `ghass scan --rules <file.yml>` evaluates org-specific policy rules from a YAML file alongside the built-in analyzers. Each rule matches at step, job, or workflow level (inferred from which condition it uses) via `uses_matches`, `run_contains`, `env_key_contains`, `runs_on_contains`, `job_write_all`, `trigger_equals`, `workflow_write_all`, and the combinators `all`/`any`/`not`. Matches show up in every existing output format tagged `Custom Rule: <id>`. See the new "Custom Rules" README section and `examples/custom-rules.yml`.
- This closes one of the two explicit blockers in this repo's Dual-Licensing Readiness assessment (see ROADMAP.md); native GHAS SARIF upload via the code scanning API remains open and needs live GitHub API access.

### Fixed

- `ghass --version` now reads the crate version from Cargo.toml instead of a hardcoded string that had drifted out of sync with actual releases.

## [0.1.8] (2026-07-12)

### Fixed

- Removed em-dashes from GETTING_STARTED.md. Swiss German orthography rule.

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
