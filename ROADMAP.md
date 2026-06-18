# Roadmap

## v0.1.0 (current)

- [x] YAML workflow parser (triggers, jobs, steps, permissions, env, with)
- [x] Script injection detector
- [x] Pwn Request detector
- [x] Excessive permissions detector (write-all, contents/pull-requests write)
- [x] Action pinning analyzer (branch, tag, SHA)
- [x] Secret exposure detector (third-party actions, env var logging)
- [x] Self-hosted runner analyzer
- [x] Output formats: table, JSON, Markdown, HTML, SARIF stub
- [x] Severity filter via `--min-severity`
- [x] Vulnerable and hardened example workflows

## v0.2.0

- [ ] Full SARIF 2.1.0 output with location info (line numbers from YAML spans)
- [ ] Reusable workflow analysis (caller + callee permission inheritance)
- [ ] Matrix build support (detect injection in matrix variable interpolation)
- [ ] `workflow_dispatch` input validation checks
- [ ] CODEOWNERS-aware permission escalation detection

## v0.3.0

- [ ] GitHub API integration (optional): resolve unpinned action SHAs automatically
- [ ] Suppression file (`.ghass-ignore`) for accepted risk findings
- [ ] Custom rule definitions via YAML policy files
- [ ] JUnit XML output for test framework integration

## v1.0.0

- [ ] VS Code extension with inline diagnostics
- [ ] Pre-commit hook support
- [ ] Dependabot-compatible SHA update suggestions
- [ ] Documented stable public API for `ghass-scan` and `ghass-core`
