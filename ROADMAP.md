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
- [ ] GitHub Advanced Security (GHAS) native SARIF upload via code scanning API
- [ ] Azure DevOps pipeline task wrapper
- [ ] Documented stable public API for `ghass-scan` and `ghass-core`

## Dual-Licensing Readiness

Assessed 2026-07-11 as a Dual-Licensing candidate (Community MIT + Commercial/Enterprise tier): CI/CD pipeline security scanning is a well-established commercial category (StepSecurity sells exactly this capability for GitHub Actions with a free tier), and this project's own roadmap already lists several classic enterprise differentiators. Not ready yet; blocked on:

- [ ] No custom policy/rule engine yet (v0.3.0 item above): a Commercial tier's core value here is usually org-specific rule authoring, not just the built-in analyzers
- [ ] No native GHAS SARIF upload via the code scanning API yet (v1.0.0 item above), still a manual export/upload step today
- [ ] No VS Code extension or Azure DevOps pipeline task wrapper yet: both are natural distribution points for a paid tier
- [ ] No server or dashboard component to gate a Commercial tier against: today this is a pure local CLI with no persistence layer

Once the custom rule engine (v0.3.0) and native GHAS integration (v1.0.0) land, revisit: candidate Enterprise-only features would be org-wide custom policy authoring, native GHAS/Azure DevOps integration, and a findings dashboard across repositories, with the core parser and built-in analyzers staying Community/MIT.
