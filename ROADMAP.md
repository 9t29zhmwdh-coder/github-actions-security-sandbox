# Roadmap

## v0.1.0

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

## v0.2.0 (current)

- [x] Custom policy/rule engine: org-specific rules from a YAML file via `--rules`, matching at step/job/workflow level (`uses_matches`, `run_contains`, `env_key_contains`, `runs_on_contains`, `job_write_all`, `trigger_equals`, `workflow_write_all`, `all`/`any`/`not`)

## v0.3.0

- [ ] Full SARIF 2.1.0 output with location info (line numbers from YAML spans)
- [ ] Reusable workflow analysis (caller + callee permission inheritance)
- [ ] Matrix build support (detect injection in matrix variable interpolation)
- [ ] `workflow_dispatch` input validation checks
- [ ] CODEOWNERS-aware permission escalation detection

## v0.4.0

- [ ] GitHub API integration (optional): resolve unpinned action SHAs automatically
- [ ] Suppression file (`.ghass-ignore`) for accepted risk findings
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

- [x] ~~No custom policy/rule engine yet~~ Shipped in v0.2.0 (`--rules`, see above): a Commercial tier's core value here is usually org-specific rule authoring, not just the built-in analyzers
- [ ] No native GHAS SARIF upload via the code scanning API yet (v1.0.0 item above), still a manual export/upload step today
- [ ] No VS Code extension or Azure DevOps pipeline task wrapper yet: both are natural distribution points for a paid tier
- [ ] No server or dashboard component to gate a Commercial tier against: today this is a pure local CLI with no persistence layer

Once native GHAS integration (v1.0.0) lands, revisit: candidate Enterprise-only features would be org-wide custom policy authoring at scale (a policy repository shared across many org repos, not just a local YAML file), native GHAS/Azure DevOps integration, and a findings dashboard across repositories, with the core parser, built-in analyzers, and the custom rule engine itself staying Community/MIT.
