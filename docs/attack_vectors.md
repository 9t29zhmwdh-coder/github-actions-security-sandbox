<div align="center">
  <img src="../RayStudio.png" alt="RayStudio Logo" width="120"/>
  <h1>Attack Vectors Reference</h1>
</div>

## Quick Reference: Vulnerable vs. Hardened Patterns

### Script Injection

**Vulnerable:**
```yaml
- name: Echo PR title
  run: echo "PR: ${{ github.event.pull_request.title }}"
```

**Hardened:**
```yaml
- name: Echo PR title
  env:
    PR_TITLE: ${{ github.event.pull_request.title }}
  run: echo "PR: $PR_TITLE"
```

**Why it works:** The environment variable assignment happens in the YAML layer, not the shell. The shell only sees the variable name, never the raw expression value.

---

### Pwn Request

**Vulnerable:**
```yaml
on:
  pull_request_target:

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.ref }}
      - run: npm test
```

**Hardened (two-workflow pattern):**

Workflow 1: `pr-test.yml` (triggered by `pull_request`, no secrets)
```yaml
on: pull_request
permissions: {}
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4
      - run: npm test
      - uses: actions/upload-artifact@v4
        with:
          name: test-results
          path: test-results/
```

Workflow 2: `pr-comment.yml` (triggered by `workflow_run`, has write permissions)
```yaml
on:
  workflow_run:
    workflows: [PR Test]
    types: [completed]
permissions:
  pull-requests: write
jobs:
  comment:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
        with:
          name: test-results
          run-id: ${{ github.event.workflow_run.id }}
      - name: Post comment
        # Post results using GITHUB_TOKEN write permission
```

---

### Action Pinning

**Vulnerable:**
```yaml
- uses: actions/checkout@v4          # tag: can be moved
- uses: some-org/action@main         # branch: always mutable
```

**Hardened:**
```yaml
- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
- uses: some-org/action@a4d7a2b1c3e9f0823456789abcdef0123456789ab # v1.5.0
```

**Tooling:** Use [pin-github-action](https://github.com/mheap/pin-github-action) or [Dependabot](https://docs.github.com/en/code-security/dependabot) to automate SHA pinning and updates.

---

### Least-Privilege Permissions

**Vulnerable:**
```yaml
permissions: write-all
```

**Hardened:**
```yaml
permissions: {}          # deny all at workflow level

jobs:
  test:
    permissions:
      contents: read     # only what this job needs
  deploy:
    permissions:
      contents: write
      deployments: write
```

---

### Self-Hosted Runner Hardening

**Recommendation checklist:**

- [ ] Use ephemeral runners (JIT runners or container-per-job)
- [ ] Run each job in an isolated container
- [ ] Isolate runner host in a dedicated network segment
- [ ] Do not use self-hosted runners for workflows triggered by fork PRs
- [ ] Rotate any credentials stored on the runner host regularly
- [ ] Monitor runner job logs for unexpected outbound network connections
