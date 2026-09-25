# GitHub Actions Security Report

**Scanned at:** 2026-09-25 06:56 UTC  
**Workflows:** 1  
**Findings:** 8

---

## Summary

| Severity | Count |
|---|---|
| Critical | 2 |
| High | 4 |
| Medium | 2 |
| Low | 0 |
| Informational | 0 |

---

## Findings

### 🔴 `CRITICAL` | Script Injection | `examples/vulnerable_workflow.yml`

**Job:** `build`  
**Step:** `Greet contributor`  
**Evidence:** `${{ github.event.pull_request.title }}`  

**Description:** Job 'build' interpolates data an outsider controls directly into a run step. The value is pasted into the shell script before it runs, so whoever controls it (anyone who can open an issue, a pull request or a comment) can run arbitrary commands with the job's GITHUB_TOKEN and secrets.  

**Remediation:** Pass the value through an environment variable and use the variable instead: `env: TITLE: ${{ github.event.issue.title }}` and `"$TITLE"` in the shell (or `process.env.TITLE` in github-script).  

**CWE:** CWE-78: OS Command Injection  

### 🔴 `CRITICAL` | Pwn Request | `examples/vulnerable_workflow.yml`

**Job:** `build`  
**Step:** `Checkout PR head`  
**Evidence:** `trigger=pull_request_target, checkout ref=${{ github.event.pull_request.head.ref }}`  

**Description:** Workflow is triggered by 'pull_request_target' and job 'build' checks out the PR contributor's code. The untrusted code runs with full write permissions and access to all repository secrets. This is the classic Pwn Request attack vector.  

**Remediation:** Never check out PR head code in pull_request_target workflows. Use a two-workflow pattern: a pull_request workflow runs the untrusted code with no secrets; a separate pull_request_target workflow handles write operations after downloading artifacts from the first run.  

**CWE:** CWE-913: Improper Control of Dynamically-Managed Code Resources  

### 🟠 `HIGH` | Excessive Permissions | `examples/vulnerable_workflow.yml`

**Evidence:** `permissions: write-all`  

**Description:** The workflow grants write access to all scopes at the top level. All jobs inherit these permissions, including jobs that do not require write access.  

**Remediation:** Apply the principle of least privilege. Set `permissions: {}` at the workflow level to deny all by default, then grant only the specific permissions each job requires.  

**CWE:** CWE-250: Execution with Unnecessary Privileges  

### 🟠 `HIGH` | Unpinned Action | `examples/vulnerable_workflow.yml`

**Job:** `build`  
**Step:** `Build with third-party action`  
**Evidence:** `some-org/build-action@main`  

**Description:** Action 'some-org/build-action@main' is pinned to mutable branch 'main'. A compromised upstream repository or tag move can inject arbitrary code into your workflow without notice.  

**Remediation:** Replace with a SHA-pinned reference: `uses: some-org/build-action@<40-hex-SHA>  # was: main`  

**CWE:** CWE-829: Inclusion of Functionality from Untrusted Control Sphere  

### 🟠 `HIGH` | Secret Exposure | `examples/vulnerable_workflow.yml`

**Job:** `build`  
**Step:** `Build with third-party action`  
**Evidence:** `with.api-key: ${{ secrets.BUILD_API_KEY }}`  

**Description:** Job 'build' passes a repository secret via parameter 'api-key' to third-party action 'some-org/build-action@main'. A compromised or malicious action version can exfiltrate the secret to an external endpoint.  

**Remediation:** Pin 'some-org/build-action@main' to a verified commit SHA before passing secrets. Review the action source code at the pinned commit and consider whether a first-party alternative exists.  

**CWE:** CWE-522: Insufficiently Protected Credentials  

### 🟠 `HIGH` | Secret Exposure | `examples/vulnerable_workflow.yml`

**Job:** `build`  
**Step:** `Build with third-party action`  
**Evidence:** `with.token: ${{ secrets.GITHUB_TOKEN }}`  

**Description:** Job 'build' passes a repository secret via parameter 'token' to third-party action 'some-org/build-action@main'. A compromised or malicious action version can exfiltrate the secret to an external endpoint.  

**Remediation:** Pin 'some-org/build-action@main' to a verified commit SHA before passing secrets. Review the action source code at the pinned commit and consider whether a first-party alternative exists.  

**CWE:** CWE-522: Insufficiently Protected Credentials  

### 🟡 `MEDIUM` | Unpinned Action | `examples/vulnerable_workflow.yml`

**Job:** `build`  
**Step:** `Checkout PR head`  
**Evidence:** `actions/checkout@v4`  

**Description:** Action 'actions/checkout@v4' uses semantic version tag 'v4'. Tags are mutable and can be reassigned by the action author. Pin to a full 40-character commit SHA for reproducible builds.  

**Remediation:** Replace with a SHA-pinned reference: `uses: actions/checkout@<40-hex-SHA>  # was: v4`  

**CWE:** CWE-829: Inclusion of Functionality from Untrusted Control Sphere  

### 🟡 `MEDIUM` | Self-Hosted Runner | `examples/vulnerable_workflow.yml`

**Job:** `build`  
**Evidence:** `runs-on: self-hosted`  

**Description:** Job 'build' runs on a self-hosted runner (self-hosted). Self-hosted runners are persistent, reachable from within your network, and retain state between workflow runs. A compromised workflow can pivot to internal systems, read cached credentials, or tamper with build artifacts.  

**Remediation:** Run self-hosted runners in ephemeral containers to prevent state persistence between jobs. Isolate runners in a dedicated network segment. For workflows triggered by external contributors, prefer GitHub-hosted runners. Use Just-in-Time (JIT) runners where possible.  

**CWE:** CWE-653: Insufficient Isolation or Compartmentalization  

---

*Generated by GitHub Actions Security Sandbox Simulator. RayStudio*
