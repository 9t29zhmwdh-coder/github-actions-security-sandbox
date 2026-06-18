# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 0.1.x | Yes |

## Reporting a Vulnerability

Please report security vulnerabilities by opening a GitHub issue with the label `security`.

Do not include exploit code or proof-of-concept payloads in public issues. Describe the vulnerability type, affected component, and potential impact. A response within 72 hours is the target.

## False Positive Handling

If ghass produces a false positive for a finding in your repository, open an issue with:

- The workflow file content (sanitized)
- The finding type and evidence string
- Why the finding is a false positive in your context

## Supply Chain Security

All actions used in the CI pipeline are pinned to specific commit SHAs. Dependencies are managed via `Cargo.lock`. The `Cargo.lock` file is committed to the repository.
