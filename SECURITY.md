# Security Policy

## Reporting a Vulnerability

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, report it via [GitHub Security Advisory](https://github.com/9t29zhmwdh-coder/github-actions-security-sandbox/security/advisories/new) or contact the maintainer via the GitHub profile.

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

A response within **48 hours** is the target, and I will work to resolve the issue promptly.

## False Positive Handling

If ghass produces a false positive for a finding in your repository, open a regular (non-security) GitHub issue with:

- The workflow file content (sanitized)
- The finding type and evidence string
- Why the finding is a false positive in your context

## Supply Chain Security

- All GitHub Actions used in the CI pipeline are pinned to a specific commit SHA, not a mutable tag or branch.
- Dependencies are managed via `Cargo.lock`, which is committed to the repository for reproducible builds.
- `cargo audit` (or equivalent) is run in CI to catch known-vulnerable dependencies.

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest  | ✅ Yes    |
| Older   | ❌ No     |

Security fixes are only applied to the latest release.
