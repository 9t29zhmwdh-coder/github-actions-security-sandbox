# Privacy

GitHub Actions Security Sandbox Simulator operates entirely offline.

- It reads `.yml` and `.yaml` files from your local filesystem.
- It does not make any network requests.
- It does not send telemetry, analytics, or diagnostic data.
- No GitHub API, Azure API, or any other external service is contacted.
- Workflow file contents are processed in memory and discarded after the scan completes.
- Report files are written only when explicitly requested via `--output`.
