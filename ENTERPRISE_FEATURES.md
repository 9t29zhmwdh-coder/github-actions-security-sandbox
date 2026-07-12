# Enterprise Features

This document lists features planned for the Enterprise Edition of this
project, licensed separately under
[LICENSE.COMMERCIAL](LICENSE.COMMERCIAL). See [COMMERCIAL.md](COMMERCIAL.md)
for the licensing model.

## Status

No Enterprise features have shipped yet. This list is a forward-looking plan,
not a changelog of existing functionality: everything currently in this
repository is part of the Community Edition and remains MIT-licensed. See the
repository's own [ROADMAP.md](ROADMAP.md), "Dual-Licensing Readiness"
section, for the prerequisites that need to land first.

## Planned

- Org-wide custom policy authoring: a rule engine for organization-specific
  security policies, beyond the built-in analyzers.
- Native GHAS (GitHub Advanced Security) SARIF upload and Azure DevOps
  pipeline task wrapper, instead of a manual export/upload step.
- Findings dashboard across repositories: a consolidated view for
  organizations scanning many repositories, instead of a per-repo CLI run.

## Not planned

The core parser and built-in analyzers stay in the Community Edition
permanently. Dual-licensing governs only new, enterprise-shaped capabilities
such as the ones listed above, not the tool's standalone usefulness for a
single repository.
