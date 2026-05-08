# ADR-001 — Monorepo bootstrap & tooling choices

- **Status:** accepted
- **Date:** 2026-05-08
- **Authors:** Winston (architect), Amelia (dev)
- **Stakeholders:** all engineers

## Context

Phase 0 of the build needs a stable repository skeleton before any feature work begins. We have three programming languages (Python for agents/control-plane, TypeScript for console, Go for edge), two licensing tiers (Apache 2.0 for the OSS foundation, BSL for proprietary packages), and a need for fast incremental builds.

## Decision

1. **Monorepo** with a single Git repository at `/Users/prabakarannagarajan/nexus cyber os/` (no trailing space).
2. **Turborepo** for cross-language task orchestration.
3. **pnpm** as the JS/TS package manager with workspaces.
4. **uv** as the Python package manager with workspace members.
5. **go.work** for Go modules.
6. **Husky + commitlint + lint-staged** for pre-commit enforcement.
7. **GitHub Actions with self-hosted runners on AWS** for CI.
8. **Apache 2.0** for `packages/charter/` and `packages/eval-framework/`; **BSL 1.1** with 4-year change-to-Apache for everything else.

## Consequences

### Positive

- Single source of truth for version, dependencies, breaking changes.
- Cross-package refactors land in one PR.
- Easy to enforce conventions (linting, formatting, commits) globally.
- Open-source split is a build-time concern, not a repo-split concern.

### Negative

- Repo grows large; clone time increases. Mitigation: Git LFS for binary assets when needed.
- CI matrix becomes more complex than per-repo CI. Mitigation: Turborepo task caching.

### Neutral / unknown

- BSL adoption among customers is unproven. May need to revisit if customer pushback is significant.

## Alternatives considered

### Alt 1: Polyrepo (one repo per package)

- Why rejected: cross-package refactors become coordination nightmares; release versioning across 25+ packages is the wrong problem to solve at Phase 0.

### Alt 2: Lerna or Rush instead of Turborepo

- Why rejected: Turborepo's speed and simplicity beat both for our scale.

### Alt 3: poetry instead of uv

- Why rejected: uv is materially faster (10-100x), workspace support is first-class, and Astral's tooling (ruff) is already adopted.

### Alt 4: Open-source everything (full Apache 2.0)

- Why rejected: vertical content packs and production NLAHs are core IP; giving them away undermines commercial defensibility (reference: J6 in PRD).

### Alt 5: Closed-source everything (no open-core)

- Why rejected: the runtime charter's value as a category-defining artifact requires open distribution; without an open foundation, we have no community moat.

## References

- Build roadmap: `docs/superpowers/plans/2026-05-08-build-roadmap.md`
- PRD section J6 (open-source split)
- Spike P0.5 (charter contract validator) — informs charter package boundaries
