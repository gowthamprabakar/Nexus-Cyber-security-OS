# ADR-010 — Version-extension template (vN → vN+1 within-agent)

- **Status:** accepted
- **Date:** 2026-05-17
- **Authors:** AI/Agent Eng
- **Stakeholders:** every agent author shipping a within-agent version extension; reviewers of vN+1 PRs; compliance (audit-chain consistency across versions of the same agent)

## Context

Four within-agent version extensions have shipped to date:

- **D.6 Kubernetes Posture** — v0.1 (2026-05-13) → v0.2 (2026-05-16, live cluster API) → v0.3 (2026-05-16, in-cluster ServiceAccount mode)
- **A.1 Remediation Agent** — v0.1 (2026-05-16) → v0.1.1 (2026-05-17, earned-autonomy pipeline)

The pattern is empirically settled. Each extension shipped under the same shape: a per-version plan doc with execution-status table, a companion verification record (not a replacement for the initial-version's implementation record), task-commit hashes pinned in the plan, and a hard "no breaking changes to the prior version's contracts" invariant enforced by re-running the prior version's full test surface as a gate.

Each subsequent extension benefited from looking at the prior one to figure out shape. Without an ADR, the pattern drifts agent-by-agent: D.6's verification record has slightly different sectioning than A.1 v0.1.1's; A.1 v0.1.1's plan has a process-notes section D.6 v0.3 didn't need. The drift is bounded today; it won't stay bounded once F.7, A.1 v0.2, A.1 v0.3, D.6 v0.4+, D.5 v0.2, F.3 v0.2, and the rest of the Phase-1c slate start landing in parallel.

The plan that motivated this ADR is **F.7 fabric runtime** ([next plan in the platform-line sequence after A.1 v0.1.1 closed](../_meta/a1-v0-1-1-verification-2026-05-17.md#immediate-next-plan-gate-non-negotiable)). F.7 v0.1 will itself spawn v0.2 (D.7 migration onto the bus), v0.3 (next migrated surface), and so on. F.7 should inherit the codified shape, not invent it.

## Decision

**Every within-agent version extension follows the template below.** Deviations are recorded in the version's plan doc with explicit reasoning.

### What "within-agent version extension" means concretely

This ADR applies when **all** of the following hold for a planned change:

1. The change ships under the same package directory as the prior version (e.g., `packages/agents/remediation/` for A.1 v0.1.1, not a new package).
2. The change extends a single agent's surface — new tools, new modes, new flags, new audit events, new eval cases, new live tests — without renaming, removing, or repurposing anything the prior version exposed.
3. The change keeps the agent's OCSF wire shape (`class_uid`) unchanged.
4. The change keeps the agent's F.6 audit-chain action vocabulary additive — new actions are allowed, existing actions cannot be renamed or repurposed.
5. The change keeps the agent's existing CLI subcommand surface unchanged. New subcommands or new options on existing subcommands are allowed; removing or renaming existing ones is not.
6. The change keeps the agent's existing Python public API parameters unchanged. New optional params with safe defaults are allowed; required-param additions, removals, or renames are not.

**If any of those fail, the change is NOT a within-agent version extension** and requires either a new ADR for the agent (per ADR-007's "deltas from the template are recorded in per-agent ADRs" rule) or a major-version replan that supersedes the prior plan. See [When this template stops applying](#when-this-template-stops-applying) below.

### The plan-doc shape

The version's plan doc (in `docs/superpowers/plans/YYYY-MM-DD-<agent>-v<X.Y>-<scope>.md`) carries these sections in this order:

| Section                     | Required content                                                                                                                                                                                                                                                                    |
| --------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Title**                   | `# <Agent name> v<X.Y.Z> — <one-line scope>` (e.g., `# D.6 v0.2 — Live cluster API ingest`). The version string is the new version; the scope is two-to-six words that name the surface change.                                                                                     |
| **Agentic-worker preamble** | One-line `REQUIRED SUB-SKILL` block naming the executing-plans / subagent-driven-development skill, plus the "Pause for review after each numbered task" cadence statement.                                                                                                         |
| **Goal**                    | One-to-three paragraphs framing the change explicitly as an extension of the prior version. Must name (a) what changes (the new surface) and (b) what doesn't (the wire shape, the API, the prior version's eval cases).                                                            |
| **Scope**                   | What the version ships AND what it explicitly defers. Deferred items name the future-version plan that will cover them.                                                                                                                                                             |
| **Strategic role**          | Why this version is the next plan rather than some other version of this agent or a different agent. Cross-references the readiness report / platform-line ADR where applicable.                                                                                                    |
| **Resolved questions**      | Q-table with columns `# · Question · Resolution · Task`. Every non-obvious design choice the version surfaces gets a Q row before any task ships. This is the audit trail for "why was X decided this way?".                                                                        |
| **Architecture**            | Shorter than the initial-version plan's architecture section — only the **delta** vs. the prior version's architecture. Cross-reference the prior plan's architecture for shared substrate.                                                                                         |
| **Execution status**        | Plan-status table with columns `# · Status · Commit · Notes`. The agent author pins the commit hash after each task lands. This table is **single source of truth** for task-commit pinning; the verification record cites it, never duplicates it.                                 |
| **Compatibility contract**  | Explicit list of what doesn't change vs. the prior version. Cross-reference the six invariants from §"What 'within-agent version extension' means concretely" above. Reviewers check this list against the actual diff before merging.                                              |
| **Defers**                  | List of items the plan explicitly does NOT do, with the future-version plan that will cover each. Includes the next-version's working title where known.                                                                                                                            |
| **Reference template**      | Single sentence: "Follows [ADR-007](../../_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md) (reference NLAH) + [ADR-010](../../_meta/decisions/ADR-010-version-extension-template.md) (this version-extension template)." Deltas from either, if any, get their own ADR. |

The "Pause for review after each numbered task" cadence is preserved — the task-by-task review discipline is independent of this ADR and predates it. ADR-010 doesn't change task-level discipline; it codifies the document-level shape.

### The verification-record shape

The version's verification record (in `docs/_meta/<agent>-v<X.Y.Z>-verification-YYYY-MM-DD.md`) is a **companion** to the initial-version's implementation record, **not a replacement** for it.

| Section                                      | Required content                                                                                                                                                                                                                                                                                                  |
| -------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Title**                                    | `# <Agent> v<X.Y.Z> verification record — YYYY-MM-DD`.                                                                                                                                                                                                                                                            |
| **Opening paragraph**                        | Names the companion relationship to the prior implementation record (e.g., A.1 v0.1.1's record links back to `a1-verification-2026-05-16.md` for v0.1). Frames the version's strategic role in two-to-three sentences.                                                                                            |
| **Gate results**                             | Table with columns `Gate · Threshold · Result`. Includes the same gates as the initial-version record (pytest -q, ruff, ruff format, mypy strict, eval suite count) **plus** any new version-specific gates (e.g., live-cluster gates from G3; per-mode behaviour gates from A.1 v0.1.1's pre-flight stage gate). |
| **Repo-wide sanity check**                   | Test count delta vs the prior version's baseline. Skip-count delta if new gated lanes were added.                                                                                                                                                                                                                 |
| **Per-task surface**                         | Either a headline-level table mirroring the plan's execution-status table OR a paragraph stating "pinned in the plan's execution-status table with full per-task notes" + a cross-reference. The plan-status table is the source of truth; the verification record CITES it.                                      |
| **ADR-007 conformance**                      | Table with rows per convention (charter context, OCSF wire, audit-chain vocab, NLAH loader, eval-framework integration, CLI surface, test layout, output contract) and a delta column. Most rows should read "Unchanged" — that's the whole point of the version-extension framing.                               |
| **Coverage delta**                           | File-by-file LOC and test-count delta vs the prior version. Documents the additive-code-paths invariant empirically.                                                                                                                                                                                              |
| **Breaking-change note** (if any)            | Required only if some change is breaking despite the version-extension framing. Forces explicit operator-facing migration text. Most versions should not need this.                                                                                                                                               |
| **Process notes** (if any)                   | Used when the version's execution surfaced a process boundary worth recording (e.g., A.1 v0.1.1's four-boundary section recording the PR-flow → CI-gap → broken-proof history). Optional.                                                                                                                         |
| **Permanent documented limitation** (if any) | Used when the version's design has a limitation that needs permanent visibility, not just docstring documentation (e.g., A.1 v0.1.1's `reconcile_matches` evidence-only-parity limitation). Optional.                                                                                                             |
| **Closing sign-off**                         | One-to-two paragraphs stating what the version closed, what carries forward, and what the next-version gate is.                                                                                                                                                                                                   |

### The invariants this template enforces

1. **No breaking changes to the prior version's contracts.** The six conditions in §"What 'within-agent version extension' means concretely" are checked as the version-eligibility test. Reviewers verify them against the diff before merging.
2. **Additive code paths.** New modules, new methods, new optional params, new audit-event types — not modification of existing public surface. Internal refactors are allowed; public-surface modifications are not. (Internal refactors that nonetheless change behaviour of the prior public surface count as breaking changes and are out of scope.)
3. **Prior version's tests stay green.** The verification record's gate table explicitly asserts "no behavioural regression" against the prior version. If a prior-version test fails, the version is not eligible to ship under this template until the failure is resolved or explicitly justified as an intentional behaviour change (which makes it a breaking change and disqualifies the version-extension framing).
4. **Plan-status table is single source of truth for task-commit hashes.** Verification record cites; does not duplicate. The single-source-of-truth rule prevents the version's task-hash drift across two parallel records.

These four invariants are the load-bearing contract this ADR establishes. Reviewers check them on every version PR before merging.

### When this template stops applying

The version-extension template covers the productive case where the agent's external surface evolves additively. It does **not** cover:

1. **OCSF `class_uid` changes.** A new wire class is a new producer, not a version extension. Requires a fresh per-agent ADR if it's a delta from ADR-007's "first producer of class_uid X" pattern.
2. **F.6 audit-chain action rename or repurpose.** Renaming `remediation.action_refused` to `remediation.action_blocked` is a breaking change for downstream chain consumers regardless of whether the agent's CLI looks the same. Requires either a coordinated rename across consumers (with a separate plan) or a v(N+1).0 major-version replan.
3. **Removal of a CLI subcommand or option.** Even if the operator surface gains as much as it loses, the removal breaks scripts that relied on the prior surface. Requires the same v(N+1).0 replan, or an explicit deprecation cycle (deprecate in v0.X, remove in v0.X+1 — with the deprecation itself running through this template).
4. **Required-param additions on the Python public API.** Optional params with safe defaults are additive; required params are breaking. Same disposition as CLI removals.
5. **Cross-agent fan-out.** If a "version of one agent" plan touches multiple agents' surfaces, it isn't a within-agent extension — it's a multi-agent change and warrants either a multi-agent ADR or splitting into per-agent extensions.

In each of those cases the change is a major-version replan, not a version extension. The replan's plan-doc may still echo the structure above (the agentic-worker preamble, the resolved-questions table, the execution-status table), but the **verification record is an implementation record** (replaces the prior version's), not a companion to it, because the new version doesn't preserve the prior version's contracts.

## Consequences

### Positive

- **Plan-doc shape is codified once, applied consistently.** Future version-extension plans inherit the shape directly. Reviewers know what sections to expect and where.
- **Verification record is companion, not duplicate.** The initial-version's implementation record is preserved as the source of truth for v0.1's claims; each subsequent version's record extends rather than replaces. Operators reading "what does A.1 currently do" don't have to read three full implementation records — they read v0.1's plus the v0.1.1 / v0.1.2 / etc. companions.
- **Plan-status table is single source of truth.** Task-commit hashes pin once. Verification records cite. The Task-13 slip mode (proof and plan-pin landed in separate commits, the proof's actual code was never staged) is harder to reach when there's only one place where the task↔commit binding lives.
- **The six-condition eligibility test catches misuse.** A change that wants to call itself a "version extension" but renames a CLI flag is caught at the eligibility check, not at merge time after operators have started scripting against the new surface.
- **F.7 inherits the shape directly.** F.7 v0.1 (bus runtime) → F.7 v0.2 (first agent migration) → F.7 v0.3+ each follows this template. The "land the substrate, then migrate consumers one at a time" pattern that the F.7 plan explicitly chose over the scope-collapse alternative becomes the operating model for every infrastructure surface.

### Negative

- **Sectioning rigidity.** Some future extension might have a section the template doesn't anticipate. Mitigation: the template names which sections are required; additional sections are allowed without ADR amendment. The verification record's "Process notes" and "Permanent documented limitation" sections are already labelled optional and document the pattern of adding new sections as warranted.
- **Verification-record duplication risk.** Even with "companion not replacement" framing, there's pressure to copy gate-result tables forward from the prior record. Mitigation: the ADR explicitly says to keep the gate table fresh per version (the gates may differ — A.1 v0.1.1 added live-cluster gates D.6 didn't have); but the conformance and coverage tables should be deltas, not full restates.
- **Major-version replans still need their own discipline.** ADR-010 doesn't help when a change is too big for the version-extension framing. The §"When this template stops applying" list names the cases; for each, the replan still needs its own structure. Acceptable: this ADR is scoped to within-agent extensions; major replans are out of scope.

### Neutral / unknown

- **Cross-agent versioning.** F.7 specifically blurs the line — it's an infrastructure surface, not an agent surface, but its v0.1 → v0.2 → v0.3 trajectory has agent characteristics. The §"When this template stops applying" item 5 names cross-agent fan-out as a non-extension; F.7 v0.2 (D.7 migration) is technically a D.7 surface change, but the F.7 v0.2 plan should be written as F.7's plan (the migration is bus-side work) with D.7's surface treated as a documented compatibility contract. The F.7 plan author exercises judgment here; if F.7 v0.2's scope creeps into modifying D.7's CLI surface, it splits.
- **What about within-agent breaking changes that are clearly the right call?** The ADR rules them out under the version-extension framing; the right call is a major-version replan. We have no instances of this in flight, so the policy is consequence-free until one arises. When it does, the replan's first task will be re-asserting the framing.

## Alternatives considered

### Alt 1: Let each version-extension plan invent its own shape

- Why rejected: empirically already starting to drift between D.6 v0.2/v0.3 and A.1 v0.1.1's records. Codifying now is cheap; codifying after F.7 + A.1 v0.2 + F.3 v0.2 have landed under three different shapes is significantly more expensive.

### Alt 2: A heavyweight ADR per version (not per agent)

- Why rejected: would require ADR-001-per-agent-per-version (D.6 v0.2 = its own ADR; A.1 v0.1.1 = its own ADR). Substantially more bureaucracy than the four shipped extensions warranted. The pattern is shared across versions of the same agent and across versions of different agents — one shared ADR captures it.

### Alt 3: Make version extensions a section of ADR-007 instead of a new ADR

- Why rejected: ADR-007 covers the reference-NLAH for **initial-version** agents. Adding a "and here's how to extend them" section would conflate the "first version of agent X" question with the "next version of agent X" question. Two separate concerns; two separate ADRs.

### Alt 4: Tooling instead of ADR

- Why rejected: a `plan-template-vN` skill or a yamllint-style schema check would enforce shape mechanically. Worth doing eventually; out of scope for ADR-010. The ADR establishes the shape; tooling that enforces the shape is a future amendment with its own implementation plan.

## What this ADR commits us to

1. **The four currently-shipped extensions (D.6 v0.2, D.6 v0.3, A.1 v0.1.1) are the empirical reference implementations of the template.** PR reviewers comparing a new extension's shape can cite these as worked examples.
2. **F.7 v0.1's plan, when written, follows this template.** F.7 is the first plan written _after_ ADR-010 is accepted; if F.7 deviates, ADR-010 needs an amendment, not an exception.
3. **Within-agent breaking changes go through major-version replans, not version extensions.** The six eligibility conditions are checked at plan-doc time and re-checked at PR-review time.
4. **The companion-not-replacement framing for verification records is the operating norm.** A.1's record at HEAD is now three documents: `a1-verification-2026-05-16.md` (v0.1 implementation, source of truth for what shipped) + `a1-safety-verification-2026-05-16.md` (safety contract, cross-version) + `a1-v0-1-1-verification-2026-05-17.md` (v0.1.1 companion). Future versions add companions; they don't rewrite v0.1's record.
5. **ADR-010 amends itself rather than being superseded** for routine tweaks. A v1.1 amendment that adds "process notes" as a required section (rather than optional) would be the operating model — same as ADR-007's v1.1/v1.2/v1.3 amendment cadence.

## References

- **D.6 v0.1 → v0.2 plan + record**: [`2026-05-16-d-6-v0-2-live-cluster-api.md`](../../superpowers/plans/2026-05-16-d-6-v0-2-live-cluster-api.md) + [`d6-v0-2-verification-2026-05-16.md`](../d6-v0-2-verification-2026-05-16.md)
- **D.6 v0.2 → v0.3 plan + record**: [`2026-05-16-d-6-v0-3-in-cluster-mode.md`](../../superpowers/plans/2026-05-16-d-6-v0-3-in-cluster-mode.md) + [`d6-v0-3-verification-2026-05-16.md`](../d6-v0-3-verification-2026-05-16.md)
- **A.1 v0.1 → v0.1.1 plan + record**: [`2026-05-17-a-1-earned-autonomy-pipeline.md`](../../superpowers/plans/2026-05-17-a-1-earned-autonomy-pipeline.md) + [`a1-v0-1-1-verification-2026-05-17.md`](../a1-v0-1-1-verification-2026-05-17.md)
- **A.1 v0.1 implementation record (companion target)**: [`a1-verification-2026-05-16.md`](../a1-verification-2026-05-16.md)
- **ADR-007 (reference NLAH)**: [`ADR-007-cloud-posture-as-reference-agent.md`](ADR-007-cloud-posture-as-reference-agent.md) — what this ADR extends. ADR-007 covers initial-version agents; ADR-010 covers subsequent versions of the same agent.
- **Forthcoming F.7 plan**: F.7 v0.1 will be the first plan written under this ADR. ADR-010's success criterion is that F.7's plan-doc shape requires no special-case carve-outs.
