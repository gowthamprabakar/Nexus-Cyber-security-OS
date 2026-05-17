# ADR-011 — SAFETY-CRITICAL PR-flow, branch-protection, and verified-against-HEAD discipline

- **Status:** **proposed**
- **Date:** 2026-05-17
- **Authors:** AI/Agent Eng
- **Stakeholders:** every plan author; every PR reviewer; repo admin (for the branch-protection ruleset); compliance (the discipline is part of the change-management audit trail)

## Context

The A.1 v0.1.1 earned-autonomy-pipeline plan surfaced **four** process boundaries during its execution. Each is recorded honestly in the [v0.1.1 verification record's four-boundary process notes](../a1-v0-1-1-verification-2026-05-17.md#process-notes--the-four-boundaries), but those notes are **memorial documentation** — they record what happened, not a forward-looking operating discipline. Without an ADR codifying the methodology, the next safety-critical plan inherits the lesson by reading the previous verification record rather than by inheriting an executed gate.

The four boundaries, summarised:

1. **Tasks 1–8 landed direct-to-main pre-guard.** Turn-by-turn review; chat-turn artefact was the only review record. Worked for structural code; became inadequate when the plan's subject was the safety contract itself.
2. **Tasks 9–14 moved to PR-flow after the sandbox bypass-guard fired** on a direct-to-main push to a plan whose subject was the safety contract. Framing: _"the review of the safety pipeline must be as durable as the safety pipeline."_
3. **CI-enforcement gap surfaced when PR #3 merged with red CI** (`python-tests` + `python` lint failures). The merge button didn't enforce CI by default. PR #5 fixed the underlying CI hygiene; PR #6 checked in the GitHub repository ruleset that requires all 5 status checks on `main`.
4. **Task 13's broken proof merged because review was post-merge** (PR #8). The committed test used `monkeypatch.setattr(kc_mod.subprocess, ...)` against an attribute that didn't exist; the corrected spy lived only in the working tree at test time and was never staged. Hotfix PR #9 restored the fix + appended a Correction note to §8 Entry 2 disclosing all three failure modes verbatim — including that _"post-merge review is not equivalent to pre-merge review when the proof artefact ships in the same PR."_

Task 14's PR body responded with the **verified-against-merged-branch-HEAD sentence** as a structural fix for Boundary 4. v0.1.2's PR body carried the same sentence. Both PRs landed clean. But the discipline lives in PR-body convention today, not in an ADR. The next plan's authors must know to apply it — and the only way they currently know is by reading the v0.1.1 verification record and v0.1.2's PR body.

The plan that motivates this ADR is **F.7 v0.1** (fabric runtime). F.7 has 8 tasks, several of which are SAFETY-CRITICAL by the same standard A.1 v0.1.1's tasks were (substrate code that downstream consumers will depend on; integration-tested via env-gated live lanes that CI doesn't run; first plan where the proof artefact and the proof's code ship together). Without ADR-011, F.7's plan author must rediscover the four boundaries' lessons. With ADR-011, the discipline is the operating norm of the F.7 PR series, not a memorial of A.1 v0.1.1.

## Decision

**This ADR codifies four operating disciplines for the platform's PR series.** Adopting them turns the four boundaries from "things we learned the hard way" into "things every plan author and every reviewer follow by default."

### Discipline 1 — SAFETY-CRITICAL labelling at PR-open time

Every PR opens with a label in the PR title and the PR body declaring its risk class:

| Label                          | When to use                                                                                                                                                                                                                                                           | Implied discipline                                                                                                                                                                                                                    |
| ------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **SAFETY-CRITICAL**            | Plans whose subject is the safety contract, the gate, the kill switch, the migration; code that affects whether or how the agent touches the cluster / cloud / customer data; the live-cluster proof lanes; the branch-protection / CI-hygiene infrastructure itself. | Full PR review (no merge before reviewer confirms); verified-against-HEAD sentence in body (Discipline 3); report → review → merge cadence (Discipline 4); PR-flow only (no direct-to-main even if branch protection would allow it). |
| **LOW-RISK**                   | Routine refactors, dep bumps, test additions on existing surface, eval-case additions, docs typo fixes, plan-pin commits, mechanical renames.                                                                                                                         | All five CI checks green is necessary and sufficient evidence for merge approval. Reviewer may merge on confirmation without manual file review.                                                                                      |
| **methodological / docs-only** | ADR drafts, runbook updates, verification records, plan-status pins, dependency-version-extension templates.                                                                                                                                                          | Full review (the doc IS the artefact under review) but not SAFETY-CRITICAL by the code-touch standard.                                                                                                                                |

The label is **stated in the PR title** (e.g., `feat(remediation): v0.1.2 — wire --promotion <path>  [LOW-RISK]` or `feat(a1 v0.1.1 task 13): live kind proof — SAFETY-CRITICAL`) AND in the PR body's first line. Convention: title-suffix is the canonical form; the body restates it for the reviewer's first scroll.

When in doubt, **default to SAFETY-CRITICAL**. The discipline tax of treating LOW-RISK as SAFETY-CRITICAL is small (a reviewer's extra read); the safety tax of treating SAFETY-CRITICAL as LOW-RISK is the Task-13 failure mode.

### Discipline 2 — Branch protection on `main`, structurally enforced

The GitHub Rulesets-based branch protection on `main` requires all 5 status checks (`python-tests`, `python` lint, `typescript-tests`, `typescript` lint, `go` lint) to pass before merge. `bypass_actors: []` (no admin bypass). The ruleset definition is checked in at [`.github/branch-protection.json`](../../.github/branch-protection.json); the runbook for applying / re-applying it is at [`.github/BRANCH_PROTECTION.md`](../../.github/BRANCH_PROTECTION.md). Both shipped in PR #6.

**Structural rule:** a red-CI merge to `main` is impossible. The merge button is disabled until all 5 checks are green. This is not a discouragement; it is a property of the repository configuration. The previous "PR #3 merged red" failure mode is closed structurally.

**Maintaining the rule:** the ruleset is administered out-of-band (via `gh api`). Changing it requires a follow-up PR that amends `.github/branch-protection.json` + the admin re-applies via the documented `gh api` command. The "change to the rule" path goes through the same review discipline as code: PR-flow, full review, verified-against-HEAD.

**`bypass_actors: []` is intentional.** If a future emergency truly requires an admin bypass, the rule is amended in a follow-up PR with explicit reasoning recorded — not bypassed silently. The Boundary-3 lesson was that "discouraged but not enforced" reduces to "happens anyway." Structural enforcement is the only durable answer.

### Discipline 3 — Verified-against-merged-branch-HEAD sentence in every SAFETY-CRITICAL PR body

Every SAFETY-CRITICAL PR body opens with a sentence of the following shape:

> **What is verified in this PR body is what is in this PR's HEAD commit (`<short-hash>`), against a clean working tree.** All gates and proof artefacts were run AFTER the commit landed, against the branch HEAD that this PR carries. `git status --short` returns empty; `git rev-parse HEAD` returns `<full-hash>`.

The sentence is required because **Boundary 4's failure mode** — the proof artefact and the proof's code shipping together with the proof generated against an in-editor working tree state that was never staged — is otherwise invisible to the reviewer until the live lane is re-run post-merge. The sentence forces the agent / author to explicitly run the gates AFTER the commit and against the branch HEAD; the empty `git status --short` is the empirical assertion that no editor-only fixes are in play.

Required elements:

1. **HEAD short hash** in the sentence (matches `git rev-parse --short HEAD`).
2. **HEAD full hash** in the sentence (matches `git rev-parse HEAD`).
3. **Explicit "gates run AFTER the commit"** phrasing — not "gates run against this branch" (ambiguous about which commit) or "gates run during development" (the failure mode).
4. **`git status --short` returns empty** — the clean-tree assertion.

LOW-RISK PRs may also use the sentence (it's not harmful), but they are not required to. methodological / docs-only PRs typically don't have gates beyond ruff/format and may state the sentence in shortened form.

**The sentence is the load-bearing closer for Boundary 4.** A SAFETY-CRITICAL PR that doesn't carry the sentence has not satisfied this discipline.

### Discipline 4 — Report → Review → Merge cadence; the agent does not merge

Every PR follows this cadence:

1. **Agent creates the PR.** Branch pushed; PR opened; body carries the verified-against-HEAD sentence (SAFETY-CRITICAL) and the labelled risk class (any class).
2. **Agent reports the PR.** The agent surfaces the PR URL and a one-sentence verdict back to the human reviewer in the same conversation turn. Includes: gate results; one-sentence summary of what landed; what the reviewer should check.
3. **Agent STOPS.** The agent does not start the next plan; does not open follow-up PRs; does not merge.
4. **Human reviews.** Reviewer reads the PR body, the diff, the verified-against-HEAD assertion, any inline notes; runs gates locally if the PR demands re-verification (e.g., if the gates ran against an out-of-tree state).
5. **Human merges.** Only the human clicks merge. The agent has no merge authority.

**Boundary 2** (PR-flow after the bypass-guard fired) and **Boundary 4** (post-merge review is not pre-merge review) together motivate this discipline. The agent's role is to create + report; the human's role is to review + merge. Combining roles introduces the failure modes both boundaries surfaced.

**The cadence is non-negotiable for SAFETY-CRITICAL PRs.** It is the operating norm for LOW-RISK and methodological PRs too; the difference is the depth of the reviewer's read, not the cadence itself.

## Consequences

### Positive

- **The four boundaries become operating disciplines.** Future plan authors don't have to read the v0.1.1 verification record to know how the PR series operates; they read this ADR.
- **SAFETY-CRITICAL labelling is consistent.** A reviewer scanning a PR list can see at a glance which PRs demand depth; agents authoring PRs default to SAFETY-CRITICAL when in doubt; the cost is bounded.
- **Branch-protection rules are auditable.** The ruleset's JSON is checked in; changes to it go through PR-flow; the failure mode where "the merge button doesn't enforce CI" can't recur silently.
- **The verified-against-HEAD sentence is a structural check, not a convention.** A SAFETY-CRITICAL PR without the sentence is identifiable as out-of-process; reviewers know to demand it or refuse merge.
- **Report → Review → Merge prevents the agent-self-merge failure mode** entirely. The agent has no merge authority by ADR; if a sandbox or tooling change later granted that authority, it would violate the ADR and be visible at review.

### Negative

- **Discipline tax for LOW-RISK PRs.** Even routine work travels through PR-flow with labelling, body sentence, and report-pause. Mitigation: LOW-RISK PRs are smaller, faster to review, and the cadence is well-rehearsed. The empirical overhead from v0.1.2 (a LOW-RISK PR under the discipline) was a single review turn.
- **bypass_actors: [] is intentional but operationally inflexible.** Emergency hotfixes that can't wait for CI must amend the ruleset (a follow-up PR) rather than bypassing it. Mitigation: this is the explicit Boundary-3 trade-off; "discouraged" failed empirically; "structurally impossible" is the only durable answer.
- **The SAFETY-CRITICAL / LOW-RISK / methodological line is not always clear.** A.1 v0.1.2 was on the boundary (CLI wiring is operator-visible but backwards-compatible). Mitigation: the "when in doubt, default to SAFETY-CRITICAL" rule; the ADR-010 eligibility test (when applicable) gives an empirical signal — a change that fails ADR-010's six conditions is usually SAFETY-CRITICAL or methodological, never LOW-RISK.

### Neutral / unknown

- **Multi-agent PRs.** When a single PR spans multiple agents' surfaces (rare under ADR-010's "cross-agent fan-out" exclusion), the labelling defaults to the most-critical surface's class. Acceptable: this is the same default-to-strictest pattern the rest of the disciplines use.
- **PR comments that surface post-open issues.** A LOW-RISK PR that surfaces a SAFETY-CRITICAL concern in review should be re-labelled; the ADR doesn't (yet) specify the re-labelling mechanic. Probably "edit the title + body; reviewer acknowledges the re-label in a comment." Defer to first occurrence; amend the ADR if the pattern recurs.

## Alternatives considered

### Alt 1: Status quo — let the discipline live in the v0.1.1 verification record's four-boundary section

- Why rejected: memorial documentation, not operating discipline. Future plan authors read it as history, not as instructions. Boundary-4-style failures recur because the lesson is in a different document than the next plan.

### Alt 2: Make SAFETY-CRITICAL the only label; no LOW-RISK shortcut

- Why rejected: discipline tax on routine work would exceed the value. v0.1.2 ride-along PRs (the small-PR scaling that ADR-010 just validated) would be 4x longer reviews than warranted. The LOW-RISK shortcut is a real efficiency lever; abandoning it costs more than the occasional mis-categorisation does.

### Alt 3: Mechanise the verified-against-HEAD sentence via a PR template / CI lint check

- Why rejected (for now): worth doing eventually. v0.1 of the discipline is the convention captured in this ADR; a future amendment with the CI lint implementation is the natural follow-up. Reasonable to ship the ADR before the lint check rather than the other way around.

### Alt 4: Encode the four boundaries as separate ADRs (ADR-011 for PR-flow, ADR-012 for branch-protection, ADR-013 for verified-against-HEAD, ADR-014 for report → review → merge)

- Why rejected: the four disciplines reinforce each other. Splitting them dilutes the methodology. ADR-011 covers them as one operating discipline; future amendments may split if the boundaries' shapes diverge.

## What this ADR commits us to

1. **Every PR title carries a risk-class suffix** (`SAFETY-CRITICAL` / `LOW-RISK` / `methodological / docs-only`); every PR body restates it in the first line. PR templates may codify this once mechanisation lands.
2. **Branch protection's `main`-ruleset is the only path to `main`.** The `bypass_actors: []` setting is enforced; amendments go through PR-flow on `.github/branch-protection.json`.
3. **SAFETY-CRITICAL PR bodies carry the verified-against-merged-branch-HEAD sentence** in the shape specified in Discipline 3. Reviewers refuse merge without it.
4. **Agents create + report; humans review + merge.** No self-merge by the agent under any class of PR. Sandbox capabilities that would otherwise grant merge authority are not exercised.
5. **This ADR amends rather than is superseded** for routine tweaks (Discipline 1's label list, Discipline 3's sentence form, etc.), same as ADR-007's v1.1/v1.2/v1.3 amendment cadence.

## References

- **A.1 v0.1.1 verification record — four-boundary process notes**: [`a1-v0-1-1-verification-2026-05-17.md` § "Process notes — the FOUR boundaries"](../a1-v0-1-1-verification-2026-05-17.md#process-notes--the-four-boundaries). The empirical motivator.
- **§8 Entry 2 Correction note** (the Task-13 Boundary-4 disclosure): [`a1-safety-verification-2026-05-16.md` § "Correction note — 2026-05-17 post-merge hotfix"](../a1-safety-verification-2026-05-16.md). The Boundary-4 failure mode recorded in source-of-truth form.
- **PR #5 (CI hygiene fix)** and **PR #6 (branch protection ruleset)**: the structural Boundary-3 closure.
- **PR #14 (this ADR's proposal PR)**: forthcoming, alongside the F.7 v0.1 plan.
- **ADR-010** ([`ADR-010-version-extension-template.md`](ADR-010-version-extension-template.md)): the document-level shape for version extensions; ADR-011 is the **process-level** discipline for the PRs that ship those extensions.
- **ADR-004** ([`ADR-004-fabric-layer.md`](ADR-004-fabric-layer.md)): the design contract F.7 v0.1 implements. ADR-011's PR-flow + branch-protection + verified-against-HEAD discipline IS the operating norm of the F.7 PR series.
