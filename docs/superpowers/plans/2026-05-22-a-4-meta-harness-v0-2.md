# A.4 Meta-Harness Agent v0.2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Pause for review after each numbered task.

**Goal:** Ship **A.4 Meta-Harness v0.2** — Wave 0 of Phase 1 (Maturity-First), absorbing the Hermes-pattern nectar items **N1 + N2 + N5** per [§6 of the Hermes-absorption doc](../../_meta/hermes-pattern-absorption-2026-05-22.md). A.4 transitions from **read-only diagnostics** (v0.1) to the platform's **first auto-acting Meta-Harness** — it composes SKILL.md candidates from successful complex agent runs, eval-gates them against the target agent's eval suite, and auto-deploys them to the target agent's NLAH directory after operator approval (for first-of-class) or eval-gate pass (for refinements of proven classes). Becomes the **third forbidden subscriber** under [ADR-012](../../_meta/decisions/ADR-012-claims-subject-namespace.md), closing the Q-ARCH-1 trajectory predicted in [Supervisor v0.1's verification record](../../_meta/supervisor-v0-1-verification-2026-05-21.md).

**Strategic role.** A.4 v0.2 is **the foundation layer for all subsequent Phase 1 waves.** Wave 1 (F.3 v0.2 + multi-cloud-posture v0.2 + k8s-posture v0.2) and every wave after benefits from the compounding learning loop A.4 v0.2 installs. Once A.4 v0.2 closes, agents accumulate institutional memory per-customer; Wave 1+ inherits a smarter platform than v0.1's read-only-Meta-Harness world.

**Scope (v0.2, locked per the 2026-05-22 Phase 1 directive + Wave 0 hard scope fences).** Five capabilities only:

1. **N1 — Progressive-disclosure NLAH loader.** Extend the existing ADR-007 v1.2 NLAH directory structure with a sibling `skills/` subdirectory. Loader supports 3 levels: Level 0 = metadata index, Level 1 = full `SKILL.md`, Level 2 = per-skill `references/` files. All 17 agents' NLAH dirs become progressively-disclosable; backwards-compatible for agents that ship empty skills dirs.
2. **N2 — Autonomous skill creation.** A.4 reads F.6 audit chain + workspace artefacts after each `meta-harness run`. For complex successful runs (≥5 tool calls + no escalations + hash-novel tool-call sequence), A.4 composes a candidate `SKILL.md` via a single LLM call.
3. **N5 — agentskills.io open format.** All Nexus-emitted skills conform to the [agentskills.io](https://agentskills.io) standard (YAML frontmatter + markdown body) from day one. Strategic free-win — portable, ecosystem-compatible.
4. **NLAH auto-deploy with safety rails.** A.4 v0.2 CAN write to other agents' NLAH directories — **IF** the candidate passed eval-gate **AND** (the skill class is registered OR the operator approves it). This is the v0.2 step beyond v0.1's read-only stance.
5. **Subscriber-ACL self-registration.** A.4 v0.2 adds `_FORBIDDEN_SUBSCRIPTIONS["meta_harness"] = frozenset({"claims.>"})` to the substrate registry (Task 11; SAFETY-CRITICAL). Third forbidden subscriber after A.1 and Supervisor.

**Nothing else in v0.2.** Seven explicit version-named deferrals are listed in §"Out of scope" below.

**Substrate posture.** A.4 v0.2 makes **two substrate touches**:

- **Task 4 (SAFETY-CRITICAL):** extends `charter.nlah_loader` with the 3-level progressive-disclosure functions (additive — existing `default_nlah_dir()` + `load_system_prompt()` unchanged). All 17 downstream agents inherit the extension. Paired with **ADR-007 v1.4 amendment** (the progressive-disclosure loader documented as a charter evolution; v1.3 was already taken by the always-on agent class amendment). Same shape as ADR-012's original PR: doc + code together.
- **Task 11 (SAFETY-CRITICAL):** adds `_FORBIDDEN_SUBSCRIPTIONS["meta_harness"]` to `packages/shared/src/shared/fabric/client.py` + ADR-012 §"Subscriber ACL" amendment (third entry; closes the future-auto-acting paragraph).

Every other task is LOW-RISK and agent-local.

---

## Q1 — Skill storage shape: per-agent in-repo `nlah/skills/<category>/<skill>/SKILL.md`

**Resolution: in-repo, sibling of each agent's existing NLAH directory.**

- **Path:** `packages/agents/<agent>/src/<agent>/nlah/skills/<category>/<skill-name>/SKILL.md`. Each agent ships with its own skill library (operator-curated bundled skills + A.4-deployed auto-created skills land in the same directory tree).
- **Read-only at runtime for the target agent.** Each agent loads its own skills via the v1.4 progressive-disclosure loader (Task 4). Each agent never _writes_ to its own skills dir.
- **A.4 v0.2 is the ONLY writer.** A.4 writes candidate skills first to a **shadow path** under `<workspace>/.nexus/candidate-skills/<agent>/<category>/<skill>/SKILL.md` (eval-gate runs against this shadow); on approval, the file is moved to the canonical in-repo path.
- **Per-customer skill isolation deferred** to A.4 v0.x post-SET-LOCAL-fix. v0.2 single-tenant per the scope fence; customer-state paths are post-SET-LOCAL territory.
- **Operators commit deployed skills via normal git workflow.** A.4 doesn't run `git`; it writes files. Operator-side review handles version control.

## Q2 — Skill format: agentskills.io standard + Nexus-specific frontmatter extensions

**Resolution: adopt agentskills.io verbatim; extend YAML frontmatter with additive Nexus-specific fields.**

### YAML frontmatter (load-bearing for v0.2)

| Field               | Source         | Purpose                                                                                                |
| ------------------- | -------------- | ------------------------------------------------------------------------------------------------------ |
| `name`              | agentskills.io | Skill display name                                                                                     |
| `description`       | agentskills.io | One-line summary the loader matches against task descriptions                                          |
| `version`           | agentskills.io | Semver                                                                                                 |
| `platforms`         | agentskills.io | `["nexus"]` (extensible to `["nexus", "hermes", "claude-code"]` post-GA)                               |
| `target_agent`      | Nexus          | Must match a `nexus_eval_runners` entry-point name                                                     |
| `category`          | Nexus          | Matches subdirectory name; with `target_agent` forms the **first-of-class key** `(agent_id, category)` |
| `created_by`        | Nexus          | E.g., `"meta_harness@v0.2.0"`                                                                          |
| `provenance`        | Nexus          | `list[tuple[audit_log_path: str, entry_hash: str]]` — audit-chain entries that justified this skill    |
| `eval_gate_status`  | Nexus          | `passed` / `failed` / `not_run`                                                                        |
| `deployment_status` | Nexus          | `candidate` / `deployed` / `archived` / `rejected`                                                     |

### Directory layout

```
packages/agents/<agent>/src/<agent>/nlah/
├── README.md                         # operator-curated persona (ADR-007 v1.2; unchanged)
├── tools.md                          # operator-curated tool surface (unchanged)
├── examples/                         # operator-curated few-shots (unchanged)
└── skills/                           # NEW in v0.2 (per N1 + ADR-007 v1.4)
    └── <category>/                   # e.g., "investigation", "remediation", "cloud-posture"
        └── <skill-name>/
            ├── SKILL.md              # YAML frontmatter + markdown body
            ├── references/           # optional reference docs (Level 2)
            ├── templates/            # optional templates
            └── examples/             # optional invocation examples
```

**Backwards-compatible:** agents that ship empty `skills/` dirs (or omit it entirely) behave identically to v0.1.

## Q3 — Trigger criteria: ≥5 tool calls + completed successfully + hash-novel pattern

**Resolution: 3-condition gate (all must hold).**

1. **Tool-call count ≥ 5** in the run (Hermes baseline).
2. **Run completed successfully** — no escalation, no error audit-action entries (`*.failure`, `*.escalation.raised`).
3. **Pattern is novel** vs the agent's deployed skill library.

### Novelty check (deterministic, conservative)

- Build `tool_sequence_hash = SHA-256(":".join(tool_names_in_order))`.
- If this hash matches any existing deployed skill's `provenance.tool_sequence_hash` → skip (covered).
- If novel → candidate emit.

**Conservative by design.** Won't extract paraphrases of existing skills (acceptable — duplicates are worse than missed-near-duplicates in v0.2). Won't detect "same shape, different tool names" — that's v0.3 LLM-aided similarity (paired with the N3 Curator wave).

## Q4 — Eval-gate: A.4-local using v0.1's `BatchEvalRunner` + new `with_candidate_skill_overlay` context

**Resolution: agent-local; no eval-framework substrate hoist (3rd-consumer rule still gates that).** Mandatory; no `--force` flag.

Eval-gate flow per candidate:

1. A.4 writes the candidate to `<workspace>/.nexus/candidate-skills/<agent>/<category>/<skill>/SKILL.md` (shadow path).
2. A.4 captures the **baseline pass-rate**: runs the target agent's eval suite **without** the candidate first → caches baseline (**Option B — two eval runs per candidate; doesn't depend on KG**; Option A becomes available post-SET-LOCAL-fix).
3. A.4 runs the eval suite **with** the candidate, using a new `with_candidate_skill_overlay(workspace, agent_id, candidate_path)` context manager. This is a thin wrapper over v0.1's `nlah_override` (the `nlah_override` name is preserved for v0.1 callers; the new wrapper is clearer for skill-overlay usage).
4. Compare to baseline:
   - **Per-case regression check:** no individual case may drop by ≥ 5%.
   - **Overall regression check:** aggregate pass-rate must be ≥ baseline.
   - Both must hold → **eval-gate PASSED**.
5. Result cached in `<workspace>/.nexus/candidate-skills/<agent>/<category>/<skill>/eval_gate_result.json`.

**Reuses v0.1 substrate untouched:** `BatchEvalRunner` (Task 4 of v0.1), `nlah_override` (Task 5 of v0.1), per-case `ABComparisonCaseDelta` shape (Task 2 of v0.1).

## Q5 — Approval workflow: file-based + CLI; first-of-class operator gate

**Resolution: two-tier gate, both via the CLI shipped in Task 15.**

### Skill-class registry

`<workspace>/.nexus/skill-class-registry.json` tracks `(agent_id, category)` pairs that have been operator-approved at least once:

```json
{
  "investigation:iam-privesc": {"first_approved_at": "...", "first_skill_id": "..."},
  "remediation:eks-network-policy": {...}
}
```

### Decision rule

New candidate emitted → on eval-gate pass → check registry:

- **`(agent_id, category)` in registry** → **auto-deploy** (refinement of proven class) + `meta_harness.skill.deployed` audit entry with `approval_mode="auto_approved"`.
- **`(agent_id, category)` NOT in registry** → write `<workspace>/skill_candidate_<skill_id>.md` notification markdown + `meta_harness.skill.candidate_emitted` audit entry. **Wait for CLI approval.**

### CLI workflow

```sh
meta-harness list-skills --status candidate    # show pending candidates
meta-harness approve-skill <skill_id>           # promote shadow → canonical + register class
meta-harness reject-skill <skill_id> --reason "..."  # archive to rejected-skills/
```

**S.1 Console / S.3 ChatOps deferred** — file + CLI only in v0.2.

## Q6 — Audit posture: 4 additive `meta_harness.skill.*` audit-action entries

**Resolution: 4 new additive entries (per [ADR-010](../../_meta/decisions/ADR-010-version-extension-template.md) condition 4; total 8 `meta_harness.*` actions in v0.2).**

- `meta_harness.skill.candidate_emitted` — A.4 writes candidate to shadow path. Carries `skill_id`, `target_agent`, `category`, `tool_sequence_hash`, `provenance` (audit-chain refs).
- `meta_harness.skill.eval_gate_completed` — eval-gate run completed. Carries `skill_id`, `result` (∈ {passed, failed}), `baseline_pass_rate`, `candidate_pass_rate`, `per_case_regressions`.
- `meta_harness.skill.deployed` — shadow → canonical promotion. Carries `skill_id`, `target_path`, `deployed_at`, `approval_mode` (∈ {operator_approved, auto_approved}).
- `meta_harness.skill.rejected` — operator rejection OR eval-gate failure. Carries `skill_id`, `rejection_reason`, `eval_gate_result` if applicable.

F.6 hash-chain semantics inherited unchanged.

---

## Q-ARCH acknowledgments

### Q-ARCH-1: Subscriber-ACL fence (Task 11 — SAFETY-CRITICAL)

Per the [WI-5 carry-forward from Supervisor v0.1](../../_meta/supervisor-v0-1-verification-2026-05-21.md), A.4 v0.2 becomes auto-acting (writes to other agents' NLAH directories). MUST be added to `_FORBIDDEN_SUBSCRIPTIONS` per ADR-012.

```python
# packages/shared/src/shared/fabric/client.py
_FORBIDDEN_SUBSCRIPTIONS: Final[dict[str, frozenset[str]]] = {
    "remediation": frozenset({"claims.>"}),
    "supervisor": frozenset({"claims.>"}),
    "meta_harness": frozenset({"claims.>"}),    # NEW — A.4 v0.2 (Wave 0)
}
```

Plus ADR-012 §"Subscriber ACL" amendment: add the A.4 row + close the "future auto-acting agents" paragraph. The trajectory predicted in Supervisor v0.1's verification record completes here.

**Discipline:** SAFETY-CRITICAL; NO auto-merge; verified-against-HEAD; manual review. Same as ADR-012's original PR and Supervisor v0.1 Task 8.

### Q-ARCH-2: Eval-gate mechanism (Q4 — A.4-local, mandatory)

Implementation lives in A.4-local code; no eval-framework substrate hoist. Mandatory — no CLI `--force`.

### Q-ARCH-3: Operator approval gate (Q5 — first-of-class only)

First-of-class operator approval via `meta-harness approve-skill` CLI. Refinements within proven `(agent_id, category)` pairs auto-deploy on eval-gate pass.

### Q-ARCH-4 (new): Progressive-disclosure NLAH loader — CHARTER SUBSTRATE TOUCH (Task 4 — SAFETY-CRITICAL)

Per the [2026-05-22 Phase 1 directive refinement](#) (Refinement 1): Task 4 is **SAFETY-CRITICAL** because it touches `packages/charter/` — per ADR-011 plain reading, SAFETY-CRITICAL is determined by file location, not change shape. Additive substrate changes still require SAFETY-CRITICAL discipline because they affect all 17 downstream agents.

**Paired with ADR-007 v1.4 amendment** (Refinement 2). Note: ADR-007 v1.3 was already taken by the 2026-05-12 "always-on agent class" amendment, so the progressive-disclosure loader lands as **v1.4** (not v1.3 as originally proposed). The amendment goes in the same Task 4 PR — doc + code together, same shape as ADR-012's original PR.

New `charter.nlah_loader` surface (additive; existing functions unchanged):

- `default_skills_dir(package_file)` — sibling helper to existing `default_nlah_dir`.
- `load_skill_metadata_index(nlah_dir, *, skills_overlay=None)` — Level 0; returns lightweight tuples `(name, description, version, category, target_agent)` for every shipped + overlay skill.
- `load_skill(nlah_dir, skill_id, *, skills_overlay=None)` — Level 1; returns full `SKILL.md` content + parsed frontmatter.
- `load_skill_reference(nlah_dir, skill_id, ref_filename)` — Level 2; returns one reference file's content.

The `skills_overlay` parameter is how the eval-gate threads in the shadow-path candidates without modifying the agent's canonical skills dir.

---

## Architecture — 7-stage pipeline (extends v0.1's 6-stage)

```
┌──────────────────────────────────────────────────────────────────┐
│ Meta-Harness Agent v0.2 driver                                   │
│                                                                  │
│  Stage 1: INTROSPECT       — (v0.1) parse NLAH dirs              │
│  Stage 2: BATCH_EVAL       — (v0.1) run agent eval suites        │
│  Stage 3: AB_COMPARE       — (v0.1) optional NLAH A/B            │
│  Stage 4: DELTA            — (v0.1) scorecard delta tracking     │
│  Stage 5: REPORT           — (v0.1) assemble MetaHarnessReport   │
│  Stage 6: SKILL_TRIGGER    — NEW — scan F.6 audit chain for      │
│                               ≥5-tool-call successful runs +     │
│                               hash-novelty check.                │
│  Stage 7: SKILL_CREATE     — NEW — LLM-compose candidate         │
│                               SKILL.md + eval-gate + auto-deploy │
│                               OR queue for operator approval.    │
│  Stage 8: HANDOFF          — (v0.1 Stage 6 renumbered)           │
└──────────────────────────────────────────────────────────────────┘
```

**LLM consumption first introduced in v0.2** at Stage 7 (via `charter.llm_adapter` — same pattern as D.13 / D.12 per drift #2 resolution). v0.1's smoke test that asserted "no per-agent llm.py" remains valid; the new smoke test allows `charter.llm_adapter` import.

**Backwards-compatible:** A.4 v0.2 against an empty `skills/` directory + zero novel-pattern runs produces **byte-identical output** to v0.1 (modulo timestamps). Task 1's smoke suite enforces this regression test (drift #5 resolution; load-bearing).

---

## Execution status

```
1 → 2 → 3 → 4 → 5 → 6 → 7 → 8 → 9 → 10 → 11 → 12 → 13 → 14 → 15 → 16
```

| Task | Status | Commit | Notes                                                                                                                                                                                                                                                                                                                                                                                                                               |
| ---- | ------ | ------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1    | ⬜     |        | Bootstrap v0.2 — version bump (`0.1.0` → `0.2.0`); smoke tests for v0.2 invariants (4 Q-ARCH guards extended; `charter.llm_adapter` now-permitted; backwards-compat regression test asserting empty-skills-dir produces v0.1-equivalent output; progressive-disclosure smoke probe). **~14 smoke tests.**                                                                                                                           |
| 2    | ⬜     |        | `schemas.py` extension — add `Skill`, `SkillCandidate`, `SkillClassKey`, `DeploymentDecision`, `EvalGateResult` pydantic types. **~14 schema tests.**                                                                                                                                                                                                                                                                               |
| 3    | ⬜     |        | `skill_format.py` — agentskills.io YAML frontmatter parser + writer; Nexus-specific frontmatter fields validated; `references/` / `templates/` / `examples/` subdirs handled. **~12 tests.**                                                                                                                                                                                                                                        |
| 4    | ⬜     |        | **CHARTER SUBSTRATE TOUCH — SAFETY-CRITICAL.** Extend `charter.nlah_loader` with `default_skills_dir`, `load_skill_metadata_index`, `load_skill`, `load_skill_reference` (additive; existing functions unchanged). **Paired with ADR-007 v1.4 amendment** in the same PR — documents the progressive-disclosure loader + the `provenance: list[tuple[audit_log_path, entry_hash]]` frontmatter shape. **~14 tests.** NO auto-merge. |
| 5    | ⬜     |        | `skill_discovery.py` — walk all 17 agents' `nlah/skills/` subdirs; build per-agent registry; cross-reference with shadow-path overlay. **~12 tests.**                                                                                                                                                                                                                                                                               |
| 6    | ⬜     |        | `skill_triggers.py` — hash-of-tool-sequence novelty detector; reads F.6 audit chain entries; emits candidate triggers. **~13 tests.**                                                                                                                                                                                                                                                                                               |
| 7    | ⬜     |        | `skill_writer.py` — LLM-call (via `charter.llm_adapter`) composes SKILL.md; writes to shadow path; provenance frontmatter populated from audit-chain refs. **~13 tests including stub-LLM byte-equal probe.**                                                                                                                                                                                                                       |
| 8    | ⬜     |        | `skill_eval_gate.py` — eval-gate runner using `BatchEvalRunner` + new `with_candidate_skill_overlay` context (thin wrapper over v0.1's `nlah_override`); two-run baseline + with-candidate; per-case regression check ≥5% threshold; result cached. **~14 tests.**                                                                                                                                                                  |
| 9    | ⬜     |        | `skill_registry.py` — skill-class registry at `<workspace>/.nexus/skill-class-registry.json`; first-of-class `(agent_id, category)` operator gate; auto-deploy decision rule. **~10 tests.**                                                                                                                                                                                                                                        |
| 10   | ⬜     |        | `skill_approval.py` — file-based approval workflow; candidate-notification markdown writer; shadow → canonical promotion logic. **~10 tests.**                                                                                                                                                                                                                                                                                      |
| 11   | ⬜     |        | **SAFETY-CRITICAL substrate touch.** Add `_FORBIDDEN_SUBSCRIPTIONS["meta_harness"] = frozenset({"claims.>"})` to `packages/shared/src/shared/fabric/client.py` + ADR-012 §"Subscriber ACL" amendment (third entry; closes future-auto-acting paragraph). **`test_forbidden_subscription_meta_harness.py` — 7 tests.** NO auto-merge.                                                                                                |
| 12   | ⬜     |        | `audit_emit.py` extension — 4 new audit-action helpers (`skill.candidate_emitted` / `.eval_gate_completed` / `.deployed` / `.rejected`). Total **8 `meta_harness.*` actions**. **~10 tests.**                                                                                                                                                                                                                                       |
| 13   | ⬜     |        | Driver extension (`agent.py`) — add Stage 6 SKILL_TRIGGER + Stage 7 SKILL_CREATE; rename v0.1 Stage 6 HANDOFF → Stage 8. Updated `MetaHarnessReport` includes skill-lifecycle summary. **~16 tests.**                                                                                                                                                                                                                               |
| 14   | ⬜     |        | NLAH bundle update — v0.2 persona reflects auto-acting capability; new example `04-skill-curation.md`; `tools.md` updated with skill-lifecycle helpers + the 4 new audit-action vocab entries. **~17 tests.**                                                                                                                                                                                                                       |
| 15   | ⬜     |        | CLI extension (`approve-skill` / `reject-skill` / `list-skills`) + eval_runner extension with **5 new skill-workflow eval cases** (trigger-detected / eval-gate-pass-deploys-refinement / eval-gate-fail-rejects / first-of-class-requires-approval / approved-skill-loaded-by-target-agent). Total 15 cases. + stub harness extension for skill-content byte-equal (WI-3). **~30 tests.**                                          |
| 16   | ⬜     |        | Verification record (`docs/_meta/a-4-meta-harness-v0-2-verification-2026-05-22.md`) — 16-task table, gate results, 15/15 eval acceptance, WI-1..WI-5 watch-item resolutions, **Q-ARCH-1 trajectory closes** (3 forbidden subscribers final v0.2 set), **Wave 0 → Wave 1 handoff**.                                                                                                                                                  |

ADR references: [ADR-001](../../_meta/decisions/ADR-001-monorepo-bootstrap.md) · [ADR-005](../../_meta/decisions/ADR-005-async-tool-wrapper-convention.md) · [ADR-006](../../_meta/decisions/ADR-006-llm-adapter.md) · [ADR-007 v1.1 + v1.2 + (new) v1.4](../../_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md) · [ADR-008](../../_meta/decisions/ADR-008-eval-framework.md) · [ADR-010](../../_meta/decisions/ADR-010-version-extension-template.md) · [ADR-011](../../_meta/decisions/ADR-011-pr-flow-and-branch-protection-discipline.md) · [ADR-012](../../_meta/decisions/ADR-012-claims-subject-namespace.md).

---

## Resolved questions

| #        | Question                                      | Resolution                                                                                                                                                                                                         | Task            |
| -------- | --------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------- |
| Q1       | Skill storage shape?                          | Per-agent in-repo at `packages/agents/<agent>/src/<agent>/nlah/skills/<category>/<skill>/`. A.4 writes to a shadow path first; promotes on approval.                                                               | Tasks 1, 4, 10  |
| Q2       | Skill format?                                 | agentskills.io standard + Nexus frontmatter extensions (`target_agent`, `category`, `created_by`, `provenance`, `eval_gate_status`, `deployment_status`).                                                          | Tasks 3, 4      |
| Q3       | Trigger criteria for skill creation?          | 3-condition gate: tool-calls ≥ 5 + run successful + tool-sequence-hash novel vs deployed skills.                                                                                                                   | Task 6          |
| Q4       | Eval-gate mechanism?                          | A.4-local using `BatchEvalRunner` + new `with_candidate_skill_overlay` context; **Option B baseline** (two eval runs per candidate; no KG dependency); per-case regression ≥5% threshold. Mandatory; no `--force`. | Task 8          |
| Q5       | Approval workflow?                            | File-based + CLI; first-of-class `(agent_id, category)` operator gate via `meta-harness approve-skill`; refinements within proven pairs auto-deploy.                                                               | Tasks 9, 10, 15 |
| Q6       | Audit posture?                                | 4 additive audit-action entries (`skill.candidate_emitted` / `.eval_gate_completed` / `.deployed` / `.rejected`). Total 8 `meta_harness.*` actions in v0.2.                                                        | Task 12         |
| Q-ARCH-1 | `_FORBIDDEN_SUBSCRIPTIONS["meta_harness"]`?   | **YES — Task 11, SAFETY-CRITICAL.** Third forbidden subscriber. Closes the trajectory predicted in Supervisor v0.1's verification record.                                                                          | Task 11         |
| Q-ARCH-2 | Eval-gate mandatory?                          | YES (Q4). A.4-local; no eval-framework substrate hoist (3rd-consumer rule still gates that).                                                                                                                       | Task 8          |
| Q-ARCH-3 | First-of-class approval?                      | YES (Q5). `(agent_id, category)` pair; once approved, refinements auto-deploy on eval-gate pass.                                                                                                                   | Task 9          |
| Q-ARCH-4 | Progressive-disclosure NLAH loader substrate? | **YES — Task 4, SAFETY-CRITICAL.** Extends `charter.nlah_loader` additively. **Paired with ADR-007 v1.4 amendment in the same PR.** (v1.3 was already taken by 2026-05-12 always-on agent class amendment.)        | Task 4          |

---

## Out of scope — explicit version-named deferrals (7 items)

1. **NO Autonomous Curator (N3).** Deferred to **A.4 v0.3**. Requires per-skill telemetry (load_count, success_rate, last_used) that v0.2 doesn't emit.
2. **NO Skills Hub / marketplace (S2).** Rejected entirely — not v0.2, not v0.3, not v0.x. Deferred to post-GA strategic conversation.
3. **NO cross-customer skill sharing.** Each customer's library stays isolated. Cross-customer pattern distillation is post-GA.
4. **NO multi-tenant production.** Blocks on future `SET LOCAL $1` tenant-RLS substrate-fix.
5. **NO semantic similarity / embedding-based novelty.** v0.2 uses deterministic tool-sequence hash. Embedding-based similarity defers to **A.4 v0.3** (paired with N3 Curator's similarity-based dedup).
6. **NO Console/UI integration (S.1) or ChatOps (S.3).** File-based notification + CLI only. UI surfaces belong to the Surface track.
7. **NO N6 cross-session search** (gated on Surface track). Lands in D.13 v0.2 conditionally; A.4 v0.2 doesn't ship it.

---

## File map (target)

```
packages/agents/meta-harness/
├── pyproject.toml                              # Task 1 (version bump)
├── README.md                                   # Tasks 1, 14
├── src/meta_harness/
│   ├── __init__.py                             # Task 1 (__version__ = "0.2.0")
│   ├── schemas.py                              # Task 2 (extended)
│   ├── skill_format.py                         # Task 3 (NEW)
│   ├── skill_discovery.py                      # Task 5 (NEW)
│   ├── skill_triggers.py                       # Task 6 (NEW)
│   ├── skill_writer.py                         # Task 7 (NEW; first LLM consumer)
│   ├── skill_eval_gate.py                      # Task 8 (NEW)
│   ├── skill_registry.py                       # Task 9 (NEW)
│   ├── skill_approval.py                       # Task 10 (NEW)
│   ├── agent.py                                # Task 13 (extended; +Stage 6 + Stage 7; renumber Stage 8)
│   ├── audit_emit.py                           # Task 12 (extended; +4 actions)
│   ├── cli.py                                  # Task 15 (extended; approve-skill / reject-skill / list-skills)
│   ├── eval_runner.py                          # Task 15 (extended; +5 new cases)
│   ├── nlah/                                   # Task 14 (persona update; +example 04-skill-curation.md)
│   └── tools/
│       ├── nlah_parser.py                      # extended for skills dir + Level 0/1/2
│       └── ab_compare.py                       # +with_candidate_skill_overlay wrapper (nlah_override preserved)
└── eval/
    ├── cases/                                  # Task 15 (5 new skill-workflow cases; total 15)
    └── stub_responses/                         # Task 15 (LLM responses for skill_writer)

packages/charter/src/charter/nlah_loader.py    # Task 4 (CHARTER SUBSTRATE TOUCH — additive; SAFETY-CRITICAL)
docs/_meta/decisions/ADR-007-...md             # Task 4 (SAFETY-CRITICAL doc amend — §v1.4)
packages/shared/src/shared/fabric/client.py    # Task 11 (SAFETY-CRITICAL substrate touch)
docs/_meta/decisions/ADR-012-...md             # Task 11 (SAFETY-CRITICAL doc amend — Subscriber ACL)
docs/_meta/a-4-meta-harness-v0-2-verification-2026-05-22.md  # Task 16
```

---

## Risks

| Risk                                                                                                        | Mitigation                                                                                                                                                                                                                                                                        |
| ----------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A.4 v0.2 auto-writes a buggy skill that regresses a target agent silently                                   | **WI-4 mandatory eval-gate** (Q4) — no skill deploys without eval-gate pass + (for first-of-class) operator approval. Integration tests assert both safeguards; CLI has no `--force`. Two eval runs per candidate (baseline + with-candidate); per-case regression ≥5% threshold. |
| Backwards-compatibility breaks for v0.1 callers (e.g., A.4 v0.1 consumers; other v0.1 agents' NLAH loaders) | Task 1 smoke test enforces byte-equal output (modulo timestamps) against empty skills/ + zero candidates. Task 4's `charter.nlah_loader` additions are strictly additive; existing functions unchanged. Existing v0.1 callers don't touch the new APIs.                           |
| LLM non-determinism in Stage 7 SKILL_CREATE breaks WI-3                                                     | Per-case `stub_responses/<case_id>/responses.json` in the bundled eval suite; byte-equal probe asserts identical skill content across reruns under stub-LLM. Production LLM provider per `charter.llm_adapter` (same as D.13/D.12).                                               |
| ADR-007 v1.4 amendment lands without the substrate code (or vice versa)                                     | Same shape as ADR-012's original PR: doc + code in the SAME Task 4 PR. SAFETY-CRITICAL discipline; manual review; no auto-merge.                                                                                                                                                  |
| Operator-side review surface gap — no UI for approving skills                                               | Q5 + Q-ARCH-3 explicitly: file-based notification (`<workspace>/skill_candidate_<id>.md`) + CLI (`meta-harness approve-skill <id>`). UI surfaces deferred to Surface track. Operator workflow tested via CliRunner in Task 15.                                                    |
| Q-ARCH-1 carry-forward dropped (future auto-acting agent misses the registry)                               | This v0.2 plan CLOSES the Q-ARCH-1 trajectory at 3 forbidden subscribers — verification record records "no further pending additions in Phase 1." Future auto-acting agents must surface a fresh Q-ARCH issue in their own v0.2+ plan; the carry-forward chain ends here.         |

---

## Watch-items (carry-forward to verification record)

- **WI-1: Substrate sealed except Tasks 4 + 11.** `git diff --stat packages/charter/ packages/shared/` empty across non-substrate tasks. Task 4 substrate diff bounded to `charter/nlah_loader.py` additive functions + ADR-007 v1.4 doc amend. Task 11 bounded to `_FORBIDDEN_SUBSCRIPTIONS["meta_harness"]` (~5 lines) + ADR-012 doc amend.
- **WI-2: Single-tenant default.** `semantic_store=None` opt-in throughout (inherited from v0.1). Per-customer skill isolation deferred to v0.x post-SET-LOCAL-fix.
- **WI-3: Stub-LLM determinism extended to skill content.** v0.2 introduces LLM consumption (Stage 7). Per-case `responses.json` enables byte-equal probe across reruns. Same audit-chain input → same generated SKILL.md content.
- **WI-4: Auto-deploy safety rails.** **No skill deploys without (a) eval-gate pass AND (b) first-of-class operator approval.** Integration tests assert both; CLI has no `--force` flag. Two eval runs per candidate (Option B baseline).
- **WI-5: Q-ARCH-1 trajectory CLOSES at 3 forbidden subscribers.** Verification record records: **A.1 + Supervisor + A.4 v0.2 — the trajectory predicted in Supervisor v0.1's verification record completes here.** No further pending additions in Phase 1.

---

## Done definition

A.4 Meta-Harness v0.2 is **done** when:

- 16/16 tasks closed; every commit pinned in the execution-status table.
- ≥ 80% test coverage on `packages/agents/meta-harness`.
- `ruff check` + `ruff format --check` + `mypy --strict` clean.
- `meta-harness eval` returns 15/15 (10 original v0.1 cases + 5 new skill-workflow cases).
- `meta-harness run` against the live 17-agent fleet produces:
  - The v0.1 outputs (scorecards, deltas, regressions, report markdown) — **backwards-compatible**.
  - PLUS skill-lifecycle entries (candidates triggered, eval-gate results, deployed/rejected counts).
- One end-to-end smoke run demonstrates: trigger detected → candidate emitted → eval-gate run → first-of-class operator approval → deploy → next-run target agent picks up the skill via the progressive-disclosure loader.
- ADR-007 v1.1 + v1.2 + v1.4 + ADR-010 + ADR-011 + ADR-012 conformance verified end-to-end.
- README + smoke runbook reviewed.
- Verification record committed at `docs/_meta/a-4-meta-harness-v0-2-verification-2026-05-22.md`.
- **Watch-items WI-1 through WI-5 verified at close**, with **WI-5 closing the Q-ARCH-1 trajectory** (3 forbidden subscribers final v0.2 set, no further pending additions in Phase 1).

That closes **Wave 0 of Phase 1.** Wave 1 (F.3 v0.2 → multi-cloud-posture v0.2 → k8s-posture v0.2) begins with the compounding learning loop in place.

---

## ADR-011 cadence (per-task discipline)

Every numbered task above lands as its **own PR** off branches like `feat/a-4-task-N-<scope>`. Per [ADR-011](../../_meta/decisions/ADR-011-pr-flow-and-branch-protection-discipline.md):

- **LOW-RISK label on Tasks 1-3, 5-10, 12-16** (14 tasks) — agent-local changes.
- **SAFETY-CRITICAL label on Tasks 4 + 11 only** (2 tasks):
  - Task 4: `packages/charter/` substrate touch + ADR-007 v1.4 amendment.
  - Task 11: `packages/shared/` substrate touch + ADR-012 amendment.
- **NO auto-merge on SAFETY-CRITICAL PRs.** Verified-against-HEAD; manual review.
- **Report → review → merge → next task.** After each task PR opens, pause for review.
- **Execution-status table is single source of truth** for task-commit pinning per ADR-010.

---

## Phase 1 / Wave 0 context — next waves queued

- **Wave 0 (this plan)** — A.4 Meta-Harness v0.2 (N1 + N2 + N5 + auto-deploy safety rails + subscriber-ACL self-registration).
- **Wave 1** — F.3 v0.2 → multi-cloud-posture v0.2 → k8s-posture v0.2 (CSPM family, live mode).
- **Wave 2** — D.5 v0.2 → D.6 v0.2 (Data + Compliance).
- **Wave 3** — D.4 v0.2 → D.3 v0.2 → D.8 v0.2 (Threat layer).
- **Wave 4** — D.2 v0.2 → D.1 v0.2 (Identity + Vulnerability).
- **Wave 5** — D.7 v0.2 → D.12 v0.2 → D.13 v0.2 (Smart layer).
- **Wave 6** — A.4 v0.3 (Curator — N3) + F.6 v0.2 (Compliance reporting).

Excluded from Phase 1: A.1 Remediation v0.2 (Phase 3 territory), Supervisor #0 v0.2 (downstream of A.4 v0.2 introspection).

---

## Reference template

Follows [ADR-007](../../_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md) (reference NLAH) + [ADR-010](../../_meta/decisions/ADR-010-version-extension-template.md). [A.4 Meta-Harness v0.1's verification record](../../_meta/a-4-meta-harness-v0-1-verification-2026-05-21.md) is the closest reference for cadence + verification-record shape; [Supervisor v0.1's plan + verification record](../../_meta/supervisor-v0-1-verification-2026-05-21.md) is the reference for the SAFETY-CRITICAL substrate-fence pattern (Task 11 inherits Supervisor v0.1 Task 8's discipline). The [Hermes-pattern absorption doc](../../_meta/hermes-pattern-absorption-2026-05-22.md) is the canonical reference for the N1+N2+N5 nectar shape.
