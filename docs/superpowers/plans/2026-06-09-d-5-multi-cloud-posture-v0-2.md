# D.5 Multi-Cloud Posture v0.2 — plan (Azure + GCP live + native rule engines) (2026-06-09)

> **The pre-cycle plan.** Q-locks locked by operator 2026-06-09 ([brainstorm #268](../brainstorms/2026-06-09-d-5-multi-cloud-posture-v0-2-brainstorm.md)). **19 tasks / 6 milestones**, strict-serial, per-task PR cadence ([ADR-011](../../_meta/decisions/ADR-011-pr-flow-and-branch-protection-discipline.md)), substrate seal empty throughout. Mirrors the [F.3 v0.2 plan](2026-06-07-f-3-cloud-posture-v0-2.md) pattern (the reference cycle, closed 2026-06-08, #267). No code here — execution begins task-by-task after this plan merges.

---

## §1. Context

- **D.5 Multi-Cloud Posture** is the cloud-posture agent for **Azure + GCP** (architectural per [ADR-007](../../_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md)). F.3 owns AWS; D.5 owns the non-AWS clouds. Multi-cloud lives here by design.
- **Today (main HEAD):** `multi-cloud-posture` v0.1.0, **fully offline** (filesystem JSON ingest; no live SDK deps; depends on `nexus-cloud-posture`). Azure side is a **Defender-for-Cloud passthrough with 0 native rules**; GCP side has **~4–5 native IAM-binding rules** + SCC passthrough. 214 tests. OCSF 2003 re-exported from `cloud_posture`.
- **v0.2 target:** Level 1 (offline passthrough) → **Level 2 (live Azure + GCP SDKs, single-subscription / single-project, native rule engines seeded)**.
- **D.5 is the 2nd consumer** of F.3's hoist-candidate patterns (#266); per ADR-007 the **charter hoist fires at the 3rd consumer (D.2)** — so **no charter touch this cycle**; D.5 imports the cloud-agnostic seams directly from `cloud_posture`.
- **Reference cycle:** [F.3 v0.2](../../_meta/f-3-cloud-posture-v0-2-verification-2026-06-08.md) — same task discipline, OCSF 2003 invariance, per-task PR cadence, honest per-cloud coverage reporting (WI-C).

## §2. Q-lock mapping (locked 2026-06-09)

| Q   | Lock                                                                                                   | Honored in                                         |
| --- | ------------------------------------------------------------------------------------------------------ | -------------------------------------------------- |
| Q1  | **(C) No charter hoist** — D.5 = 2nd consumer; import cloud-agnostic seams from `cloud_posture`        | All tasks (seal empty); Tasks 2, 6 import the seam |
| Q2  | **(A) Azure `DefaultAzureCredential` chain** (SP → MI → CLI)                                           | Task 2                                             |
| Q3  | **(A) GCP ADC** (SA-key dev → WIF prod)                                                                | Task 6                                             |
| Q4  | **(A) Azure 5–10 + GCP 10–15 native rules at v0.2**; full CIS = v0.3                                   | Tasks 10, 11                                       |
| Q5  | **(A) `NEXUS_LIVE_AZURE` + `NEXUS_LIVE_GCP` separate lanes** (per #266)                                | Tasks 13, 14                                       |
| Q6  | **(A) Single subscription + single project at v0.2**; multi → v0.3                                     | Tasks 3, 7                                         |
| Q7  | **(A) Defender kept as provenance-tagged source**; provenance surfaces plainly; removal → v0.3 (WI-D7) | Task 12                                            |

## §3. Milestones (19 tasks)

Risk labels per ADR-011. Each task = its own PR; each confirms substrate seal empty + offline eval cases byte-identical.

**M1 — Bootstrap (1 task)**

- **Task 1** — version v0.1 → v0.2 + ADR-010 pin + smoke. _(LOW-RISK)_

**M2 — Live Azure core (4 tasks)**

- **Task 2** — Azure credential resolver (`DefaultAzureCredential` chain, Q2); **imports the seam pattern from `cloud_posture`** (Q1). _(LOW-RISK)_
- **Task 3** — Azure **subscription** + region/location discovery (single-subscription, Q6); analog to F.3 Task 3. _(LOW-RISK)_
- **Task 4** — Azure region scoping (`--azure-regions` CLI); analog to F.3 Task 4. _(LOW-RISK)_
- **Task 5** — live-Azure error handling + partial-scan degradation; analog to F.3 Task 5 (closes M2). _(LOW-RISK)_

**M3 — Live GCP core (4 tasks)**

- **Task 6** — GCP credential resolver (ADC chain, Q3); **imports the seam pattern from `cloud_posture`** (Q1). _(LOW-RISK)_
- **Task 7** — GCP **project** + region discovery (single-project, Q6); analog to F.3 Task 3. _(LOW-RISK)_
- **Task 8** — GCP region scoping (`--gcp-regions` CLI); analog to F.3 Task 4. _(LOW-RISK)_
- **Task 9** — live-GCP error handling + partial-scan degradation; analog to F.3 Task 5 (closes M3). _(LOW-RISK)_

**M4 — Native rule engines (3 tasks)**

- **Task 10** — Azure native rule engine bootstrap + **5–10 CIS-Azure rules** (Q4) — closes the zero-native-rule gap. _(LOW-RISK)_
- **Task 11** — GCP native rule engine expansion to **10–15 CIS-GCP rules** (Q4). _(LOW-RISK)_
- **Task 12** — Defender provenance tagging in findings output (Q7) — surface `Source: Microsoft Defender` vs `Source: Nexus-native` plainly (closes M4). _(LOW-RISK)_

**M5 — Eval + test lanes (3 tasks)**

- **Task 13** — `NEXUS_LIVE_AZURE=1` gated live-eval lane (Q5); analog to F.3 Task 6. _(LOW-RISK)_
- **Task 14** — `NEXUS_LIVE_GCP=1` gated live-eval lane (Q5). _(LOW-RISK)_
- **Task 15** — live integration tests (read-only, Azure + GCP); analog to F.3 Task 7 (closes M5). _(LOW-RISK)_

**M6 — Validation + closure (4 tasks)**

- **Task 16** — cross-agent OCSF 2003 consumer regression sweep; analog to F.3 Task 9. _(LOW-RISK)_
- **Task 17** — operator runbooks + README v0.2 (**per-cloud**: an Azure runbook + a GCP runbook). _(LOW-RISK, docs)_
- **Task 18** — **Azure CSPM + GCP CSPM coverage `[estimate]` notes — separate per-cloud measurements** (WI-D1; no aggregate number). _(LOW-RISK, docs)_
- **Task 19** — verification record + cycle closure; mirror F.3 Task 13 (closes M6 + cycle). _(LOW-RISK, docs)_

**Total: 19 tasks / 6 milestones** — larger than F.3 v0.2's 13 because D.5 covers **two clouds** + native-rule-engine bootstrap (Azure from zero) + provenance tagging.

## §4. Scope rules

- ❌ No AWS work (F.3's scope). ❌ No AWS coverage claims.
- ❌ No multi-subscription / multi-project (v0.3 per Q6). ❌ No OCI / Alibaba / other clouds (v0.3+).
- ❌ No Defender removal (kept as provenance-tagged source per Q7).
- ❌ No full CIS rule libraries (5–10 Azure + 10–15 GCP per Q4; full CIS = v0.3).
- ❌ No charter touch (Q1 — D.5 = 2nd consumer). ❌ No substrate touch. ❌ No parked work (macro plan §1.5).
- ✅ **Per-cloud honesty** — Azure measured separately from GCP, no aggregate. ✅ OCSF 2003 invariance per task. ✅ Per-task PR cadence. ✅ Substrate seal empty per task. ✅ Cross-agent sweep at closure (Task 16).

## §5. Watch-items (preemptive, from F.3 v0.2 learnings)

- **WI-D1** — **Per-cloud coverage honesty:** Azure and GCP coverage measured + reported **separately**, each `[estimate]`-tagged. **No aggregate "multi-cloud CSPM coverage" number.**
- **WI-D2** — **Defender provenance surfaces in output:** customers see `Source: Microsoft Defender` vs `Source: Nexus-native` plainly — not theater.
- **WI-D3** — **Honest native-rule-library size:** report the real count at closure even if Azure lands at 5 (not 10); no fabrication to the plan target (the F.3 WI-C lesson).
- **WI-D4** — **Hoist readiness for D.2:** D.5 uses `cloud_posture` seams directly; the Task 19 record documents hoist readiness so **D.2 (3rd consumer)** can trigger the charter hoist.
- **WI-D5** — **Substrate seal per task:** every PR confirms `packages/charter/**` untouched.
- **WI-D6** — **OCSF 2003 byte-identical eval cases per task** (analog to F.3's 10 offline cases).
- **WI-D7** — **Defender-passthrough removal → v0.3** (carry-forward per Q7).

## §6. Verification gates at cycle closure

- ✅ All 19 task PRs: 5/5 CI checks green.
- ✅ Substrate seal empty: no `packages/charter/**` in any task.
- ✅ OCSF 2003 wire shape invariant: confirmed by Task 16 sweep.
- ✅ Offline eval cases byte-identical: Task 1 → Task 19.
- ✅ `NEXUS_LIVE_AZURE=1` lane green (operator dev Azure subscription, Task 15).
- ✅ `NEXUS_LIVE_GCP=1` lane green (operator dev GCP project, Task 15).
- ✅ Cross-agent regression sweep green at Task 16 (analog to F.3's 1,188-test sweep across 5 consumers).
- ✅ Native Azure rule engine live, emitting `class_uid 2003`, **5–10 rules ≥ floor**.
- ✅ Native GCP rule engine live, emitting `class_uid 2003`, **10–15 rules ≥ floor**.
- ✅ Defender provenance tagging visible in finding output.
- ✅ Azure CSPM coverage `[estimate]` note — separate (Task 18).
- ✅ GCP CSPM coverage `[estimate]` note — separate (Task 18).
- ✅ ruff + ruff format + mypy (strict) clean across all task PRs.

## §7. Carry-forward to D.2 v0.2 (the 3rd consumer)

D.5 v0.2 closure (Task 19) hands off to D.2:

- **Confirmation of which `cloud_posture` seams D.5 consumed directly** — proves the seam works for a 2nd adopter (the precondition for the ADR-007 charter hoist at D.2).
- **Any new patterns D.5 establishes** that D.2 may consume (e.g. the per-cloud native-rule-engine shape).
- **Per-cloud lane-naming pattern** (`NEXUS_LIVE_AZURE` / `NEXUS_LIVE_GCP`) — D.2 may extend with its own per-cloud IAM lanes.

## §8. Cross-references

- [D.5 v0.2 brainstorm](../brainstorms/2026-06-09-d-5-multi-cloud-posture-v0-2-brainstorm.md) (#268, Q-locks locked)
- [F.3 v0.2 plan](2026-06-07-f-3-cloud-posture-v0-2.md) (reference template) · [F.3 v0.2 verification record](../../_meta/f-3-cloud-posture-v0-2-verification-2026-06-08.md) (#267) · [F.3 v0.2 hoist candidates](../../_meta/f-3-cloud-posture-v0-2-hoist-candidates-2026-06-08.md) (#266)
- [ADR-007](../../_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md) (reference agent + third-consumer rule) · [ADR-010](../../_meta/decisions/ADR-010-version-extension-template.md) · [ADR-011](../../_meta/decisions/ADR-011-pr-flow-and-branch-protection-discipline.md)
- [Macro plan](../../strategy/nexus-agent-maturity-roadmap-2026-06-07.md) (§4 sequence) · [Competitive benchmark](../../strategy/competitive-benchmark-2026-06-08.md) (§5 D.5 structural exposure)

---

— recorded 2026-06-09 (D.5 Multi-Cloud Posture v0.2 plan; 19 tasks / 6 milestones; all 7 Q-locks honored; no code, execution begins after merge).
