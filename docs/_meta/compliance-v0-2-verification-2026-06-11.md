# compliance (D.6) v0.2 — Verification Record & Cycle Closure

**Date:** 2026-06-11 · **Cycle 9 of 17** · **Maturity: Level 1 → Level 2 (infrastructure).**
The **second Group D (posture-class) consumer** — inherits the k8s-posture (Cycle 8) pattern;
compliance is the genuine **D.6** per benchmark naming + the **4th OCSF 2003 emitter**. Single
comprehensive directive, self-merge cascade (Tasks 1–21), operator review at close (Task 22).

---

## §1. Cycle summary

Took the compliance agent from package **`__version__` 0.1.0 → 0.2.0** (ADR-010): the full
CIS family (AWS/Azure/GCP/K8s), PASS attestation alongside FAIL, multi-emitter consumption,
continuous-monitoring infrastructure, and audit-ready evidence bundles — all keeping the
offline FAIL `run()`/eval byte-identical (WI-C5).

- **22 tasks, 23 PRs** (#455–#476; Task 21 = #475 + #476). 8 milestones.
- **Tests:** compliance **225 → 351 passed** (+126) + 1 gated-live skip. Full repo **6075
  passed, 66 skipped, 0 failed**.
- **Substrate seal EMPTY all 22** — no charter/shared edit (`schemas.py` additions are
  compliance-local + additive). **No charter hoist** (as planned). Consumes the hoisted
  `charter.live_lane`.

## §2. Task execution table

| #   | Task                                             | PR          |
| --- | ------------------------------------------------ | ----------- |
| 1   | Bootstrap (version + ADR-010 + OCSF 2003 verify) | #455        |
| 2   | CIS-AWS real-rule wiring + no-fabrication guard  | #456        |
| 3   | CIS-Azure benchmark                              | #457        |
| 4   | CIS-GCP benchmark                                | #458        |
| 5   | CIS-K8s benchmark                                | #459        |
| 6   | PASS attestation finding schema + emission       | #460        |
| 7   | PASS evidence collection per control             | #461        |
| 8   | PASS+FAIL roll-up aggregation                    | #462        |
| 9   | F.3 OCSF 2003 consumption + control mapping      | #463        |
| 10  | D.5 OCSF 2003 consumption (CIS-Azure + CIS-GCP)  | #464        |
| 11  | k8s-posture OCSF 2003 consumption (CIS-K8s)      | #465        |
| 12  | Background scan scheduler                        | #466        |
| 13  | Delta detection on emitter findings              | #467        |
| 14  | Continuous + heartbeat coexistence               | #468        |
| 15  | Audit-ready evidence bundle schema               | #469        |
| 16  | Evidence hash chain + signed manifest            | #470        |
| 17  | Per-framework PDF + JSON export                  | #471        |
| 18  | NEXUS_LIVE_COMPLIANCE gated lane                 | #472        |
| 19  | WI-C2/C7 live multi-emitter e2e                  | #473        |
| 20  | Live-lane coexistence                            | #474        |
| 21  | 4-emitter sweep + coverage + runbook + README    | #475 + #476 |
| 22  | Verification record + cycle closure              | _this PR_   |

## §3. Q-lock mapping (all 7 honored)

| Q   | Lock                                                            | Where honored                                                                                                                                                                  |
| --- | --------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Q1  | (B) CIS family complete (AWS/Azure/GCP/K8s)                     | 4 control libraries + readers (Tasks 2–5)                                                                                                                                      |
| Q2  | (A) full control wiring                                         | **honored with a premise correction** — wired to every rule the emitters ACTUALLY emit (14 AWS / 8 Azure / 10 GCP / 15 K8s); the rest are honest gaps, not fabricated (see §5) |
| Q3  | (A) PASS + FAIL emitted                                         | `build_pass_finding` + `attestation.py` (Tasks 6–7); PASS carries positive evidence (WI-C6)                                                                                    |
| Q4  | (A) continuous INFRASTRUCTURE; run() wiring → Phase C           | `continuous/` scheduler + delta + mode (Tasks 12–14); NOT run()-wired                                                                                                          |
| Q5  | (A) multi-cloud sources via 3 emitters                          | `consumption.py` consumes F.3 + D.5 + k8s-posture (Tasks 9–11)                                                                                                                 |
| Q6  | (A) audit-ready evidence bundles (hash chain + signed manifest) | `evidence/` bundle + chain + export (Tasks 15–17)                                                                                                                              |
| Q7  | OCSF class_uid 2003 (byte-identical)                            | verified + pinned (WI-C5); **4th emitter** (F.3/D.5/k8s-posture/compliance)                                                                                                    |

## §4. Gates passed

- **All 5 CI checks green** on every self-merged PR.
- **Substrate seal EMPTY** for all 22 tasks (no charter/shared edit; `schemas.py` additions
  — PASS status, the Azure/GCP/K8s `ComplianceFramework` members — are compliance-local +
  additive).
- **OCSF 2003 byte-identical** every task: the FAIL `build_finding` path + the 10 eval cases
  are unchanged; PASS emission + the new framework members are additive, live-path only (WI-C5).
- **WI-C2/C7 multi-emitter e2e** green (Task 19, two-layer); **lane coexistence** 17 distinct
  lanes (Task 20).
- **Cross-agent sweep** (Task 21, WI-C7): **4** OCSF 2003 emitters + 4 consumers, 2326 passed
  / 32 skipped / **0 failed** — the largest 2003 sweep yet.
- **WI-C2 no-fabrication drift guards**: per-framework tests assert every mapping references a
  rule the emitter actually emits.
- **WI-C6 PASS positive evidence**: a PASS attests only when its mapped rules were evaluated;
  `build_pass_finding` rejects an empty attestation.
- **WI-C11 advisory-only**: compliance emits + maps; no enforcement surface.
- **ruff + ruff format + mypy strict** clean per task; tool-proxy boundary inherited.

## §5. Honest findings (WI-C3)

- **Continuous mode is INFRASTRUCTURE; the production loop is NOT wired (Phase C, not v0.3).**
  Per the Path 1 framing, v0.2 ships the scheduler + delta + mode-coexistence + the full
  consumption/attestation/evidence pipeline, all e2e-tested **through emission** — but
  CONTINUOUS is **not** wired into `agent.run()`. The offline `run()` stays the only
  deterministic OCSF-emitting path (WI-C5). Wiring it is the **Phase C consolidated retrofit**
  after all 17 v0.2 cycles — explicitly Phase C, NOT a v0.3 carry-forward.
- **Q2 premise correction (operator-confirmed 2026-06-11) — the headline honesty.** The
  directive assumed the emitters expose ~44 CIS-AWS rules to wire; ground-truth is they expose
  a small **stable** set: F.3 = 7 AWS rules (+ a hash-bucketed Prowler passthrough), D.5 = 8
  Azure + 10 GCP, k8s-posture = 15 CIS-K8s. So "full wiring" was honestly redefined as **wire
  to every rule the emitters actually emit, never fabricate**: 14/43 CIS-AWS, 8 CIS-Azure,
  10 CIS-GCP, 15/15 CIS-K8s. Broader coverage tracks the **emitters** expanding their rule
  catalogs (their work), not compliance inventing mappings. Drift-guard tests enforce this.
- **Wiz-weight target was ~50%; realistic realized ~35% `[estimate]`.** The infrastructure is
  complete across all 4 frameworks (PASS, continuous, evidence), but control coverage is
  **emitter-rule-capped** and the production loop is deferred — so the realized capability is
  below the headline target. Stated plainly per WI-C3.
- **PASS positive-evidence schema is basic** (evaluated-rule list + all-passing); per-resource
  evaluation evidence + richer attestation is v0.3.
- **Evidence manifest signing is a placeholder** — the F.6 audit signer (Cycle 11) slots into
  the injectable seam (WI-C9).
- **Per-framework coverage (WI-C1, no aggregate):** CIS-AWS ~30%, CIS-Azure ~12%, CIS-GCP ~16%,
  CIS-K8s ~12% of full set but 100% of k8s-posture's emitted catalog — all `[estimate]`.

## §6. Watch-items carry-forward

- The **Phase C wiring list** grows by one agent (compliance continuous → run()).
- The Q2 premise reality: CIS-family coverage is emitter-rule-capped; it grows when F.3/D.5/
  k8s-posture expand their stable rule catalogs.
- The F.6 audit-signer integration for the evidence manifest (Cycle 11, WI-C9).
- PCI-DSS / HIPAA / SOC2 / NIST / GDPR frameworks (Phase D / v0.3).

## §7. Phase C deferred handoff (NOT v0.3)

Wire the continuous-monitoring loop (scheduler-driven re-scan + delta) into `agent.run()` so
compliance grades frameworks continuously — the consolidated production-loop retrofit shared
with D.8/D.3/D.4/k8s-posture (the whole detection wave), after all 17 v0.2 cycles close.

## §8. Cross-references

- Cross-agent sweep: `compliance-v0-2-cross-agent-sweep-2026-06-11.md`
- Per-framework coverage: `compliance-v0-2-cis-{aws,azure,gcp,k8s}-coverage-2026-06-11.md`
- Runbook: `packages/agents/compliance/runbooks/multi_emitter_consumption.md`
- OCSF 2003 emitter siblings: F.3 Cloud Posture, D.5 Multi-Cloud Posture, k8s-posture (4 emitters).
- Group D pattern: **consumer #2** (compliance), inheriting k8s-posture v0.2 (`d-6-k8s-posture-v0-2-verification-2026-06-11.md` — the package-named "k8s-posture", distinct from this D.6).

---

**compliance (D.6) v0.2 — CYCLE CLOSED ✅** (pending operator merge of this record). 22/22
tasks, 8/8 milestones, substrate seal empty throughout, 0 failures, full CIS family wired
honestly to real emitter rules, PASS attestation with positive evidence, continuous
infrastructure + audit-ready evidence bundles.
