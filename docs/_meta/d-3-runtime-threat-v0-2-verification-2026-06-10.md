# D.3 Runtime Threat v0.2 — Verification Record & Cycle Closure

**Date:** 2026-06-10 · **Cycle 6 of 17** (Phase 3 of the Option α roadmap) · **Maturity:
Level 1 → Level 2 (Real-Time Event Streams).** The **first Group A** (real-time-class)
agent. Single comprehensive directive, self-merge cascade (Tasks 1–21), operator review
at close (Task 22).

---

## §1. Cycle summary

D.3 took the Runtime Threat agent from **v0.1** (offline Falco/Tracee/OSQuery alert
normalizers) to **v0.2**: **live real-time event subscription** for Falco + Tracee
(push, gRPC/pipe) alongside the heartbeat readers, live normalization + process/container/
k8s + syscall enrichment, **cross-sensor correlation**, **MITRE ATT&CK** technique mapping
with heuristic confidence, **passive behavioral baseline** observation + persistence, a
**read-only forensic snapshot** action + write-once artifact store, and an **Investigation
handoff** flag.

- **22 tasks, 22 PRs** (#389–#409 + this record). 8 milestones.
- **Tests:** runtime-threat **181 → 317 passed** (+136) + 2 gated-live skips. Full repo
  **5671 passed, 61 skipped, 0 failed**.
- **Substrate seal EMPTY the entire cycle** — no charter touch (WI-R2: the real-time
  event-stream pattern is documented for a future ADR-007 third-consumer hoist; D.3 is
  consumer #1, D.4 Network Threat in Cycle 7 the likely #2).
- **No charter hoist** fired (as planned).

## §2. Task execution table

| #   | Task                                                   | PR        | Risk                  |
| --- | ------------------------------------------------------ | --------- | --------------------- |
| 1   | Bootstrap (version + ADR-010 + OCSF 2004 verification) | #389      | LOW                   |
| 2   | Falco real-time subscription framework                 | #390      | LOW                   |
| 3   | Falco rule pack management                             | #391      | LOW                   |
| 4   | Falco live event normalization                         | #392      | LOW                   |
| 5   | Tracee real-time subscription                          | #393      | LOW                   |
| 6   | Tracee live event normalization                        | #394      | LOW                   |
| 7   | Falco + Tracee cross-sensor correlation                | #395      | LOW                   |
| 8   | MITRE ATT&CK technique catalog loader                  | #396      | LOW                   |
| 9   | Event → MITRE technique mapping engine                 | #397      | LOW                   |
| 10  | MITRE technique emission in findings                   | #398      | LOW                   |
| 11  | Passive behavioral baseline collector                  | #399      | LOW                   |
| 12  | Baseline persistence layer                             | #400      | LOW                   |
| 13  | Forensic snapshot action emission                      | #401      | LOW                   |
| 14  | Snapshot artifact handling                             | #402      | LOW                   |
| 15  | Investigation agent handoff                            | #403      | LOW                   |
| 16  | NEXUS_LIVE_RUNTIME_FALCO gated lane                    | #404      | LOW                   |
| 17  | NEXUS_LIVE_RUNTIME_TRACEE gated lane                   | #405      | LOW                   |
| 18  | WI-R4 live real-time event e2e                         | #406      | LOW                   |
| 19  | Lane coexistence with prior cycles                     | #407      | LOW                   |
| 20  | Cross-agent OCSF 2004 sweep                            | #408      | LOW                   |
| 21  | Per-sensor coverage + runbooks + README v0.2           | #409      | LOW                   |
| 22  | Verification record + cycle closure                    | _this PR_ | LOW (operator review) |

## §3. Q-lock mapping (all 7 honored)

| Q   | Lock                                                 | Where honored                                                                                      |
| --- | ---------------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| Q1  | (C) Heartbeat + real-time coexist; preempt → v0.3    | `falco_realtime.py` / `tracee_realtime.py` run alongside the offline readers; no preempt (WI-R11)  |
| Q2  | (B) Falco + Tracee; Tetragon/Wazuh → v0.3            | Both sensors live (Tasks 2–7); separate lanes (Tasks 16–17)                                        |
| Q3  | (B) Basic rule-based MITRE mapping + confidence      | `mitre/mapper.py` static heuristic confidence (Tasks 8–10)                                         |
| Q4  | (B) Snapshot only (read-only); kill/quarantine → A.1 | `actions/snapshot.py` — `assert_authorized` hard-blocks non-snapshot (WI-R8/R9)                    |
| Q5  | (B) Passive baseline                                 | `baseline/` collects + persists, no drift detection (WI-R10)                                       |
| Q6  | (B) D.3 emits; D.7 escalates                         | `handoff.py` sets the flag; no escalate/notify surface                                             |
| Q7  | Maintain OCSF class_uid (byte-identical)             | **Verified class_uid 2004** (directive's "likely 2005" was wrong); pinned + byte-identical (WI-R5) |

## §4. Gates passed

- **All 5 CI checks green** on every one of the 21 self-merged PRs (server-side merge
  gate enforced each merge).
- **Substrate seal EMPTY** for all 22 tasks (no charter/shared edit; Tasks 16–17 _consume_
  the hoisted `charter.live_lane`).
- **OCSF 2004 byte-identical** every task: live readers added _alongside_ the offline
  readers; the technique block + handoff flag attach to evidence **only when present**, so
  the offline `run()` + the 10 eval cases are unchanged (WI-R5).
- **WI-R4 live real-time lane** green: two-layer e2e (offline every push + gated
  `NEXUS_LIVE_RUNTIME_FALCO/TRACEE=1`), Task 18.
- **Cross-agent sweep** (Task 20, WI-R6): 3 OCSF 2004 emitters + 8 consumers,
  2661 passed / 11 skipped / **0 failed**.
- **Q4 safety invariant** (WI-R8) held: no Tier-1 (kill/quarantine) action exists; the
  only action is the read-only snapshot, guarded by `assert_authorized`.
- **ruff + ruff format + mypy strict** clean per task; tool-proxy boundary inherited.

## §5. Honest findings (WI-R3)

- **The defining gap — real-time → OCSF production loop is NOT wired (v0.3).** Like D.8's
  §5, v0.2 ships the real-time-event _infrastructure_ + MITRE/baseline/snapshot/handoff
  _building blocks_, all unit- and e2e-tested through **emission**. But the live readers
  are **not** driven from the agent's `run()` correlation→OCSF path — the **offline
  `run()` remains the only OCSF-2004-emitting path** (deliberately, WI-R5). So "subscribe
  to live sensors → emit OCSF findings continuously" is **not** an end-to-end production
  capability at v0.2; it is the largest v0.3 carry-forward.
- **Wiz-weight target was ~70%; realistic realized ~50–55% `[estimate]`.** The live
  subscription breadth + framework move the agent toward L2, but because the production
  loop above is deferred, the _realized_ capability is nearer the v0.1 baseline. Stated
  plainly per WI-R3 rather than claimed.
- **Real-time does not preempt the heartbeat** (Q1/WI-R11) — both modes coexist; preempt
  (benchmark Mode B) is v0.3.
- **Baseline is collected but not driving outcomes** (Q5/WI-R10) — passive; active drift
  detection is v0.3.
- **MITRE mapping confidence is a static heuristic** (Q3), not automated extraction.
- **Kill / workload quarantine are deferred to the A.1 Remediation cycle** (Q4/WI-R9);
  D.3 emits findings + a read-only snapshot + recommendations only.
- **Coverage is breadth, not depth, per-sensor (WI-R1, no aggregate):** Falco ~55–65%,
  Tracee ~50–60% — both `[estimate]`, see the per-sensor coverage docs.

## §6. Watch-items carry-forward

- **WI-R2:** the real-time-event-stream pattern is documented (`falco_realtime.py`
  docstring); evaluate the ADR-007 third-consumer hoist when consumer #3 emerges (D.4 in
  Cycle 7 is the likely #2 — Group A pattern reuse).
- The honest-findings gaps above, foremost the **real-time → OCSF run-loop wiring**.
- eBPF capability / kernel-version + sensor-socket reachability are operator concerns
  (runbooks flag this).

## §7. v0.3 deferred handoff

Tetragon advanced kernel telemetry (Q2) · active behavioral drift detection (Q5) · full
automated MITRE mapping (Q3) · real-time preempt of the heartbeat (Q1, Mode B) ·
**Tier-1 process kill / workload quarantine via the A.1 Remediation cycle** (Q4) · and the
headline item: **wiring the live real-time readers into the agent's correlation→OCSF run
loop** so sensors emit OCSF 2004 findings end-to-end.

## §8. Cross-references

- Cross-agent sweep: `d-3-runtime-threat-v0-2-cross-agent-sweep-2026-06-10.md`
- Per-sensor coverage: `d-3-runtime-threat-v0-2-{falco,tracee}-coverage-2026-06-10.md`
- Runbooks: `packages/agents/runtime-threat/runbooks/{falco,tracee}_realtime.md`
- **D.8 v0.2 precedent** (continuous-ingestion class, the prior cycle):
  `d-8-threat-intel-v0-2-verification-2026-06-10.md`
- **Group A real-time-class precedent for D.4 (Cycle 7):** this record. D.4 Network Threat
  inherits the real-time-subscription + per-sensor-scope + action-with-safety-invariant +
  Investigation-handoff + dual-mode patterns; its v0.2 action is a temporary auto-expiring
  IP block (vs D.3's read-only snapshot).

---

**D.3 Runtime Threat (CWPP) v0.2 — CYCLE CLOSED ✅** (pending operator merge of this
record). 22/22 tasks, 8/8 milestones, substrate seal empty throughout, 0 failures, Q4
safety invariant held.
