# D.4 Network Threat v0.2 — Verification Record & Cycle Closure

**Date:** 2026-06-11 · **Cycle 7 of 17** (Phase 3 of the Option α roadmap) · **Maturity:
Level 1 → Level 2 (Real-Time Event Streams).** The **second Group A** (real-time-class)
agent — real-time-event-stream pattern **consumer #2** (D.3 was #1). Single comprehensive
directive, self-merge cascade (Tasks 1–21), operator review at close (Task 22).

---

## §1. Cycle summary

D.4 took the Network Threat agent from **v0.1** (offline Suricata/VPC/DNS readers + 3
detectors) to **v0.2**: **live Suricata + Zeek real-time subscription** + **live AWS VPC
Flow Logs** alongside the heartbeat readers, live normalization + cross-sensor correlation,
DGA/DNS-pattern + connection-rate detection refinement, a **TTL-bounded auto-expiring
IP-block** action with a code-level safety guard, and an Investigation handoff flag.

- **22 tasks, 22 PRs** (#411–#431 + this record). 8 milestones.
- **Tests:** network-threat **231 → 387 passed** (+156) + 3 gated-live skips. Full repo
  **5827 passed, 64 skipped, 0 failed**.
- **Substrate seal EMPTY the entire cycle** — no charter touch (WI-N2: the real-time
  event-stream pattern is now at **consumer #2**; the ADR-007 third-consumer hoist
  evaluation is LIVE for a future consumer #3). Tasks 8/18 _consume_ the hoisted
  `charter.credentials` + `charter.live_lane`.
- **No charter hoist** fired (as planned).

## §2. Task execution table

| #   | Task                                                   | PR        | Risk                  |
| --- | ------------------------------------------------------ | --------- | --------------------- |
| 1   | Bootstrap (version + ADR-010 + OCSF 2004 verification) | #411      | LOW                   |
| 2   | Suricata real-time subscription framework              | #412      | LOW                   |
| 3   | Suricata live alert normalization                      | #413      | LOW                   |
| 4   | Suricata rule pack management                          | #414      | LOW                   |
| 5   | Zeek real-time subscription                            | #415      | LOW                   |
| 6   | Zeek live event normalization                          | #416      | LOW                   |
| 7   | Zeek + Suricata cross-sensor correlation               | #417      | LOW                   |
| 8   | Live AWS VPC Flow Logs subscription                    | #418      | LOW                   |
| 9   | VPC flow normalization + aggregation                   | #419      | LOW                   |
| 10  | Flow anomaly detection refinement                      | #420      | LOW                   |
| 11  | DGA detection enhancement                              | #421      | LOW                   |
| 12  | DNS query pattern detection                            | #422      | LOW                   |
| 13  | DNS resolver integration improvements                  | #423      | LOW                   |
| 14  | Temporary IP block action infrastructure               | #424      | LOW                   |
| 15  | IP block auto-expiry mechanism                         | #425      | LOW                   |
| 16  | Block action emission flow                             | #426      | LOW                   |
| 17  | Suricata + Zeek gated lanes                            | #427      | LOW                   |
| 18  | NEXUS_LIVE_NETWORK_VPC_AWS lane                        | #428      | LOW                   |
| 19  | WI-N4 live e2e + lane coexistence                      | #429      | LOW                   |
| 20  | Cross-agent OCSF 2004 sweep (4 emitters)               | #430      | LOW                   |
| 21  | Per-sensor coverage + runbooks + README v0.2           | #431      | LOW                   |
| 22  | Verification record + cycle closure                    | _this PR_ | LOW (operator review) |

## §3. Q-lock mapping (all 7 honored)

| Q   | Lock                                              | Where honored                                                                             |
| --- | ------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| Q1  | (C) Heartbeat + real-time coexist; preempt → v0.3 | `suricata_realtime.py` / `zeek_realtime.py` alongside offline readers; no preempt         |
| Q2  | (A) Suricata + Zeek + VPC flow                    | All three live (Tasks 2–9); separate lanes (Tasks 17–18)                                  |
| Q3  | (B) AWS VPC live; Azure/GCP → v0.3                | `vpc_flow_realtime_aws.py` AWS-only via CloudWatch + CredentialResolver (Task 8)          |
| Q4  | (A) TTL'd IP block; permanent/BGP → A.1           | `actions/temporary_ip_block.assert_block_authorized` hard guard (TTL 1-3600, public-only) |
| Q5  | (B) D.4 emits; D.7 + D.8 correlate                | standalone — no direct D.8 dependency (Task 13)                                           |
| Q6  | (B) D.4 emits handoff flag; D.7 escalates         | `actions/emission_flow.attach_block_handoff`; no escalate surface                         |
| Q7  | OCSF class_uid 2004 (byte-identical)              | verified + pinned (WI-N5); 4th emitter (D.2/D.3/D.4/D.8)                                  |

## §4. Gates passed

- **All 5 CI checks green** on every one of the 21 self-merged PRs.
- **Substrate seal EMPTY** for all 22 tasks (no charter/shared edit; Tasks 8/18 _consume_
  the hoists).
- **OCSF 2004 byte-identical** every task: live readers added _alongside_ the offline
  readers; the new detectors are additive; the block/handoff fields attach to evidence
  **only when present**, so the offline `run()` + the 10 eval cases are unchanged (WI-N5).
- **WI-N4 live real-time lane** green: two-layer e2e (offline every push + gated
  `NEXUS_LIVE_NETWORK_*=1`), Task 19. **Auto-expiry exercised end-to-end (WI-N11).**
- **Cross-agent sweep** (Task 20, WI-N6): **4** OCSF 2004 emitters + 6 consumers,
  2740 passed / 26 skipped / **0 failed**.
- **Q4 safety invariant** (WI-N8/N10) held: the only action is the TTL-bounded
  `temporary_ip_block`; `assert_block_authorized` hard-rejects permanent / over-1h /
  private-range / non-block actions, and a removal failure escalates (WI-N11).
- **ruff + ruff format + mypy strict** clean per task; tool-proxy boundary inherited.

## §5. Honest findings (WI-N3)

- **The defining gap — real-time → OCSF production loop is NOT wired (v0.3).** Like
  D.3/D.8's §5, v0.2 ships the real-time-event _infrastructure_ + detection/action/handoff
  _building blocks_, all unit- and e2e-tested through **emission**. But the live readers
  are **not** driven from the agent's `run()` correlation→OCSF path — the **offline
  `run()` remains the only OCSF-2004-emitting path** (deliberately, WI-N5). So "subscribe
  to live network sensors → emit OCSF findings continuously" is **not** an end-to-end
  production capability at v0.2; it is the largest v0.3 carry-forward.
- **Wiz-weight target was ~50%; realistic realized ~30–35% `[estimate]`.** The live
  subscription breadth + framework move the agent toward L2, but because the production
  loop above is deferred, the _realized_ capability is nearer the v0.1 baseline. Stated
  plainly per WI-N3 rather than claimed.
- **Real-time does not preempt the heartbeat** (Q1) — both modes coexist; preempt is v0.3.
- **Azure NSG + GCP VPC flow logs are NOT live** (Q3) — AWS only at v0.2.
- **Permanent IP blocks + BGP/routing changes are out of scope** (Q4/WI-N9) — A.1
  Remediation cycle; D.4 only emits the TTL-bounded auto-expiring block.
- **Beacon/DGA/connection-rate detection is heuristic**, not behavioral models (v0.3).
- **Coverage is breadth, not depth, per-sensor (WI-N1, no aggregate):** Suricata ~50–60%,
  Zeek ~45–55%, VPC flow ~40–50% — all `[estimate]`, see the per-sensor coverage docs.

## §6. Watch-items carry-forward

- **WI-N2:** the real-time-event-stream pattern is now at **consumer #2** (D.3 + D.4); the
  ADR-007 third-consumer hoist evaluation is LIVE — when a consumer #3 emerges (a future
  cycle), the hoist fires.
- The honest-findings gaps above, foremost the **real-time → OCSF run-loop wiring**.
- Cloud-provider expansion (Azure/GCP VPC flow) + the v5 field surface are operator/v0.3
  concerns (runbooks flag this).

## §7. v0.3 deferred handoff

Azure NSG flow + GCP VPC flow (Q3) · real-time preempt of the heartbeat (Q1) · behavioral
models (beacon/DGA/flow) · **permanent IP block / BGP-routing changes via the A.1
Remediation cycle** (Q4) · microsegmentation recommendations · and the headline item:
**wiring the live real-time readers into the agent's correlation→OCSF run loop** so
sensors emit OCSF 2004 findings end-to-end.

## §8. Cross-references

- Cross-agent sweep: `d-4-network-threat-v0-2-cross-agent-sweep-2026-06-11.md`
- Per-sensor coverage: `d-4-network-threat-v0-2-{suricata,zeek,vpc-flow}-coverage-2026-06-11.md`
- Runbooks: `packages/agents/network-threat/runbooks/{suricata,zeek}_realtime.md` + `aws_vpc_flow_live.md`
- **D.3 v0.2 (Group A consumer #1, the precedent this cycle inherited):**
  `d-3-runtime-threat-v0-2-verification-2026-06-10.md`
- **D.8 v0.2 (continuous-ingestion class):** `d-8-threat-intel-v0-2-verification-2026-06-10.md`
- Group A real-time-event-stream pattern: now at **2 consumers** (D.3 + D.4); hoist
  evaluation LIVE for #3.

---

**D.4 Network Threat (Network IDS) v0.2 — CYCLE CLOSED ✅** (pending operator merge of this
record). 22/22 tasks, 8/8 milestones, substrate seal empty throughout, 0 failures, Q4
TTL-block safety invariant held + auto-expiry verified e2e.
