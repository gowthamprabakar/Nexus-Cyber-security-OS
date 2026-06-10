# D.4 Network Threat v0.2 — Cross-Agent OCSF 2004 Consumer Sweep (WI-N6)

**Date:** 2026-06-11 · **Task:** D.4 v0.2 Task 20 · **Scope:** prove D.4 v0.2 changes
don't break any OCSF v1.3 Detection Finding (`class_uid 2004`) emitter or downstream
consumer. **Now 4 emitters** (D.2, D.3, D.4, D.8) — larger than D.3's sweep (D.4 is the
additional emitter).

## Why this is safe by construction

Every D.4 v0.2 change was kept **off** the OCSF emission path:

- The real-time Suricata/Zeek/VPC readers + framework, MITRE-free detectors, DNS
  refinements, TTL'd block action, and handoff helpers are **new modules** not wired into
  the deterministic `run()` correlation→emission path.
- The new detectors are **additive** (the v0.1 port_scan / beacon / dga + their eval
  cases are untouched); the block/handoff fields attach to evidence **only when present**
  — so the 10 offline eval cases + the OCSF 2004 wire shape are byte-identical (WI-N5).

So no consumer's input contract changed. The sweep below is the empirical proof.

## OCSF 2004 emitters (4 — share the `class_uid 2004` wire shape)

| Agent                           | Suite                            | Result                    |
| ------------------------------- | -------------------------------- | ------------------------- |
| D.2 Identity                    | `packages/agents/identity`       | **211 passed, 1 skipped** |
| D.3 Runtime Threat              | `packages/agents/runtime-threat` | **317 passed, 2 skipped** |
| D.4 Network Threat (this cycle) | `packages/agents/network-threat` | **387 passed, 3 skipped** |
| D.8 Threat Intel                | `packages/agents/threat-intel`   | **400 passed, 2 skipped** |

## Downstream consumers (read / route / synthesize 2004 findings)

| Agent             | Suite                           | Result                    |
| ----------------- | ------------------------------- | ------------------------- |
| D.7 Investigation | `packages/agents/investigation` | **254 passed, 2 skipped** |
| A.1 Remediation   | `packages/agents/remediation`   | **455 passed, 6 skipped** |
| Synthesis         | `packages/agents/synthesis`     | **214 passed, 1 skipped** |
| Audit             | `packages/agents/audit`         | **129 passed**            |
| Compliance        | `packages/agents/compliance`    | **225 passed**            |
| F.3 Cloud Posture | `packages/agents/cloud-posture` | **148 passed, 9 skipped** |

## Result

**All 4 emitters + 6 consumers green — 0 failures.** Total (10 agents): **2740 passed,
26 skipped, 0 failed**; the full-repo run at Task 19 was **5827 passed, 64 skipped, 0
failed**. No OCSF 2004 wire-shape drift; substrate seal empty the entire cycle (no charter
touch). D.4 v0.2 introduces no cross-agent regression.
