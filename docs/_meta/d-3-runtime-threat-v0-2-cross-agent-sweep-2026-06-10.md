# D.3 Runtime Threat v0.2 — Cross-Agent OCSF 2004 Consumer Sweep (WI-R6)

**Date:** 2026-06-10 · **Task:** D.3 v0.2 Task 20 · **Scope:** prove D.3 v0.2 changes
don't break any OCSF v1.3 Detection Finding (`class_uid 2004`) emitter or downstream
consumer. Same surface as D.8 v0.2 Task 19.

## Why this is safe by construction

Every D.3 v0.2 change was kept **off** the OCSF emission path:

- The real-time Falco/Tracee readers + framework, MITRE catalog/mapper, baseline,
  snapshot action, and handoff helpers are **new modules** not wired into the
  deterministic `run()` correlation→emission path.
- The MITRE technique block + investigation-handoff flag attach to evidence **only when
  present** (`attach_techniques([])` / offline `run()` never calls them) — so the 10
  offline eval cases + the OCSF 2004 wire shape are byte-identical (WI-R5).

So no consumer's input contract changed. The sweep below is the empirical proof.

## OCSF 2004 emitters (share the `class_uid 2004` wire shape)

| Agent                           | Suite                            | Result                    |
| ------------------------------- | -------------------------------- | ------------------------- |
| D.4 Network Threat              | `packages/agents/network-threat` | **231 passed**            |
| D.8 Threat Intel                | `packages/agents/threat-intel`   | **400 passed, 2 skipped** |
| D.3 Runtime Threat (this cycle) | `packages/agents/runtime-threat` | **317 passed, 2 skipped** |

## Downstream consumers (read / route / synthesize 2004 findings)

| Agent                     | Suite                           | Result                    |
| ------------------------- | ------------------------------- | ------------------------- |
| D.7 Investigation         | `packages/agents/investigation` | **254 passed, 2 skipped** |
| A.1 Remediation           | `packages/agents/remediation`   | **455 passed, 6 skipped** |
| Synthesis                 | `packages/agents/synthesis`     | **214 passed, 1 skipped** |
| Audit                     | `packages/agents/audit`         | **129 passed**            |
| Compliance                | `packages/agents/compliance`    | **225 passed**            |
| Curiosity                 | `packages/agents/curiosity`     | **227 passed**            |
| Data Security             | `packages/agents/data-security` | **292 passed**            |
| Supervisor (Meta-Harness) | `packages/agents/supervisor`    | **234 passed**            |

## Result

**All emitters + consumers green — 0 failures.** Consumer total (10 agents):
**2661 passed, 11 skipped, 0 failed**; the full-repo run at Task 19 was **5671 passed,
61 skipped, 0 failed**. No OCSF 2004 wire-shape drift; substrate seal empty the entire
cycle (no charter touch). D.3 v0.2 introduces no cross-agent regression.
