# D.8 Threat Intel v0.2 — Cross-Agent OCSF 2004 Consumer Sweep (WI-T6)

**Date:** 2026-06-10 · **Task:** D.8 v0.2 Task 19 · **Scope:** prove D.8 v0.2 changes
don't break any OCSF v1.3 Detection Finding (`class_uid 2004`) emitter or downstream
consumer. Same surface as D.2 v0.2 Task 20.

## Why this is safe by construction

Every D.8 v0.2 change was kept **off** the OCSF emission path:

- Live feeds (Tasks 5–9) added **live** readers _alongside_ the offline readers; the
  offline `read_*` + `run()` pipeline + the 10 offline eval cases are unchanged (WI-T5).
- The continuous-ingestion framework, STIX/TAXII + HTTP poller, profiles, briefing, and
  threat-actor matcher are **new modules** not wired into `run()`'s correlation→emission.
- `build_registry()` gained live tools but `run()` still makes exactly its prior tool
  calls — the OCSF 2004 wire shape is byte-identical.

So no consumer's input contract changed. The sweep below is the empirical proof.

## OCSF 2004 emitters (share the `class_uid 2004` wire shape)

| Agent                         | Suite                            | Result                    |
| ----------------------------- | -------------------------------- | ------------------------- |
| D.4 Network Threat            | `packages/agents/network-threat` | **231 passed**            |
| D.3 Runtime Threat            | `packages/agents/runtime-threat` | **181 passed**            |
| D.8 Threat Intel (this cycle) | `packages/agents/threat-intel`   | **400 passed, 2 skipped** |

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
**2442 passed, 9 skipped, 0 failed**; the full-repo run at Task 18 was **5535 passed,
59 skipped, 0 failed**. No OCSF 2004 wire-shape drift; substrate seal empty the entire
cycle (no charter touch). D.8 v0.2 introduces no cross-agent regression.
