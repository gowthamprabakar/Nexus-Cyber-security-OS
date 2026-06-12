# synthesis v0.2 — Cross-Agent OCSF 2004 Sweep (WI-Y6)

**Date:** 2026-06-12 · **Task:** synthesis v0.2 Task 19 · **Scope:** prove synthesis (D.13) v0.2
changes don't break any OCSF v1.3 Detection Finding (`class_uid 2004`) emitter or downstream
consumer. **D.13 is the 5th OCSF 2004 emitter** — the largest 2004 class to date.

## Why this is safe by construction

Synthesis's v0.2 OCSF emission is **additive**: `synthesis_finding.json` (the OCSF 2004 finding)
is a **new** workspace output written alongside the unchanged `narrative.md` +
`executive_summary.md`, so the 10 stub-LLM eval cases stay byte-identical (WI-Y5, verified by the
full synthesis suite). Everything else (fleet reader, enumeration, cross-source orchestration,
provider fallback, cost tracking, continuous infra, the three code-level invariants) is **new
modules**. The **deviation profile holds** (empty `build_registry()`, LLM only via
`charter.llm_adapter` — WI-Y9), so no other agent's contract surface changed.

## The 5 OCSF 2004 emitters

| Agent                       | Suite            | Result                    |
| --------------------------- | ---------------- | ------------------------- |
| D.2 Identity                | `identity`       | **211 passed, 1 skipped** |
| D.3 Runtime Threat          | `runtime-threat` | **317 passed, 2 skipped** |
| D.4 Network Threat          | `network-threat` | **387 passed, 3 skipped** |
| D.8 Threat Intel            | `threat-intel`   | **400 passed, 2 skipped** |
| D.13 Synthesis (this cycle) | `synthesis`      | **352 passed, 2 skipped** |

## Downstream consumers (route / audit / investigate / remediate / narrate)

| Agent             | Suite           | Result                    |
| ----------------- | --------------- | ------------------------- |
| Supervisor        | `supervisor`    | **387 passed**            |
| F.6 audit         | `audit`         | **270 passed, 1 skipped** |
| D.7 Investigation | `investigation` | **254 passed, 2 skipped** |
| A.1 Remediation   | `remediation`   | **455 passed, 6 skipped** |
| D.12 Curiosity    | `curiosity`     | **227 passed**            |

## Result

**All 5 emitters + 5 consumers green — 0 failures.** Total (10 agents): **3260 passed, 19
skipped, 0 failed**; the full-repo run at Task 18 was **6674 passed, 69 skipped, 0 failed**. No
OCSF 2004 wire-shape drift; substrate seal empty the entire cycle; D.13 deviation profile
preserved. synthesis v0.2 introduces no cross-agent regression.
