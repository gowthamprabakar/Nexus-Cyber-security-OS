# D.2 Identity v0.2 — Cross-Agent Regression Sweep (WI-I7)

**Task:** D.2 v0.2 Milestone 7, Task 20.
**Date:** 2026-06-10
**Scope:** The largest cross-agent sweep of the detection track yet — every OCSF
`class_uid 2004` emitter + every charter-hoist consumer + the finding-consumer
agents, run green **after** the D.2 cycle's three SAFETY-CRITICAL charter hoists
(Patterns E + D + A). The hoist is the cycle's risk surface; this sweep is the proof
it regressed no consumer.

> WI-I7 (brainstorm §15): "cross-agent regression sweep at closure — the largest yet …
> all green **after the charter hoist**."

---

## §1. Why this sweep is the largest

D.2 is the cycle where the ADR-007 third-consumer charter hoist finally fired:
`charter.degradation` (Pattern E), `charter.live_lane` (Pattern D), and
`charter.credentials.CredentialResolver` (Pattern A) were hoisted from F.3 / D.5 / D.1
and adopted by their origin agents + identity. A regression in any hoisted contract
would surface fleet-wide — so the sweep covers both the **OCSF 2004 surface** and the
**charter-hoist consumers**, plus a full-repo run.

---

## §2. OCSF 2004 emitters + finding-consumer agents — all green

`class_uid 2004` (Detection Finding) emitters and the agents that consume / correlate
findings:

| Agent                | Result                                         |
| -------------------- | ---------------------------------------------- |
| identity (D.2)       | **211 passed, 1 skipped** (the gated live e2e) |
| runtime-threat (D.3) | **181 passed**                                 |
| network-threat (D.4) | **231 passed**                                 |
| threat-intel (D.8)   | **249 passed**                                 |
| investigation (D.7)  | **254 passed, 2 skipped**                      |
| synthesis (D.13)     | **214 passed, 1 skipped**                      |
| audit (F.6)          | **129 passed**                                 |
| compliance           | **225 passed**                                 |

OCSF wire shapes unchanged: identity emits `2004` (incl. the new `federation` finding
type, Task 15) with `IdentityFinding` validating `class_uid == 2004` + the id pattern
at construction.

---

## §3. Charter-hoist consumers — regression proof

The agents that adopted the hoisted Patterns E / D / A (plus the charter itself):

| Agent / package           | Result                     | Adopted                                            |
| ------------------------- | -------------------------- | -------------------------------------------------- |
| charter                   | **335 passed, 9 skipped**  | the 3 hoisted contracts + tests                    |
| cloud-posture (F.3)       | **148 passed, 9 skipped**  | Pattern E + D + A (origin)                         |
| multi-cloud-posture (D.5) | **344 passed, 12 skipped** | Pattern D mirror + Pattern A (Azure/GCP resolvers) |
| vulnerability (D.1)       | **244 passed, 11 skipped** | Pattern E + D (registry lanes)                     |

**Tool-proxy hard boundary intact:** `charter/tests/test_tool_import_guard.py` —
**16 passed, 1 skipped**. The ADR-016 boundary that the NLAH backfill cycle established
still holds after the D.2 substrate work.

---

## §4. Full-repo grand total

```
5384 passed, 57 skipped, 0 failed
```

The 57 skips are the env-gated live lanes (NEXUS*LIVE*\* AWS/Azure/GCP/registry/identity

- NATS/Postgres) — green when their credentials/services are present, skipped in CI.

---

## §5. Conclusion

The D.2 Identity v0.2 cycle — including the three charter hoists (E + D + A) and their
fleet-wide adoption — **regressed no consumer**. Every OCSF 2004 emitter, every
charter-hoist consumer, and the full repository are green. The substrate-seal-empty
streak resumed correctly after the intentional hoists (Tasks 2–4), and Tasks 5–19 each
kept the seal empty.

WI-I7 satisfied. Cleared for closure (Tasks 21–24).
