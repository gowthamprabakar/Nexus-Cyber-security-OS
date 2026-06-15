# v0.3 / Phase D — A-4 verification record: D.2 effective-perms driven (2026-06-15)

> Closes **A-4** (D.2 identity effective-perms simulator — the v0.2 watch-item WI-I3
> "built-but-undriven"). Records what shipped, the fork resolutions, and the honest
> scope.

## 1. What shipped

| PR   | What                                                                                                                                                 |
| ---- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| #688 | Wire the IAM `SimulatePrincipalPolicy` simulator into `run()` (gated `assess_effective_perms`); curated action set; resolve → grants → OVERPRIVILEGE |
| this | OVERPRIVILEGE **evidence enrichment** — surface the real per-action / per-resource grants + this verification record                                 |

## 2. Fork resolutions (all operator-approved (a) options)

- **1a curated action set** — `CURATED_RISK_ACTIONS = (iam:*, s3:*, ec2:*, sts:AssumeRole)`.
  **Folded into #688** (the simulator can't run without actions), so the operator's
  separately-planned "PR2 = curated set" was subsumed — no redundant PR was made.
- **2a refine OVERPRIVILEGE** — simulator-derived `EffectiveGrant`s flow through the
  existing normalizer (same OCSF 2004, no new class). This PR completes 2a by
  surfacing the grants in evidence (`admin_actions`, `admin_resource_patterns`),
  not just counting them.
- **3a synchronous in run()** — `_simulate_effective_grants` runs per-principal via
  `ctx.call_tool` (ADR-016 gate/budget/audit) in a TaskGroup.
- **4a skip inline-policy fetch** — the simulator already folds inherited/inline
  policy for users (permission_paths Q3); simulate users + roles only.

## 3. Gate + byte-identicality

`assess_effective_perms` defaults **OFF** (mirrors this agent's `detect_federation`):
the v0.1 attached-policy path (`_synthesize_admin_grants`) stays byte-identical, so
offline eval is unaffected and no AWS is required. **ON** (operator opt-in via
`--assess-effective-perms`, live AWS) drives the simulator.

The evidence enrichment is **eval-safe**: the identity eval runner compares only
`finding_count` / `by_severity` / `by_finding_type` (not the evidence dict), and the
unit tests assert individual evidence keys — so the two new keys break nothing. Full
identity suite **216 pass / 1 skip**; ruff + mypy clean; substrate seal EMPTY.

## 4. Honest scope (carried forward)

- **Live simulation is operator-run** (gated); the +pp lift is realized when the
  live lane runs against a real account, not by the wiring alone (same honesty as
  the A-1 live-readers).
- **Azure effective-perms** remains out of scope (the AzureAdListing is shape-
  disjoint with no role-assignment/simulation API) — AWS-only, as scoped.
- **SCPs / condition keys / inline-policy bodies** stay deferred (permission_paths
  Q3 Phase-1 caps) — the curated-action simulator is the honest first depth step,
  not a complete effective-permissions engine.

## 5. References

- A-4 recon — `v0-3-a-4-recon-2026-06-14.md`. WI-I3 — `project_d2_v0_2_closed`.
- Simulator wiring — `identity/agent.py` (`_simulate_effective_grants`, #688);
  evidence — `identity/normalizer.py` `_overprivilege_findings`.
