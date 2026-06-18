# Hermes Phase 5 — skill deprecation (dual-trigger + sunset period)

_2026-06-18 · v0.4 Stage 2 · self-merge (no substrate touch)_

## What shipped

`meta_harness/skill_deprecation.py` — an **advisory** deprecation policy for deployed skills.

### Dual trigger (Q6 — OR semantics, either fires)

- **time** (`STALE_AGE`) — deployed longer than `DEFAULT_MAX_AGE_DAYS` (90). A rotation/staleness
  policy: old skills get re-examined even if still passing.
- **performance** (`LOW_EFFECTIVENESS`) — measured `global_score` below `DEFAULT_MIN_EFFECTIVENESS`
  (0.4) with non-zero confidence. An unscored skill is **never** deprecated on performance grounds.

### Sunset period

A flagged skill enters a `DEFAULT_SUNSET_DAYS` (14) window as `DeprecationPhase.SUNSET` — still
live, but on notice, giving a replacement time to deploy. Once the window elapses it becomes
`EXPIRED` (recommended for archival). If every trigger clears before the window elapses (e.g.
effectiveness recovers, or the skill is no longer stale) the flag is dropped and the skill
returns to `ACTIVE`.

## Advisory only — never auto-removes

Mirrors the F.6 audit agent (never auto-repairs) and A.1 (default-recommend): this module
produces `DeprecationDecision` records and logs flagged skills, but **never** archives or removes
a skill from the registry. Acting on an `EXPIRED` recommendation is a deliberate operator/driver
action. The controller is therefore safe to run continuously.

## Honest limitation — age anchoring

No deploy timestamp is persisted with deployed skills, so the controller measures age from when
it **first observed** the skill (stamped into `.nexus/skill-deprecation/state.json`). For skills
already deployed before the controller first ran, age is a **lower bound** on true deployment age
— conservative (never deprecates earlier than warranted). A persisted deploy timestamp is a v0.5
refinement.

## Tests

`test_skill_deprecation.py` — pure dual-trigger logic, sunset→expired transition, recovery
flag-clear, unscored-never-deprecated, plus controller state persistence / first-observation
age anchoring / stale-state pruning. 703 pass / 2 skip (meta-harness) · ruff + mypy clean · no
charter/schemas touch.
