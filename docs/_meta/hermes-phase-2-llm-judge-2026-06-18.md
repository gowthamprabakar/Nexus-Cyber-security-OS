# Hermes Phase 2 — LLM-judge adjudication (additive, above the pass-rate floor)

_2026-06-18 · v0.4 Stage 2 · self-merge (no substrate touch)_

## What shipped

An Anthropic-style **LLM-as-judge** that adjudicates a DSPy candidate vs the legacy candidate
on **qualitative** merit — layered strictly **above** the deterministic eval-gate pass-rate
comparison, which remains the **hard floor**.

- `meta_harness/skill_judge.py`
  - `judge_skill_candidates(...)` — a single categorical comparison (`A` / `B` / `TIE`) over
    `charter.llm`, enforcing the two shared LLM invariants: `assert_categorical_only` (no
    plaintext PII echoed into the verdict) + `assert_bounded_retry` (initial + at most one
    retry). Any provider error, unparseable reply, or contract violation collapses to `TIE`
    (abstain). The judge never raises and never skews a run.
  - `adjudicate_with_judge(...)` — the pure adjudicator. Mirrors `adjudicate_pass_rates`
    exactly when no verdict is supplied; the judge is consulted **only on a pass-rate tie** and
    can shift the outcome **only toward DSPy**.

## How "additive above the floor" is enforced

| Pass-rate relation       | Decision                                           | Judge consulted?                           |
| ------------------------ | -------------------------------------------------- | ------------------------------------------ |
| DSPy **>** legacy        | DSPy wins                                          | no — floor decides                         |
| DSPy **<** legacy        | legacy wins (hard floor)                           | **no** — a regression can never be rescued |
| DSPy **==** legacy (tie) | judge breaks it; `PREFER_DSPY` → DSPy, else legacy | yes (if enabled)                           |

So the judge can only ever _add_ DSPy promotions in the region the deterministic floor leaves
ambiguous (commonly both candidates at 1.0). It cannot demote a pass-rate winner nor rescue a
pass-rate loser. Pass-rate stays the hard floor (operator Q4).

## Default-OFF

Gated behind `NEXUS_DSPY_LLM_JUDGE` (default-OFF), and a no-op anyway unless the DSPy path is
itself enabled (`NEXUS_DSPY_PRODUCTION`). Capability, not a flag flip. With both flags unset the
adjudication is byte-identical to the prior deterministic behaviour.

## Tests

`test_skill_judge.py` (floor invariance + defensive abstain + bounded retry + categorical
guard) and `test_task6_adjudication.py` (tie → judge promotes / abstains; regression never
consults the judge). 693 pass / 2 skip · ruff + mypy clean · no charter/schemas touch.
