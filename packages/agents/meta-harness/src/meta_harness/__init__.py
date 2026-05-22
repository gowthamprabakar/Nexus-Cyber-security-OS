"""Nexus Meta-Harness Agent — A.4 v0.2 / Phase 1 Wave 0.

**v0.2 transitions A.4 from read-only diagnostics (v0.1) to the
platform's first auto-acting Meta-Harness.** Composes SKILL.md
candidates from successful complex agent runs, eval-gates them
against the target agent's eval suite, and auto-deploys them to
the target agent's NLAH directory after operator approval (for
first-of-class) or eval-gate pass (for refinements of proven
classes). Becomes the **third forbidden subscriber** under ADR-012,
closing the Q-ARCH-1 trajectory predicted in Supervisor v0.1's
verification record.

Phase 1 / Wave 0 scope (locked 2026-05-22):

- **N1** Progressive-disclosure NLAH loader — Level 0 metadata
  index, Level 1 full SKILL.md, Level 2 references.
- **N2** Autonomous skill creation — >=5 tool calls + successful
  + tool-sequence-hash novel vs deployed skills.
- **N5** agentskills.io open format from day one.
- **NLAH auto-deploy with safety rails** — mandatory eval-gate +
  first-of-class operator approval.
- **Subscriber-ACL self-registration** — Task 11 SAFETY-CRITICAL
  adds ``_FORBIDDEN_SUBSCRIPTIONS["meta_harness"]``.

Seven-stage pipeline (extends v0.1's 6-stage):

  INTROSPECT -> BATCH_EVAL -> AB_COMPARE -> DELTA -> REPORT
                -> SKILL_TRIGGER -> SKILL_CREATE -> HANDOFF

LLM consumption first introduced in v0.2 at Stage 7 SKILL_CREATE
via ``charter.llm_adapter`` (same pattern as D.13 / D.12).

Watch-items (v0.2):

- WI-1: substrate sealed except Tasks 4 + 11 (both SAFETY-CRITICAL).
- WI-2: single-tenant default (``semantic_store=None`` opt-in).
- WI-3: stub-LLM determinism extended to skill content.
- WI-4: auto-deploy safety rails — no skill deploys without
  eval-gate pass + (first-of-class) operator approval.
- WI-5: **Q-ARCH-1 trajectory CLOSES** at 3 forbidden subscribers
  (A.1 + Supervisor + A.4 v0.2). No further pending additions
  in Phase 1.

Deferred to A.4 v0.3 (per the 2026-05-22 plan doc): N3 Autonomous
Curator (skill pruning); semantic-similarity novelty. Deferred
post-GA: Skills Hub marketplace (S2); cross-customer sharing.
Deferred post-SET-LOCAL-fix: multi-tenant production +
per-customer skill paths.

**Backwards-compatible with v0.1.** ``meta-harness run`` against
an empty ``skills/`` directory + zero novel-pattern runs produces
byte-identical output to v0.1 (modulo timestamps). Task 1's smoke
suite enforces this regression test (load-bearing).
"""

from __future__ import annotations

__version__ = "0.2.0"
