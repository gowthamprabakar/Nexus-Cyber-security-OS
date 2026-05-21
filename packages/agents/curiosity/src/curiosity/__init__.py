"""Nexus Curiosity Agent — D.12 / Agent #15 under ADR-007.

The fifth of the 7 unbuilt agents shipped under the 2026-05-20
Path-B-breadth-first operating rule. **The first generative agent in
the fleet** — emits hypotheses about what might be under-scanned, not
findings about what was scanned. The first publisher on the
``claims.>`` substrate introduced by ADR-012 (the 6th fabric bus).

Scope (v0.1, locked 2026-05-21):

- 3 emit directions per run:
    1. ``SemanticStore`` entity (``entity_type="hypothesis"``;
       persistent KG record).
    2. ``claims.>`` fabric publish on
       ``claims.tenant.<tid>.agent.curiosity`` (dogfoods ADR-012).
    3. ``hypotheses.md`` workspace markdown for operator review.
- 1 deterministic gap detector: **region-gap** (regions with ≥10
  assets but zero findings in 30d).
- Single LLM call per run; max 5 hypotheses emitted (budget cap).
- Single-tenant ``semantic_store=None`` + ``js_client=None`` opt-in
  defaults.
- Q6 invariant inherited from D.13: reuses
  ``synthesis.reviewer._scan_classifier_labels`` to guard against
  classifier-substring leakage in LLM-generated text.

Seven-stage pipeline:

  INGEST -> DETECT -> HYPOTHESIZE -> REVIEW -> PERSIST -> PUBLISH -> HANDOFF

Watch-items:

- WI-1: first ``claims.>`` publisher; payload schema pydantic-validated.
- WI-2: Q6 — no classifier-shaped substrings leak.
- WI-3: stub-LLM byte-equal determinism across reruns.
- WI-4: A.1 subscriber-ACL fence holds (ADR-012 substrate guard).

OCSF emit on `findings.>`, probe-directive consumer integration in
D.7/D.5/D.8, asset-type/time-window/severity-distribution gap
detectors, cross-tenant baseline drift, and multi-tenant production
are all deferred per the 2026-05-20 version-roadmap (D.12 v0.2
through v0.5+).
"""

from __future__ import annotations

__version__ = "0.1.0"
