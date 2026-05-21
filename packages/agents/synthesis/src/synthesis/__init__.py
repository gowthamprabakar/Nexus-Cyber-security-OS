"""Nexus Synthesis Agent — D.13 / Agent #14 under ADR-007.

The fourth of the 7 unbuilt agents shipped under the 2026-05-20 Path-B-
breadth-first operating rule. Customer-facing narration: synthesizes
findings + investigations + compliance reports from sibling-agent
workspaces (D.7 Investigation + D.6 Compliance + F.3 Cloud Posture)
into human-readable LLM-narrated summaries.

**D.13 is the first agent that calls the LLM in its hot path.** Prior
agents (F.3 / D.1 / D.3 / D.4 / D.5 / D.6 / D.7 / D.8 / multi-cloud /
k8s / A.1) plumb ``llm_provider`` through their drivers but never
invoke it — narration is out-of-scope per F.3's NLAH ("customer-
facing narration belongs to the Synthesis Agent"). D.13 closes that
loop.

Scope (v0.1, locked 2026-05-21):

- 2 narrative artifacts: ``narrative.md`` (sectioned per-finding-
  class) + ``executive_summary.md`` (1-paragraph C-suite digest).
- 3 sibling sources: D.7 Investigation + D.6 Compliance + F.3
  Cloud Posture workspaces (read-only, operator-pinned via flags).
- 2 LLM calls per run (outline -> per-section narration). Both
  seeded ``temperature=0.0``; model pinned via
  ``envelope.model_pin``.
- 3 prompt templates loaded via ``importlib.resources``.
- Stub-LLM eval harness keeps the eval suite deterministic +
  offline; live-LLM smoke test gated by ``NEXUS_LIVE_LLM=1``.
- Single-tenant ``semantic_store=None`` opt-in default.
- **No OCSF emit in v0.1** (deferred to v0.2 pending a
  ``class_uid`` ADR).

Six-stage pipeline:

  INGEST -> ENRICH -> NARRATE -> REVIEW -> SUMMARIZE -> HANDOFF

Q6 invariant (carried through from D.5):

  Two-layer defence against classifier-substring leakage via LLM
  hallucination: (a) Stage 2 ENRICH carries structured fields only,
  never matched substrings; (b) Stage 4 REVIEW regex-guards the
  rendered narrative for classifier patterns and retries on
  violation.

OCSF emit, D.12 Curiosity hypothesis narration, periodic
re-narration on findings delta, F.7 fabric event on
``synthesis.produced``, and multi-tenant production are deferred
per the 2026-05-20 version-roadmap (D.13 v0.2 through v0.5+).
"""

from __future__ import annotations

__version__ = "0.1.0"
