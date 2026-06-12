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

# synthesis v0.2 (Cycle 13 — D.13, the FIRST LLM-heavy agent; the empty-registry LLM-first
# deviator: charter context + EMPTY ToolRegistry, LLM exclusively via charter.llm_adapter — no
# charter-gated tools, WI-Y9). Level 1 -> Level 2 INFRASTRUCTURE: OCSF 2004 Detection Finding
# emission (markdown narrative in the unmapped slot, markdown artifacts preserved alongside,
# Q1/WI-Y12), source scope 3 -> 12 (all closed-cycle agents, Q3), DeepSeek primary + Anthropic
# fallback (Q5), a live-LLM eval lane alongside the byte-identical stub harness (Q6/WI-Y5), and
# continuous-synthesis infrastructure. THREE new code-level invariants establishing the
# LLM-agent template (inherited by D.7/D.12/A.4): assert_categorical_only (WI-Y8/Q4 — no
# plaintext PII in narrative), assert_bounded_retry (WI-Y10/H5 — max 1 retry), and
# assert_findings_cited (WI-Y13 — the hallucination guard). Per Path 1: continuous mode is
# INFRASTRUCTURE here; production-loop wiring is the Phase C consolidated retrofit. ADR-010 bump.
__version__ = "0.2.0"
