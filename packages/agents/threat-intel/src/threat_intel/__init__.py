"""Nexus Threat Intel Agent — D.8 / Agent #12 under ADR-007.

The second of the 7 unbuilt agents shipped under the 2026-05-20 Path-B-
breadth-first operating rule. Lifts platform coverage from siloed
detection to threat-context correlation — the first agent that consumes
external threat-intel feeds (NVD CVE + CISA KEV + MITRE ATT&CK) and
joins them against sibling-agent findings to elevate risk.

Scope (v0.1, locked 2026-05-21):

- 3 public, no-auth feeds (offline-mode JSON snapshots staged by
  the operator): NVD CVE 2.0, CISA KEV catalog, MITRE ATT&CK STIX 2.1.
- 3 sibling-workspace correlators (D.1 Vulnerability +
  D.4 Network Threat + D.3 Runtime Threat). Operator-pinned via
  per-workspace flags. Read-only.
- SemanticStore writes for IOC / CVE / TTP entities (single-tenant
  ``semantic_store=None`` opt-in default).
- OCSF v1.3 Detection Finding (``class_uid 2004``) re-exported from
  ``network_threat.schemas`` with ``finding_info.types[0] =
  "threat_intel"`` discriminator. Deterministic (no LLM in loop).

Six-stage pipeline:

  INGEST → ENRICH → CORRELATE → SCORE → SUMMARIZE → HANDOFF

Live HTTP polling, MISP / STIX-TAXII integration, abuse.ch /
VirusTotal feeds, active-campaign tracking, vertical feeds, and
multi-tenant production are deferred per the 2026-05-20 version-
roadmap (D.8 v0.2 through v0.5+).
"""

from __future__ import annotations

# D.8 Threat Intel v0.2 (single comprehensive directive cycle) — Level 1 → Level 2:
# continuous ingestion + live STIX/TAXII feeds + industry/tech-stack profiles +
# briefing skeleton + basic threat-actor matching. ADR-010 version-extension bump.
__version__ = "0.2.0"
