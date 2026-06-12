"""OCSF 2004 emission flow (curiosity v0.2 Task 4, Q1/WI-X5).

Maps an assembled ``CuriosityReport`` to its OCSF 2004 findings (one per claim) and renders the
``curiosity_findings.json`` workspace artifact. **Additive** — it rides alongside the unchanged
``hypotheses.md`` + ``probe_directives.json`` + the ``claims.>`` publish, so the existing stub-LLM
eval cases stay byte-identical (the eval validates the returned report, not the artifact set).
Pure + deterministic.
"""

from __future__ import annotations

import json
from typing import Any

from curiosity.ocsf.claim_translator import claim_to_ocsf
from curiosity.schemas import CuriosityReport


def emit_curiosity_findings(report: CuriosityReport) -> list[dict[str, Any]]:
    """One OCSF 2004 Detection Finding per published claim (empty report -> empty list)."""
    return [claim_to_ocsf(claim) for claim in report.claims]


def render_curiosity_findings_json(report: CuriosityReport) -> str:
    """Render the additive ``curiosity_findings.json`` workspace artifact."""
    return json.dumps(emit_curiosity_findings(report), indent=2, sort_keys=True)
