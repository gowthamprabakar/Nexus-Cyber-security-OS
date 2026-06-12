"""OCSF emission flow (synthesis v0.2 Task 4, Q1/WI-Y5/WI-Y12).

The additive tail of the HANDOFF stage: alongside the unchanged ``narrative.md`` +
``executive_summary.md`` artifacts, the driver writes an OCSF 2004 Detection Finding as
``synthesis_finding.json``. Because the markdown artifacts are untouched, the 10 stub-LLM eval
cases stay byte-identical (WI-Y5); the OCSF output is a **new** workspace file (WI-Y12 additive).
"""

from __future__ import annotations

import json

from synthesis.ocsf.narrative_translator import translate_report_to_ocsf
from synthesis.schemas import SynthesisReport

#: The additive OCSF workspace output filename.
SYNTHESIS_FINDING_OUTPUT = "synthesis_finding.json"


def build_synthesis_finding_json(report: SynthesisReport) -> bytes:
    """JSON-encode the OCSF 2004 finding for the additive workspace output (deterministic)."""
    finding = translate_report_to_ocsf(report)
    return json.dumps(finding, sort_keys=True, indent=2).encode("utf-8")
