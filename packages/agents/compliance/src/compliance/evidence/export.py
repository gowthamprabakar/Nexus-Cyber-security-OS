"""Per-framework evidence exports (compliance v0.2 Task 17).

The customer-handoff artifacts for an evidence bundle + its signed manifest. Two formats:

- **JSON** — the machine-readable bundle + manifest (complete).
- **Report text** — a deterministic, audit-ready Markdown report (per-control PASS/FAIL
  table + the signed manifest), **PDF-ready**: real PDF *binary* rendering needs a heavy
  dependency (reportlab/weasyprint) not in the workspace, so it is deferred — the text is
  shaped for a downstream PDF converter.
"""

from __future__ import annotations

import json

from compliance.evidence.bundle import EvidenceBundle
from compliance.evidence.chain import SignedManifest

_STATUS_LABEL = {"pass": "PASS", "fail": "FAIL", "not_evaluated": "N/E"}


def export_json(bundle: EvidenceBundle, manifest: SignedManifest) -> str:
    """The complete bundle + manifest as deterministic JSON."""
    return json.dumps(
        {"bundle": bundle.to_dict(), "manifest": manifest.to_dict()},
        sort_keys=True,
        indent=2,
    )


def export_report_text(bundle: EvidenceBundle, manifest: SignedManifest) -> str:
    """An audit-ready Markdown report (PDF-ready) for one framework."""
    passed = sum(1 for e in bundle.entries if e.status == "pass")
    failed = sum(1 for e in bundle.entries if e.status == "fail")
    lines = [
        f"# Compliance Evidence — {bundle.framework_id}",
        "",
        f"Generated: {bundle.generated_at}",
        f"Controls: {len(bundle.entries)} (PASS {passed} / FAIL {failed})",
        "",
        "| Control | Status | Sources | Entry hash |",
        "| --- | --- | --- | --- |",
    ]
    for e in bundle.entries:
        label = _STATUS_LABEL.get(e.status, e.status)
        sources = ", ".join(e.source_finding_ids) or "-"
        lines.append(f"| {e.control_id} | {label} | {sources} | {e.entry_hash[:12]}… |")
    lines += [
        "",
        "## Signed manifest",
        "",
        f"- chain head: `{manifest.chain_head}`",
        f"- signature: `{manifest.signature}`",
        f"- signed by: {manifest.signed_by}",
    ]
    return "\n".join(lines)
