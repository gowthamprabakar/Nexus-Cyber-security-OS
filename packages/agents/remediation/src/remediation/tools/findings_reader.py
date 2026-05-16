"""`read_findings` — Stage 1 ingest: load detect-agent findings.json + reconstruct ManifestFindings.

Consumes the output of a D.6 Kubernetes Posture run (`findings.json`). The
file shape is `cloud_posture.schemas.FindingsReport.model_dump_json()` —
each entry in `findings[]` is a wrapped OCSF v1.3 dict (`class_uid 2003`)
that D.6 emitted via `build_finding`.

A.1 v0.1 only knows how to remediate **manifest-source** findings (the
ones produced by D.6's bundled 10-rule analyser, evidence kind = "manifest").
kube-bench and Polaris findings reference cluster controls / workload
audits whose remediation shape is materially different — they'll get their
own A.1 v0.2+ paths. For now the reader **filters to manifest-source**
findings and silently drops the rest.

The reader reconstructs `k8s_posture.tools.manifests.ManifestFinding`
instances from the OCSF payload — the same shape D.6's `normalize_manifest`
originally lifted. This is round-tripping the schema through the
filesystem, but it lets A.1 stay agent-output-format-agnostic.

**File-read errors** raise `FindingsReaderError`; **malformed individual
findings** are dropped (defensive; one bad finding shouldn't kill an
otherwise-actionable run).
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cloud_posture.schemas import Severity, severity_from_id
from k8s_posture.tools.manifests import ManifestFinding


class FindingsReaderError(RuntimeError):
    """The findings.json file could not be read or parsed."""


async def read_findings(*, path: Path | str) -> tuple[ManifestFinding, ...]:
    """Load detect-agent findings.json and reconstruct ManifestFinding records.

    Args:
        path: Path to a `findings.json` produced by D.6 (or another detect
            agent emitting the same wrapped-OCSF-2003 shape).

    Returns:
        Tuple of `ManifestFinding` records. Order preserved from the source
        file. Findings whose evidence is not `kind="manifest"` are dropped.

    Raises:
        FindingsReaderError: file missing / non-JSON / top-level shape wrong.
    """
    return await asyncio.to_thread(_read_sync, path=Path(path))


def _read_sync(*, path: Path) -> tuple[ManifestFinding, ...]:
    if not path.exists():
        raise FindingsReaderError(f"findings.json not found: {path}")
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise FindingsReaderError(f"failed to read findings.json {path}: {exc}") from exc
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise FindingsReaderError(f"findings.json is not valid JSON ({path}): {exc}") from exc

    if not isinstance(payload, dict):
        raise FindingsReaderError(
            f"findings.json top-level must be an object (FindingsReport); got {type(payload).__name__}"
        )
    findings_list = payload.get("findings")
    if not isinstance(findings_list, list):
        raise FindingsReaderError(
            "findings.json must contain a `findings: list[...]` field "
            f"(got {type(findings_list).__name__})"
        )

    out: list[ManifestFinding] = []
    for entry in findings_list:
        if not isinstance(entry, dict):
            continue
        finding = _reconstruct_manifest_finding(entry)
        if finding is not None:
            out.append(finding)
    return tuple(out)


def _reconstruct_manifest_finding(payload: dict[str, Any]) -> ManifestFinding | None:
    """Build a `ManifestFinding` from a wrapped OCSF 2003 payload.

    Returns None when the payload isn't a manifest-source finding (kube-bench,
    Polaris, or anything else with `evidence[*].kind != "manifest"`). Also
    returns None when required fields are missing — defensive, drop the bad
    finding and keep going.
    """
    evidences = payload.get("evidences")
    if not isinstance(evidences, list):
        return None

    manifest_evidence: dict[str, Any] | None = None
    for ev in evidences:
        if isinstance(ev, dict) and ev.get("kind") == "manifest":
            manifest_evidence = ev
            break
    if manifest_evidence is None:
        return None

    rule_id = manifest_evidence.get("rule_id")
    rule_title = manifest_evidence.get("rule_title")
    workload_kind = manifest_evidence.get("workload_kind")
    workload_name = manifest_evidence.get("workload_name")
    if not (isinstance(rule_id, str) and rule_id):
        return None
    if not (isinstance(rule_title, str) and rule_title):
        return None
    if not (isinstance(workload_kind, str) and workload_kind):
        return None
    if not (isinstance(workload_name, str) and workload_name):
        return None

    namespace = manifest_evidence.get("namespace") or "default"
    container_name = manifest_evidence.get("container_name", "")
    manifest_path = manifest_evidence.get("manifest_path") or "unknown"
    severity = _severity_from_payload(payload)
    detected_at = _detected_at_from_payload(payload)

    try:
        return ManifestFinding(
            rule_id=rule_id,
            rule_title=rule_title,
            severity=severity,
            workload_kind=workload_kind,
            workload_name=workload_name,
            namespace=str(namespace),
            container_name=str(container_name),
            manifest_path=str(manifest_path),
            detected_at=detected_at,
            unmapped=manifest_evidence.get("unmapped", {}) or {},
        )
    except Exception:
        # Defensive: a bad finding shouldn't kill the whole run.
        return None


def _severity_from_payload(payload: dict[str, Any]) -> Severity:
    """Pull severity from the OCSF wrapper; fall back to MEDIUM if missing."""
    sid = payload.get("severity_id")
    if isinstance(sid, int):
        try:
            return severity_from_id(sid)
        except ValueError:
            pass
    return Severity.MEDIUM


def _detected_at_from_payload(payload: dict[str, Any]) -> datetime:
    """Pull detected_at from the OCSF wrapper. Falls back to NOW(UTC) on parse failure."""
    time_dt = payload.get("time_dt")
    if isinstance(time_dt, str) and time_dt:
        try:
            return datetime.fromisoformat(time_dt.replace("Z", "+00:00"))
        except ValueError:
            pass
    time_ms = payload.get("time")
    if isinstance(time_ms, int):
        try:
            return datetime.fromtimestamp(time_ms / 1000, tz=UTC)
        except (OSError, ValueError):
            pass
    return datetime.now(UTC)


__all__ = [
    "FindingsReaderError",
    "read_findings",
]
