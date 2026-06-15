"""Secrets-in-runtime ingestion → OCSF 2003 — A-2.4 (ADR-015), DSPM side.

ADR-015 splits ownership: **D.1 SCANS** (Trivy's secret scanner; D.1 writes a
REDACTED ``runtime_secrets.json`` to its workspace), **DSPM EMITS** the OCSF 2003
Data Security Finding. This module is the emit side: it reads D.1's sibling-
workspace artifact and builds findings with the ``SECRET_EXPOSED_IN_RUNTIME``
discriminator.

**Privacy.** D.1 already redacted the plaintext at the source (only categorical
metadata — rule id, category, severity, title, target file, line span — is in the
artifact). This module consumes that metadata as-is; no plaintext can appear.

**Cross-agent timing.** DSPM reads AFTER D.1's scan has written the file within a
tenant scan window. A missing/empty artifact yields zero findings (no error).
"""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path
from typing import Any

from shared.fabric.envelope import NexusEnvelope

from data_security.schemas import (
    AffectedResource,
    CloudPostureFinding,
    DataSecurityFindingType,
    Severity,
    build_finding,
    source_token,
)

#: The artifact D.1 writes (must match vulnerability.secrets.RUNTIME_SECRETS_OUTPUT).
RUNTIME_SECRETS_FILENAME = "runtime_secrets.json"

_SLUG_RE = re.compile(r"[^a-z0-9]+")

_SEVERITY_MAP: dict[str, Severity] = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "UNKNOWN": Severity.MEDIUM,
}


def read_runtime_secrets(vulnerability_workspace: Path | str) -> list[dict[str, Any]]:
    """Read D.1's redacted ``runtime_secrets.json`` from a sibling workspace.

    Returns the list of secret-hit dicts, or ``[]`` when the artifact is absent
    or carries no secrets (the no-secret / no-D.1-run case is routine, not error).
    """
    path = Path(vulnerability_workspace) / RUNTIME_SECRETS_FILENAME
    if not path.exists():
        return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []
    secrets = payload.get("secrets", [])
    return list(secrets) if isinstance(secrets, list) else []


def _to_severity(raw: str) -> Severity:
    return _SEVERITY_MAP.get(raw.upper(), Severity.MEDIUM)


def _build_finding_id(target: str, sequence: int) -> str:
    src = source_token(DataSecurityFindingType.SECRET_EXPOSED_IN_RUNTIME)
    context = _SLUG_RE.sub("-", target.lower()).strip("-") or "secret"
    context = context[:40]
    return f"CSPM-RUNTIME-{src}-{sequence:03d}-{context}"


def secrets_to_findings(
    secrets: Sequence[dict[str, Any]],
    *,
    envelope: NexusEnvelope,
    detected_at: datetime,
) -> list[CloudPostureFinding]:
    """Map redacted secret-hit dicts to OCSF 2003 SECRET_EXPOSED_IN_RUNTIME findings."""
    findings: list[CloudPostureFinding] = []
    for sequence, secret in enumerate(secrets):
        rule_id = str(secret.get("rule_id", "")) or "unknown"
        target = str(secret.get("target", "")) or "unknown"
        title_txt = str(secret.get("title", "")) or rule_id
        category = str(secret.get("category", ""))
        start_line = secret.get("start_line", 0)

        affected = AffectedResource(
            cloud="runtime",
            account_id=envelope.tenant_id,
            region="local",
            resource_type="file",
            resource_id=target,
            arn=f"runtime-secret://{target}",
        )
        evidence: dict[str, Any] = {
            "rule": "secret_exposed_in_runtime",
            "source_finding_type": DataSecurityFindingType.SECRET_EXPOSED_IN_RUNTIME.value,
            "secret_rule_id": rule_id,
            "secret_category": category,
            "target": target,
            "start_line": start_line,
            "source_agent": "vulnerability",
        }
        findings.append(
            build_finding(
                finding_id=_build_finding_id(target, sequence),
                rule_id="secret_exposed_in_runtime",
                severity=_to_severity(str(secret.get("severity", ""))),
                title=f"Secret exposed in runtime: {title_txt}",
                description=(
                    f"D.1 detected a secret ({rule_id}) in {target} "
                    f"line {start_line}. Owned per ADR-015: D.1 scans, DSPM emits."
                ),
                affected=[affected],
                detected_at=detected_at,
                envelope=envelope,
                evidence=evidence,
            )
        )
    return findings


def ingest_runtime_secret_findings(
    vulnerability_workspace: Path | str | None,
    *,
    envelope: NexusEnvelope,
    detected_at: datetime,
) -> list[CloudPostureFinding]:
    """Read + map D.1's secrets handoff to OCSF 2003 findings (``[]`` if unset)."""
    if vulnerability_workspace is None:
        return []
    secrets = read_runtime_secrets(vulnerability_workspace)
    return secrets_to_findings(secrets, envelope=envelope, detected_at=detected_at)


__all__ = [
    "RUNTIME_SECRETS_FILENAME",
    "ingest_runtime_secret_findings",
    "read_runtime_secrets",
    "secrets_to_findings",
]
