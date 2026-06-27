"""gitleaks output → redacted code-secrets handoff to DSPM — D.14 B-1 PR3 (ADR-015).

ADR-015 §Rationale-3: AppSec secrets-in-CODE route to **DSPM** for OCSF 2003
emission (the same unified emission point D.1's secrets-in-runtime use). This is
the D.14 producer side: parse gitleaks findings into REDACTED categorical metadata
and serialize ``code_secrets.json`` in the SAME shape D.1 writes
``runtime_secrets.json`` — so one DSPM ingester consumes both.

**Privacy boundary (hard):** the matched plaintext (gitleaks ``Secret`` / ``Match``)
is NEVER read or written — only rule id, target file, line span, and a policy
severity cross the boundary.
"""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from typing import Any

from appsec.tools.gitleaks_runner import GitleaksResult

#: AWS access key ID — the NON-secret credential identifier (CloudTrail logs it; the secret access
#: key is the sensitive half). Only this is extracted for the leaked-cred graph join (path #17).
_AKIA_RE = re.compile(r"AKIA[0-9A-Z]{16}")

#: Sibling-workspace artifact DSPM consumes (same shape as D.1 runtime_secrets.json).
CODE_SECRETS_OUTPUT = "code_secrets.json"

_SECRETS_SCHEMA_VERSION = "0.1"

#: Secrets-in-code are treated high-severity by policy (gitleaks emits no severity).
_CODE_SECRET_SEVERITY = "HIGH"  # noqa: S105  # severity label, not a credential


@dataclass(frozen=True)
class CodeSecretHit:
    """A redacted secret-in-code detection — categorical only, NO plaintext.

    Field-compatible with D.1's ``RuntimeSecretHit`` so DSPM ingests both shapes.
    """

    rule_id: str
    category: str
    severity: str
    title: str
    target: str
    start_line: int
    end_line: int


def _int(value: object) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return 0


def _to_hit(raw: dict[str, Any]) -> CodeSecretHit:
    return CodeSecretHit(
        rule_id=str(raw.get("RuleID", "")),
        category="code_secret",
        severity=_CODE_SECRET_SEVERITY,
        title=str(raw.get("Description", "")) or str(raw.get("RuleID", "")),
        target=str(raw.get("File", "")),
        start_line=_int(raw.get("StartLine", 0)),
        end_line=_int(raw.get("EndLine", 0)),
    )


def gitleaks_to_secret_hits(result: GitleaksResult) -> list[CodeSecretHit]:
    """Flatten + redact gitleaks findings (drops Secret/Match by construction)."""
    return [_to_hit(raw) for raw in result.payload if isinstance(raw, dict)]


def extract_leaked_key_ids(result: GitleaksResult) -> list[tuple[str, str]]:
    """``(file, AWS access key ID)`` for each gitleaks hit whose match contains an ``AKIA…``.

    NARROW, DELIBERATE exception to the redaction boundary (operator-approved, path #17): reads the
    gitleaks match to extract ONLY the access key ID — the non-secret identifier AWS logs in
    CloudTrail. The secret access key and ALL other match content are never retained. Feeds the
    leaked-cred -> cloud-identity graph join; the DSPM handoff (:class:`CodeSecretHit`) is untouched
    and stays fully redacted.
    """
    out: list[tuple[str, str]] = []
    for raw in result.payload:
        if not isinstance(raw, dict):
            continue
        match = _AKIA_RE.search(f"{raw.get('Secret', '')} {raw.get('Match', '')}")
        if match:
            out.append((str(raw.get("File", "")), match.group(0)))
    return out


def render_code_secrets_json(*, run_id: str, hits: Sequence[CodeSecretHit]) -> bytes:
    """Serialize the D.14→DSPM handoff (redacted metadata only)."""
    payload = {
        "schema_version": _SECRETS_SCHEMA_VERSION,
        "agent": "appsec",
        "run_id": run_id,
        "secrets": [asdict(h) for h in hits],
    }
    return json.dumps(payload, indent=2).encode("utf-8")


__all__ = [
    "CODE_SECRETS_OUTPUT",
    "CodeSecretHit",
    "gitleaks_to_secret_hits",
    "render_code_secrets_json",
]
