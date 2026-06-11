"""Sensitive-data + over-permissive-access severity uplift (data-security v0.2 Task 15, Q5).

When a data source is **both** sensitive (carries PII/PHI/PAN) **and** flagged by D.2 Identity
for over-permissive access, the combined risk is greater than either alone — so its severity
is elevated one rung. This is **emit-only** (WI-S11 / Q5 invariant): data-security never
modifies IAM; A.1 Remediation owns enforcement. There is deliberately no remediation surface
in this module.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

#: Canonical severity ladder (low -> critical).
_LADDER = ("low", "medium", "high", "critical")

_REASON = "sensitive data + over-permissive access (D.2 Identity)"


def escalate(severity: str) -> str:
    """Raise a severity one rung; ``critical`` is the ceiling, unknowns start at ``low``."""
    try:
        idx = _LADDER.index(severity)
    except ValueError:
        idx = 0
    return _LADDER[min(idx + 1, len(_LADDER) - 1)]


@dataclass(frozen=True, slots=True)
class AccessRiskFinding:
    source: str
    base_severity: str
    elevated_severity: str
    reason: str


def elevate_sensitive_with_access(
    *,
    sensitive_identifiers: set[str],
    access_flagged_identifiers: set[str],
    base_severities: Mapping[str, str] | None = None,
) -> tuple[AccessRiskFinding, ...]:
    """For each source that is **both** sensitive and access-flagged, emit an elevated-severity
    finding. Sources in only one set are not elevated."""
    base = base_severities or {}
    out: list[AccessRiskFinding] = []
    for ident in sorted(sensitive_identifiers & access_flagged_identifiers):
        base_sev = base.get(ident, "high")
        out.append(
            AccessRiskFinding(
                source=ident,
                base_severity=base_sev,
                elevated_severity=escalate(base_sev),
                reason=_REASON,
            )
        )
    return tuple(out)
