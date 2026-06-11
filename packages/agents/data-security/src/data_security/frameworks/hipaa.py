"""HIPAA Security Rule alignment (data-security v0.2 Task 13, Q6).

Maps PHI-bearing data sources to HIPAA Security Rule sections — encryption at rest
(§164.312(a)(2)(iv)), access control (§164.312(a)(1)), access logging / information-system
activity review (§164.308(a)(1)(ii)(D)), and audit controls (§164.312(b)). Findings are
metadata-only (source identifier + section + severity).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum

from data_security.tools.data_source import DataSource


class HipaaSection(StrEnum):
    ACCESS_CONTROL = "164.312(a)(1)"
    ENCRYPTION = "164.312(a)(2)(iv)"
    AUDIT_CONTROLS = "164.312(b)"
    ACCESS_LOGGING = "164.308(a)(1)(ii)(D)"


@dataclass(frozen=True, slots=True)
class HipaaFinding:
    section: HipaaSection
    source: str
    severity: str
    message: str


def map_hipaa(
    sources: Sequence[DataSource], *, phi_bearing_identifiers: set[str]
) -> tuple[HipaaFinding, ...]:
    """Emit HIPAA Security Rule findings for sources holding PHI."""
    out: list[HipaaFinding] = []
    for s in sources:
        if s.identifier not in phi_bearing_identifiers:
            continue
        if s.is_public:
            out.append(
                HipaaFinding(
                    HipaaSection.ACCESS_CONTROL,
                    s.identifier,
                    "critical",
                    "PHI publicly accessible — HIPAA §164.312(a)(1)",
                )
            )
        if not s.is_encrypted:
            out.append(
                HipaaFinding(
                    HipaaSection.ENCRYPTION,
                    s.identifier,
                    "critical",
                    "PHI not encrypted at rest — HIPAA §164.312(a)(2)(iv)",
                )
            )
        out.append(
            HipaaFinding(
                HipaaSection.AUDIT_CONTROLS,
                s.identifier,
                "medium",
                "verify audit controls on PHI store — HIPAA §164.312(b)",
            )
        )
        out.append(
            HipaaFinding(
                HipaaSection.ACCESS_LOGGING,
                s.identifier,
                "medium",
                "verify access logging on PHI store — HIPAA §164.308(a)(1)(ii)(D)",
            )
        )
    return tuple(out)
