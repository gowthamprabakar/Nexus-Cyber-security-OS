"""GDPR framework alignment (data-security v0.2 Task 11, Q6).

Maps the unified data sources + their sensitivity to GDPR articles — personal-data inventory
(Art. 30), right-to-erasure scope (Art. 17), security of processing (Art. 32), and EU data
residency (Art. 5). Findings are metadata-only (source identifier + article + severity), per
the WI-S10 residency boundary.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum

from data_security.tools.data_source import DataSource


class GdprArticle(StrEnum):
    ART_5 = "art_5"  # principles incl. storage limitation / residency
    ART_17 = "art_17"  # right to erasure
    ART_30 = "art_30"  # records of processing
    ART_32 = "art_32"  # security of processing


@dataclass(frozen=True, slots=True)
class GdprFinding:
    article: GdprArticle
    source: str
    severity: str
    message: str


def is_eu_region(region: str) -> bool:
    """Cloud-agnostic EU-region check (AWS eu-*, GCP europe-*, Azure *europe*)."""
    r = region.lower()
    return r.startswith("eu") or "europe" in r


def map_gdpr(
    sources: Sequence[DataSource], *, sensitive_identifiers: set[str]
) -> tuple[GdprFinding, ...]:
    """Emit GDPR-article findings for sources holding personal data."""
    out: list[GdprFinding] = []
    for s in sources:
        if s.identifier not in sensitive_identifiers:
            continue
        out.append(
            GdprFinding(
                GdprArticle.ART_30,
                s.identifier,
                "medium",
                "personal data present — Article 30 records of processing",
            )
        )
        out.append(
            GdprFinding(
                GdprArticle.ART_17,
                s.identifier,
                "medium",
                "personal data in scope for right-to-erasure (Article 17)",
            )
        )
        if not s.is_encrypted:
            out.append(
                GdprFinding(
                    GdprArticle.ART_32,
                    s.identifier,
                    "high",
                    "personal data not encrypted at rest — Article 32",
                )
            )
        if is_eu_region(s.region):
            out.append(
                GdprFinding(
                    GdprArticle.ART_5,
                    s.identifier,
                    "low",
                    "personal data resident in an EU region — Article 5",
                )
            )
    return tuple(out)
