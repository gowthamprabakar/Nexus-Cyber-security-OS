"""IOC / CVE / TTP entity models for the D.8 Threat Intel SemanticStore writer.

Per Q3 of the D.8 v0.1 plan, the agent ships three pydantic entity
models that mirror the three feeds' core records:

- ``IocEntity`` — entity_type=``"ioc"``; properties shape compatible
  with the IocType enum from ``schemas.py``.
- ``CveEntity`` — entity_type=``"cve"``; KEV-listed flag included.
- ``TechniqueEntity`` — entity_type=``"ttp"``; MITRE ATT&CK technique.

These are **logical-layer** models — used by the ``kg_writer`` to
serialise into the ``SemanticStore.entities`` / ``relationships``
substrate. The substrate's three-column composite key is
``(tenant_id, entity_type, external_id)`` per the F.3 KG-loop pattern;
``external_id`` is computed per-model below.

Q6 reminder: none of these entities carry classifier-matched substrings
or any PII. They carry feed-derived metadata only (CVE IDs, IOC values
from public threat feeds, ATT&CK technique IDs).
"""

from __future__ import annotations

from datetime import date, datetime
from typing import Any

from pydantic import BaseModel, Field

from threat_intel.schemas import IocType


class IocEntity(BaseModel):
    """One IOC entity to persist in SemanticStore (entity_type=``"ioc"``).

    The external_id encodes both the IOC kind and value to allow distinct
    IPv4/domain/url/file-hash IOCs sharing similar strings to coexist
    (e.g., ``ip:1.2.3.4`` vs a hypothetical ``url:1.2.3.4``).
    """

    ioc_type: IocType
    value: str = Field(min_length=1)
    first_seen: datetime
    last_seen: datetime
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    source_feed: str = Field(min_length=1)

    @property
    def external_id(self) -> str:
        return f"{self.ioc_type.value}:{self.value}"

    def properties(self) -> dict[str, Any]:
        """Serialise to the SemanticStore properties dict."""
        return {
            "ioc_type": self.ioc_type.value,
            "value": self.value,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "confidence": self.confidence,
            "source_feed": self.source_feed,
        }


class CveEntity(BaseModel):
    """One CVE entity to persist in SemanticStore (entity_type=``"cve"``).

    Merges NVD + KEV signal: ``cvss_v3_score`` / ``cvss_v3_severity``
    come from NVD; ``kev_listed`` / ``kev_added_date`` come from CISA
    KEV. ``epss_score`` is reserved for D.8 v0.2 (EPSS feed not in
    v0.1 scope).
    """

    cve_id: str = Field(min_length=10, max_length=20)
    cvss_v3_score: float | None = Field(default=None, ge=0.0, le=10.0)
    cvss_v3_severity: str | None = None
    epss_score: float | None = Field(default=None, ge=0.0, le=1.0)
    kev_listed: bool = False
    kev_added_date: date | None = None
    description: str = ""
    affected_products: list[str] = Field(default_factory=list)

    @property
    def external_id(self) -> str:
        return self.cve_id

    def properties(self) -> dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "cvss_v3_score": self.cvss_v3_score,
            "cvss_v3_severity": self.cvss_v3_severity,
            "epss_score": self.epss_score,
            "kev_listed": self.kev_listed,
            "kev_added_date": (
                self.kev_added_date.isoformat() if self.kev_added_date is not None else None
            ),
            "description": self.description,
            "affected_products": list(self.affected_products),
        }


class TechniqueEntity(BaseModel):
    """One ATT&CK technique entity to persist in SemanticStore (entity_type=``"ttp"``).

    Mirrors ``TechniqueRecord`` from ``tools/mitre_attack.py`` with one
    addition: ``external_id`` uses the technique ID directly (which
    matches the substrate's three-column key shape).
    """

    technique_id: str = Field(min_length=4, max_length=10)
    name: str = Field(min_length=1)
    description: str = ""
    tactics: list[str] = Field(default_factory=list)
    platforms: list[str] = Field(default_factory=list)
    is_subtechnique: bool = False
    url: str = ""

    @property
    def external_id(self) -> str:
        return self.technique_id

    def properties(self) -> dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "name": self.name,
            "description": self.description,
            "tactics": list(self.tactics),
            "platforms": list(self.platforms),
            "is_subtechnique": self.is_subtechnique,
            "url": self.url,
        }


__all__ = ["CveEntity", "IocEntity", "TechniqueEntity"]
