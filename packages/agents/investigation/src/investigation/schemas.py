"""Investigation Agent schemas — OCSF v1.3 Incident Finding (class_uid 2005).

**Q1 resolution (Task 2 verification).** The D.7 plan said "ship under
2004 with `types[0]="incident"` discriminator, verify at Task 4." On
verification: OCSF v1.3 *does* have `2005 Incident Finding` (added in
OCSF v1.2.0), purpose-built for exactly D.7's output shape. **Corrected
to class_uid 2005.** This mirrors F.6's 2007→6003 correction — the
plan's first guess gets refined on close OCSF reading.

Cross-agent OCSF inventory after D.7:

| Agent                | OCSF class_uid | Class name             |
| -------------------- | -------------- | ---------------------- |
| Cloud Posture (F.3)  | 2003           | Compliance Finding     |
| Vulnerability (D.1)  | 2002           | Vulnerability Finding  |
| Identity (D.2)       | 2004           | Detection Finding      |
| Runtime Threat (D.3) | 2004           | Detection Finding      |
| Audit Agent (F.6)    | 6003           | API Activity           |
| **Investigation (D.7)** | **2005**    | **Incident Finding**   |

Six pydantic models — all `frozen=True`, `extra="forbid"`, JSON-round-tripping:

- `Hypothesis` — one hypothesis with `evidence_refs` pointing at
  audit_event_id / finding_id values. Confidence ∈ [0, 1].
- `IocItem` — indicator of compromise; type ∈ {ipv4, ipv6, domain, url,
  sha256, sha1, md5, email, cve}. Value validated against the type's
  canonical regex.
- `MitreTechnique` — MITRE ATT&CK reference; technique_id format
  ``T<digits>``, optional sub-technique ``T<digits>.<3-digits>``
  (e.g. ``T1078.004``).
- `TimelineEvent` — one event in the reconstructed timeline.
- `Timeline` — auto-sorted-ascending tuple of `TimelineEvent`.
- `IncidentReport` — top-level wire shape with the OCSF envelope.
"""

from __future__ import annotations

import re
from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

OCSF_VERSION = "1.3.0"
OCSF_CATEGORY_UID = 2
OCSF_CATEGORY_NAME = "Findings"
OCSF_CLASS_UID = 2005
OCSF_CLASS_NAME = "Incident Finding"
# Activity 1 = "Create" per OCSF; D.7 always emits "Create" in v0.1
# (no Update / Close flows yet).
OCSF_ACTIVITY_INCIDENT_CREATE = 1

_ULID_LEN = 26


class IocType(StrEnum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    SHA256 = "sha256"
    SHA1 = "sha1"
    MD5 = "md5"
    EMAIL = "email"
    CVE = "cve"


_IOC_VALIDATORS: dict[IocType, re.Pattern[str]] = {
    IocType.IPV4: re.compile(
        r"^(?:25[0-5]|2[0-4]\d|[01]?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d?\d)){3}$"
    ),
    # Permissive IPv6; full RFC compliance not required for IOC matching.
    IocType.IPV6: re.compile(r"^[0-9a-fA-F:]+$"),
    IocType.DOMAIN: re.compile(
        r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    ),
    IocType.URL: re.compile(r"^https?://\S+$"),
    IocType.SHA256: re.compile(r"^[0-9a-f]{64}$"),
    IocType.SHA1: re.compile(r"^[0-9a-f]{40}$"),
    IocType.MD5: re.compile(r"^[0-9a-f]{32}$"),
    IocType.EMAIL: re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"),
    IocType.CVE: re.compile(r"^CVE-\d{4}-\d{4,}$"),
}


class Hypothesis(BaseModel):
    """A single forensic hypothesis with traceable evidence references."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    hypothesis_id: str = Field(min_length=1, max_length=32)
    statement: str = Field(min_length=1, max_length=2048)
    confidence: float = Field(ge=0.0, le=1.0)
    # At least one evidence ref. Format: "<kind>:<id>" — kinds:
    # `audit_event`, `finding`, `entity`. Validation of resolvability
    # happens at the synthesizer layer (Task 11), not here.
    evidence_refs: tuple[str, ...] = Field(min_length=1)


class IocItem(BaseModel):
    """An indicator of compromise — type-validated value."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    type: IocType
    value: str = Field(min_length=1, max_length=2048)

    @model_validator(mode="after")
    def _check_value_shape(self) -> IocItem:
        pattern = _IOC_VALIDATORS[self.type]
        if not pattern.match(self.value):
            raise ValueError(
                f"IocItem value {self.value!r} does not match canonical shape for type {self.type.value!r}"
            )
        return self


_TECHNIQUE_RE = re.compile(r"^T\d{4,}$")
_SUB_TECHNIQUE_RE = re.compile(r"^T\d{4,}\.\d{3}$")
_TACTIC_RE = re.compile(r"^TA\d{4}$")


class MitreTechnique(BaseModel):
    """MITRE ATT&CK technique reference, optional sub-technique."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    technique_id: str
    technique_name: str = Field(min_length=1, max_length=128)
    tactic_id: str
    tactic_name: str = Field(min_length=1, max_length=128)
    sub_technique_id: str | None = None
    sub_technique_name: str | None = None

    @model_validator(mode="after")
    def _check_shapes(self) -> MitreTechnique:
        if not _TECHNIQUE_RE.match(self.technique_id):
            raise ValueError(f"technique_id {self.technique_id!r} must match /T\\d+/ (e.g. T1078)")
        if not _TACTIC_RE.match(self.tactic_id):
            raise ValueError(f"tactic_id {self.tactic_id!r} must match /TA\\d{{4}}/ (e.g. TA0001)")
        if self.sub_technique_id is not None and not _SUB_TECHNIQUE_RE.match(self.sub_technique_id):
            raise ValueError(
                f"sub_technique_id {self.sub_technique_id!r} must match "
                "/T\\d+\\.\\d{3}/ (e.g. T1078.004)"
            )
        return self


class TimelineEvent(BaseModel):
    """One event in the reconstructed incident timeline."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    emitted_at: datetime
    source: str = Field(min_length=1, max_length=64)
    actor: str = Field(min_length=1, max_length=64)
    action: str = Field(min_length=1, max_length=128)
    evidence_ref: str = Field(min_length=1, max_length=256)
    description: str = Field(min_length=1, max_length=2048)


class Timeline(BaseModel):
    """Ordered tuple of `TimelineEvent` — sorted ascending by `emitted_at`.

    Construction sorts the input tuple deterministically so callers
    don't have to pre-sort, and the wire shape is stable across
    different ingest orderings.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    events: tuple[TimelineEvent, ...]

    @model_validator(mode="after")
    def _sort_events(self) -> Timeline:
        sorted_events = tuple(sorted(self.events, key=lambda e: e.emitted_at))
        # Bypass frozen=True for the post-init reordering — pydantic
        # supports this via __dict__ on the model instance.
        object.__setattr__(self, "events", sorted_events)
        return self


class IncidentReport(BaseModel):
    """The top-level wire shape D.7 emits — one incident, one report."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    incident_id: str = Field(min_length=1, max_length=64)
    tenant_id: str = Field(min_length=_ULID_LEN, max_length=_ULID_LEN)
    correlation_id: str = Field(min_length=1, max_length=32)
    timeline: Timeline
    hypotheses: tuple[Hypothesis, ...]
    iocs: tuple[IocItem, ...]
    mitre_techniques: tuple[MitreTechnique, ...]
    containment_summary: str = Field(max_length=8192)
    confidence: float = Field(ge=0.0, le=1.0)
    emitted_at: datetime

    def count_hypotheses_by_confidence_bucket(self) -> dict[str, int]:
        """Bucket every hypothesis into high / medium / low for the report."""
        counts = {"high": 0, "medium": 0, "low": 0}
        for h in self.hypotheses:
            if h.confidence >= 0.7:
                counts["high"] += 1
            elif h.confidence >= 0.4:
                counts["medium"] += 1
            else:
                counts["low"] += 1
        return counts

    def to_ocsf(self) -> dict[str, Any]:
        """Render as an OCSF v1.3 Incident Finding (class_uid 2005)."""
        return {
            "metadata": {
                "version": OCSF_VERSION,
                "product": {"name": "Nexus Investigation Agent"},
            },
            "category_uid": OCSF_CATEGORY_UID,
            "category_name": OCSF_CATEGORY_NAME,
            "class_uid": OCSF_CLASS_UID,
            "class_name": OCSF_CLASS_NAME,
            "activity_id": OCSF_ACTIVITY_INCIDENT_CREATE,
            "activity_name": "Create",
            "time": int(self.emitted_at.timestamp() * 1000),
            "finding_info": {
                "uid": self.incident_id,
                "title": f"Incident {self.incident_id}",
                "confidence_score": int(self.confidence * 100),
            },
            "unmapped": {
                "tenant_id": self.tenant_id,
                "correlation_id": self.correlation_id,
                "timeline": [e.model_dump(mode="json") for e in self.timeline.events],
                "hypotheses": [h.model_dump(mode="json") for h in self.hypotheses],
                "iocs": [i.model_dump(mode="json") for i in self.iocs],
                "mitre_techniques": [m.model_dump(mode="json") for m in self.mitre_techniques],
                "containment_summary": self.containment_summary,
            },
        }


__all__ = [
    "OCSF_ACTIVITY_INCIDENT_CREATE",
    "OCSF_CATEGORY_NAME",
    "OCSF_CATEGORY_UID",
    "OCSF_CLASS_NAME",
    "OCSF_CLASS_UID",
    "OCSF_VERSION",
    "Hypothesis",
    "IncidentReport",
    "IocItem",
    "IocType",
    "MitreTechnique",
    "Timeline",
    "TimelineEvent",
]
