"""Audit Agent schemas — OCSF v1.3 API Activity (class_uid 6003).

**OCSF class selection.** The F.6 plan named the class as `2007 Audit Activity`,
but OCSF v1.3 has no such id; the canonical OCSF class for action-records is
**6003 API Activity** under category 6 (Application Activity). Each audit
entry represents an action taken on the platform's internal API, which is
exactly what 6003 was designed for. The chain-specific fields
(`previous_hash`, `entry_hash`) ride in the OCSF `unmapped` slot — that's
the OCSF-blessed extension point for vendor-specific fields the schema
doesn't model directly.

Cross-agent OCSF inventory after F.6:

| Agent                | OCSF class_uid | Class name              |
| -------------------- | -------------- | ----------------------- |
| Cloud Posture (F.3)  | 2003           | Compliance Finding      |
| Vulnerability (D.1)  | 2002           | Vulnerability Finding   |
| Identity (D.2)       | 2004           | Detection Finding       |
| Runtime Threat (D.3) | 2004           | Detection Finding       |
| **Audit Agent (F.6)**| **6003**       | **API Activity**        |

F.6 is the first agent to emit a non-2000-series OCSF class. The fabric
layer (`shared.fabric.envelope`) already routes on `class_uid`, so this
choice doesn't add new plumbing.

Three pydantic models — all `frozen=True`, `extra="forbid"`, JSON-round-tripping:

- `AuditEvent` — one chain entry, schema-pinned (hash columns are 64-char
  hex, `tenant_id` is a 26-char ULID, `correlation_id` is ≤ 32 chars).
- `AuditQueryResult` — the wire shape every `AuditStore.query` returns;
  carries the events tuple plus derived `count_by_action` / `count_by_agent`
  views so callers don't recompute.
- `ChainIntegrityReport` — the verifier's output. Enforces the invariant
  that `valid=True` ↔ `broken_at_correlation_id is None`.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

# OCSF v1.3 constants — pinned at module scope so downstream consumers
# (the fabric layer, the Meta-Harness reader) can match on them.
OCSF_VERSION = "1.3.0"
OCSF_CATEGORY_UID = 6
OCSF_CATEGORY_NAME = "Application Activity"
OCSF_CLASS_UID = 6003
OCSF_CLASS_NAME = "API Activity"
# OCSF reserves activity_id 1-99 inside each class for the standard
# activities. 99 is the "Other" extension slot — F.6 uses it for
# "audit chain entry recorded".
OCSF_ACTIVITY_AUDIT_RECORD = 99

_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_ULID_LEN = 26
_CORRELATION_MAX = 32


class AuditEvent(BaseModel):
    """One entry in the audit chain.

    Wraps the same fields `charter.audit.AuditEntry` carries plus the
    `tenant_id` and `source` provenance fields F.6 needs for the
    query path.
    """

    model_config = ConfigDict(frozen=True, extra="forbid", str_strip_whitespace=False)

    tenant_id: str = Field(min_length=_ULID_LEN, max_length=_ULID_LEN)
    correlation_id: str = Field(min_length=1, max_length=_CORRELATION_MAX)
    agent_id: str = Field(min_length=1, max_length=64)
    action: str = Field(min_length=1, max_length=128)
    payload: dict[str, Any]
    previous_hash: str
    entry_hash: str
    emitted_at: datetime
    # `source` carries provenance like "jsonl:<path>" or "memory:<tenant>";
    # filesystem paths can be long. 512 matches the LTREE column ceiling
    # in `charter.memory.models._PortableLtree`.
    source: str = Field(min_length=1, max_length=512)

    @model_validator(mode="after")
    def _check_hashes(self) -> AuditEvent:
        for label, value in (
            ("previous_hash", self.previous_hash),
            ("entry_hash", self.entry_hash),
        ):
            if not _HEX64_RE.match(value):
                raise ValueError(
                    f"{label} must be 64-character lowercase hex (SHA-256 digest); got {value!r}"
                )
        return self

    def to_ocsf(self) -> dict[str, Any]:
        """Render as an OCSF v1.3 API Activity record."""
        return {
            "metadata": {"version": OCSF_VERSION, "product": {"name": "Nexus Audit Agent"}},
            "category_uid": OCSF_CATEGORY_UID,
            "category_name": OCSF_CATEGORY_NAME,
            "class_uid": OCSF_CLASS_UID,
            "class_name": OCSF_CLASS_NAME,
            "activity_id": OCSF_ACTIVITY_AUDIT_RECORD,
            "activity_name": "Audit chain entry recorded",
            "time": int(self.emitted_at.timestamp() * 1000),
            "actor": {"user": {"name": self.agent_id}},
            "api": {"operation": self.action},
            "unmapped": {
                "tenant_id": self.tenant_id,
                "correlation_id": self.correlation_id,
                "previous_hash": self.previous_hash,
                "entry_hash": self.entry_hash,
                "payload": self.payload,
                "source": self.source,
            },
        }


class AuditQueryResult(BaseModel):
    """The shape `AuditStore.query` returns and the CLI / Meta-Harness consume."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    total: int = Field(ge=0)
    events: tuple[AuditEvent, ...]

    @property
    def count_by_action(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for event in self.events:
            counts[event.action] = counts.get(event.action, 0) + 1
        return counts

    @property
    def count_by_agent(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for event in self.events:
            counts[event.agent_id] = counts.get(event.agent_id, 0) + 1
        return counts


class ChainIntegrityReport(BaseModel):
    """The output of `audit.chain.verify_audit_chain` (F.6 Task 8).

    Invariant: `valid` ↔ `broken_at_correlation_id is None`. A True
    result with a break location is a contradiction and rejected by
    the validator; a False result without a break location is equally
    invalid (a reader can't act on a break it has no pointer to).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    valid: bool
    entries_checked: int = Field(ge=0)
    broken_at_correlation_id: str | None = None
    broken_at_action: str | None = None

    @model_validator(mode="after")
    def _check_invariant(self) -> ChainIntegrityReport:
        if self.valid and self.broken_at_correlation_id is not None:
            raise ValueError("valid=True is incompatible with broken_at_correlation_id set")
        if not self.valid and self.broken_at_correlation_id is None:
            raise ValueError("valid=False requires broken_at_correlation_id to be set")
        return self


__all__ = [
    "OCSF_ACTIVITY_AUDIT_RECORD",
    "OCSF_CATEGORY_NAME",
    "OCSF_CATEGORY_UID",
    "OCSF_CLASS_NAME",
    "OCSF_CLASS_UID",
    "OCSF_VERSION",
    "AuditEvent",
    "AuditQueryResult",
    "ChainIntegrityReport",
]
