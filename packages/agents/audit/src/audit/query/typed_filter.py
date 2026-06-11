"""Broad typed audit query filter (audit v0.2 Task 9, Q3).

A strongly-typed (Pydantic) filter over the five v0.2 query dimensions — time-range
(``since``/``until``), ``tenant_id``, ``action``, ``agent_id``, and ``status`` — plus a
``parse_filter`` that validates a raw dict into the model. ``status`` is matched against the
event ``payload["status"]`` at execution time (Task 10) since it is not a first-class
``AuditEvent`` field. A SQL-like query DSL is explicitly deferred to v0.3.

Distinct from the existing ``AuditQueryArgs`` (NL-translation path): this is the broad typed
filter the query engine consumes, left as a separate model so the NL path stays byte-identical.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

_ULID_LEN = 26


class TypedAuditFilter(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    tenant_id: str = Field(min_length=_ULID_LEN, max_length=_ULID_LEN)
    since: datetime | None = None
    until: datetime | None = None
    action: str | None = None
    agent_id: str | None = None
    status: str | None = None

    @model_validator(mode="after")
    def _check_range(self) -> TypedAuditFilter:
        if self.since is not None and self.until is not None and self.since > self.until:
            raise ValueError("since must be <= until")
        return self

    def is_cross_tenant(self) -> bool:
        """A single-tenant filter is never cross-tenant; the multi-tenant admin gate
        (Task 14) builds on this seam."""
        return False


def parse_filter(raw: Mapping[str, Any]) -> TypedAuditFilter:
    """Parse + validate a raw filter mapping into a ``TypedAuditFilter`` (Pydantic-validated)."""
    return TypedAuditFilter.model_validate(dict(raw))
