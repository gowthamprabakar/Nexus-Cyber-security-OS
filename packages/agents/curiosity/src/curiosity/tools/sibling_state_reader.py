"""Stage 1 INGEST — async aggregate-state queries over SemanticStore.

Reads the per-region asset + finding aggregate state that Stage 2's
deterministic coverage-gap detector consumes. Forgiving on every
failure mode: when ``semantic_store=None`` (Q5 single-tenant opt-in
default), returns an empty ``SiblingState``; when entities of a
given type don't exist, treats them as zero-rows rather than raising.

**Per-region entity schema (v0.1 convention).**

D.12 v0.1 reads three entity types written by upstream agents
(F.3 Cloud Posture for the region inventory; D.5/D.6/F.3 for the
finding aggregates). The schema is not yet standardised across
agents — v0.2 will pick it up alongside the asset-type / time-window
gap detectors.

- ``aws_account_region``: one entity per region the customer has
  assets in. Properties:
    - ``asset_count: int`` — current asset inventory.
- ``finding_aggregate``: one entity per (region, source-agent)
  pair that has surfaced findings in the recent past. Properties:
    - ``region: str`` — denormalized for the v0.1 query path.
    - ``days_since_last_finding: int`` — caller-computed delta
      against the run's scan window.
    - ``last_finding_severity: str | None``.
    - ``source_agent: str`` — F.3 / D.5 / D.6 / D.8 origin label.

Entities without these property keys are projected into
``RegionState`` with default values (asset_count=0; days_since=-1
meaning "no findings observed"). Future v0.2 schema lockdown will
make these properties required.

**Q5 single-tenant.** The reader strictly scopes queries to the
caller-supplied ``customer_id``; cross-tenant aggregation is
explicitly forbidden per sketch §4. Missing/empty ``customer_id``
raises ``ValueError`` at the API boundary so the violation surfaces
before any DB call.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from charter.memory.semantic import SemanticStore

_LOG = logging.getLogger(__name__)

_SENTINEL_NO_FINDINGS = -1


@dataclass(frozen=True, slots=True)
class RegionState:
    """Per-region aggregate snapshot used by Stage 2 DETECT."""

    region: str
    asset_count: int
    days_since_last_finding: int
    last_finding_severity: str | None


@dataclass(frozen=True, slots=True)
class SiblingState:
    """The Stage 1 INGEST output flowing to Stage 2 DETECT."""

    regions: tuple[RegionState, ...] = field(default_factory=tuple)
    total_assets: int = 0
    total_findings_30d: int = 0

    @property
    def any_data_present(self) -> bool:
        """True iff at least one region carried data in this snapshot."""
        return bool(self.regions) or self.total_assets > 0


async def read_sibling_state(
    semantic_store: SemanticStore | None,
    *,
    customer_id: str,
    window_days: int = 30,
) -> SiblingState:
    """Read aggregate sibling-agent state from the SemanticStore.

    Returns an empty ``SiblingState`` (with a one-line log) when
    ``semantic_store`` is ``None`` — this is the Q5 single-tenant
    default; the Task 10 driver wires a real store when one is
    available.

    Raises ``ValueError`` if ``customer_id`` is empty (privacy
    posture — never run without a tenant scope).
    """
    if not customer_id:
        raise ValueError("customer_id must be a non-empty string; cross-tenant reads forbidden")

    if semantic_store is None:
        _LOG.info(
            "sibling_state_reader: semantic_store=None; emitting empty SiblingState "
            "(customer_id=%s, window_days=%d)",
            customer_id,
            window_days,
        )
        return SiblingState()

    # Two reads — region inventory + finding aggregates. asyncio.gather
    # would let them race but the SQLAlchemy session model prefers
    # sequential reads on a single session_factory.
    region_rows = await semantic_store.list_entities_by_type(
        tenant_id=customer_id,
        entity_type="aws_account_region",
    )
    finding_agg_rows = await semantic_store.list_entities_by_type(
        tenant_id=customer_id,
        entity_type="finding_aggregate",
    )

    # Index finding-aggregates by region for the projection. v0.1
    # picks the AGGREGATE WITH THE SMALLEST days_since_last_finding
    # per region — the freshest sample of activity. Future v0.2 may
    # surface per-source-agent rows separately.
    fresh_by_region: dict[str, tuple[int, str | None]] = {}
    total_findings_30d = 0
    for row in finding_agg_rows:
        props = row.properties
        region = _safe_str(props.get("region"))
        if not region:
            continue
        days = _safe_int(props.get("days_since_last_finding"))
        severity = _safe_optional_str(props.get("last_finding_severity"))
        if days < window_days:
            total_findings_30d += 1
        current = fresh_by_region.get(region)
        if current is None or days < current[0]:
            fresh_by_region[region] = (days, severity)

    regions: list[RegionState] = []
    total_assets = 0
    for row in region_rows:
        region_name = row.external_id or _safe_str(row.properties.get("region"))
        if not region_name:
            continue
        asset_count = _safe_int(row.properties.get("asset_count"))
        total_assets += asset_count
        days, severity = fresh_by_region.get(region_name, (_SENTINEL_NO_FINDINGS, None))
        regions.append(
            RegionState(
                region=region_name,
                asset_count=asset_count,
                days_since_last_finding=days,
                last_finding_severity=severity,
            )
        )

    return SiblingState(
        regions=tuple(regions),
        total_assets=total_assets,
        total_findings_30d=total_findings_30d,
    )


# ---------------------------------------------------------------------------
# Property coercion helpers — forgiving on malformed property values
# ---------------------------------------------------------------------------


def _safe_str(value: object) -> str:
    return value if isinstance(value, str) else ""


def _safe_optional_str(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _safe_int(value: object) -> int:
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return value
    return 0


__all__ = [
    "RegionState",
    "SiblingState",
    "read_sibling_state",
]
