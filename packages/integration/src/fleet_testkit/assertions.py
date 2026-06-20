"""Fleet-test L1 assertions — OCSF validity, kg-entity writes, tenant isolation, audit chain.

Every helper raises ``AssertionError`` with a message that names the broken invariant
(swiss-bar #8). No helper silently no-ops; callers document any assertion they omit for a
tier (swiss-bar #5/#12).
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Any

from charter.audit import GENESIS_HASH, AuditEntry, _hash_entry
from charter.memory.graph_types import NodeCategory
from charter.memory.semantic import SemanticStore
from shared.fabric.envelope import unwrap_ocsf


def assert_ocsf_valid(payload: dict[str, Any], *, class_uid: int) -> None:
    """Unwrap the ``NexusEnvelope`` and assert OCSF structural invariants (L1 strictness).

    Validates (class-agnostic, so it holds for 2002/2003/2004/2005/2007/6003): a well-formed
    envelope (via ``unwrap_ocsf``), the expected ``class_uid``, a ``finding_info`` dict with a
    non-empty ``uid``, and a non-empty tenant on the envelope. ``finding_info.types`` is the
    Detection-class (2004) discriminator and not populated on every class, so it is checked
    only when present (must be a non-empty list). The per-agent harness asserts the specific
    ``types[0]`` value itself where it applies. (L1-Q4: structural — no full OCSF JSON-schema
    validator exists in-repo; a stricter validator is v0.5 hardening.)
    """
    event, envelope = unwrap_ocsf(payload)
    actual = event.get("class_uid")
    assert actual == class_uid, f"OCSF class_uid: expected {class_uid}, got {actual!r}"
    finding_info = event.get("finding_info")
    assert isinstance(finding_info, dict), f"OCSF finding_info must be a dict, got {finding_info!r}"
    assert finding_info.get("uid"), f"OCSF finding_info.uid must be non-empty, got {finding_info!r}"
    if "types" in finding_info and finding_info["types"] is not None:
        types = finding_info["types"]
        assert isinstance(types, list) and types, (
            f"OCSF finding_info.types, when present, must be a non-empty list, got {types!r}"
        )
    assert envelope.tenant_id, "NexusEnvelope.tenant_id must be non-empty"


async def assert_entity_written(
    store: SemanticStore, *, tenant_id: str, category: NodeCategory
) -> None:
    """Assert the agent's kg_writer wrote >=1 entity of ``category`` for ``tenant_id``."""
    rows = await store.list_entities_by_type(tenant_id=tenant_id, entity_type=category.value)
    assert rows, (
        f"expected >=1 {category.value!r} entity for tenant {tenant_id!r}, found none "
        f"(kg_writer did not write the expected ADR-018 node type)"
    )
    # list_entities_by_type is tenant-scoped, so every row already carries tenant_id; this
    # guards against an accessor regression that would weaken the tenant filter.
    for row in rows:
        assert row.tenant_id == tenant_id, (
            f"entity {row.entity_id} carries tenant {row.tenant_id!r} != {tenant_id!r}"
        )


async def assert_no_entities(
    store: SemanticStore, *, tenant_id: str, categories: Sequence[NodeCategory]
) -> None:
    """Assert NO entities of the given categories exist (the inert-offline / no-store path)."""
    for category in categories:
        rows = await store.list_entities_by_type(tenant_id=tenant_id, entity_type=category.value)
        assert not rows, (
            f"expected no {category.value!r} entities for tenant {tenant_id!r}, found {len(rows)} "
            f"(a no-store / inert run must not write to the graph)"
        )


async def assert_two_tenant_disjoint(
    store: SemanticStore,
    *,
    tenant_a: str,
    tenant_b: str,
    categories: Sequence[NodeCategory],
) -> None:
    """Assert two tenants' subgraphs are disjoint (no cross-tenant entity leak).

    Both tenants must have written something (else the check is vacuous), and their
    entity-id sets across ``categories`` must not intersect.
    """

    async def _ids(tenant_id: str) -> set[str]:
        out: set[str] = set()
        for category in categories:
            rows = await store.list_entities_by_type(
                tenant_id=tenant_id, entity_type=category.value
            )
            out.update(row.entity_id for row in rows)
        return out

    ids_a = await _ids(tenant_a)
    ids_b = await _ids(tenant_b)
    assert ids_a, f"tenant {tenant_a!r} wrote no entities — disjointness check is vacuous"
    assert ids_b, f"tenant {tenant_b!r} wrote no entities — disjointness check is vacuous"
    overlap = ids_a & ids_b
    assert not overlap, f"cross-tenant entity leak between {tenant_a!r} and {tenant_b!r}: {overlap}"


def assert_audit_chain(audit_path: Path) -> int:
    """Hash-verify the F.6 audit chain at ``audit_path`` (one JSON entry per line).

    Recomputes each entry's ``entry_hash`` from its canonical content + ``previous_hash``
    (the real ``charter.audit`` algorithm) and verifies the linkage: the first entry chains
    to the genesis hash; each subsequent ``previous_hash`` equals the prior ``entry_hash``.
    Returns the number of entries verified. Raises ``AssertionError`` on any break.
    """
    audit_path = Path(audit_path)
    assert audit_path.is_file(), f"audit log missing at {audit_path}"
    lines = [ln for ln in audit_path.read_text().splitlines() if ln.strip()]
    assert lines, f"audit log at {audit_path} is empty (no chained entries)"

    expected_prev = GENESIS_HASH
    for i, line in enumerate(lines):
        entry = AuditEntry.from_json(line)
        assert entry.previous_hash == expected_prev, (
            f"audit chain break at entry {i}: previous_hash {entry.previous_hash} "
            f"!= expected {expected_prev}"
        )
        recomputed = _hash_entry(
            entry.timestamp,
            entry.agent,
            entry.run_id,
            entry.action,
            entry.payload,
            entry.previous_hash,
        )
        assert recomputed == entry.entry_hash, (
            f"audit entry {i} hash mismatch: recomputed {recomputed} != stored {entry.entry_hash} "
            f"(tampered or corrupt entry)"
        )
        expected_prev = entry.entry_hash
    return len(lines)
