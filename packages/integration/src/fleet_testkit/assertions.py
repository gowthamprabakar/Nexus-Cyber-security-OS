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

_ENVELOPE_KEY = "nexus_envelope"


def assert_ocsf_valid(
    payload: dict[str, Any], *, class_uid: int, require_envelope: bool = False
) -> None:
    """Assert OCSF structural invariants (L1 strictness), handling bare OR enveloped findings.

    The v2 directive §2.3 requires "OCSF emission has valid schema against the agent's declared
    class" — it does NOT require the ``NexusEnvelope`` wrapper. The fleet is in fact split: most
    agents wrap findings.json via ``wrap_ocsf`` (cloud-posture, runtime-threat, the posture/
    detection agents), but several emit **bare** OCSF in their workspace findings file
    (appsec, curiosity, synthesis, investigation, remediation, audit/6003). So this validates the
    OCSF event itself and treats the envelope as optional:

    - if the ``nexus_envelope`` wrapper is present → unwrap it (well-formedness enforced by
      ``unwrap_ocsf``) and require a non-empty tenant on it;
    - else → validate the bare OCSF dict directly.

    Pass ``require_envelope=True`` to additionally assert the wrapper is present (use this only
    where the envelope is a contractual invariant for that agent).

    Class-agnostic event checks (hold for 2002/2003/2004/2005/2007/6003): expected ``class_uid``,
    a ``finding_info`` dict with a non-empty ``uid``, and — only when present — a non-empty
    ``finding_info.types`` list (the 2004 discriminator; the per-agent harness asserts the
    specific ``types[0]`` value where it applies). (L1-Q4: structural — no full OCSF JSON-schema
    validator exists in-repo; a stricter validator is v0.5 hardening.)
    """
    if _ENVELOPE_KEY in payload:
        event, envelope = unwrap_ocsf(payload)
        assert envelope.tenant_id, "NexusEnvelope.tenant_id must be non-empty"
    else:
        assert not require_envelope, (
            f"finding is missing the {_ENVELOPE_KEY!r} wrapper but require_envelope=True"
        )
        event = payload
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


def _entity_type(category: NodeCategory | str) -> str:
    """Resolve a kg entity-type token from a ``NodeCategory`` or a raw string.

    Most agents write ADR-018 ``NodeCategory`` nodes; a few pre-ADR-018 writers (threat-intel,
    curiosity, synthesis) persist raw ``entity_type`` strings with no enum member — accepted here
    so the harness can assert the real write path without inventing enum values (those agents are
    flagged for a v0.5 NodeCategory migration).
    """
    return category.value if isinstance(category, NodeCategory) else category


async def assert_entity_written(
    store: SemanticStore, *, tenant_id: str, category: NodeCategory | str
) -> None:
    """Assert the agent's kg_writer wrote >=1 entity of ``category`` for ``tenant_id``."""
    etype = _entity_type(category)
    rows = await store.list_entities_by_type(tenant_id=tenant_id, entity_type=etype)
    assert rows, (
        f"expected >=1 {etype!r} entity for tenant {tenant_id!r}, found none "
        f"(kg_writer did not write the expected node type)"
    )
    # list_entities_by_type is tenant-scoped, so every row already carries tenant_id; this
    # guards against an accessor regression that would weaken the tenant filter.
    for row in rows:
        assert row.tenant_id == tenant_id, (
            f"entity {row.entity_id} carries tenant {row.tenant_id!r} != {tenant_id!r}"
        )


async def assert_no_entities(
    store: SemanticStore, *, tenant_id: str, categories: Sequence[NodeCategory | str]
) -> None:
    """Assert NO entities of the given categories exist (the inert-offline / no-store path)."""
    for category in categories:
        etype = _entity_type(category)
        rows = await store.list_entities_by_type(tenant_id=tenant_id, entity_type=etype)
        assert not rows, (
            f"expected no {etype!r} entities for tenant {tenant_id!r}, found {len(rows)} "
            f"(a no-store / inert run must not write to the graph)"
        )


async def assert_two_tenant_disjoint(
    store: SemanticStore,
    *,
    tenant_a: str,
    tenant_b: str,
    categories: Sequence[NodeCategory | str],
) -> None:
    """Assert two tenants' subgraphs are disjoint (no cross-tenant entity leak).

    Both tenants must have written something (else the check is vacuous), and their
    entity-id sets across ``categories`` must not intersect.
    """

    async def _ids(tenant_id: str) -> set[str]:
        out: set[str] = set()
        for category in categories:
            rows = await store.list_entities_by_type(
                tenant_id=tenant_id, entity_type=_entity_type(category)
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
