"""``fleet_testkit`` — shared helpers for the v0.4 fleet test (directive v2).

Level 1 (integration smoke) surface: an in-memory ``SemanticStore``, OCSF structural
validation, kg-entity-written + tenant-isolation + audit-chain assertions, and a wiring
``ExecutionContract`` builder. Later levels extend this package (L2 precision/recall
evaluator; L6 pure-breed finale) — L1 ships only the smoke surface.

The shared mechanics live here so all 20 per-agent ``tests/integration/test_wiring.py``
files import one implementation (no per-agent copy-paste of the harness).
"""

from __future__ import annotations

from fleet_testkit.assertions import (
    assert_audit_chain,
    assert_entity_written,
    assert_no_entities,
    assert_ocsf_valid,
    assert_two_tenant_disjoint,
)
from fleet_testkit.contract import wiring_contract
from fleet_testkit.store import in_memory_semantic_store

__all__ = [
    "assert_audit_chain",
    "assert_entity_written",
    "assert_no_entities",
    "assert_ocsf_valid",
    "assert_two_tenant_disjoint",
    "in_memory_semantic_store",
    "wiring_contract",
]
