"""investigation v0.2 Task 4 — substrate query integration tests (WI-I16/H5)."""

from __future__ import annotations

import pytest
from investigation.tools.fleet_evidence_reader import TenantScopeError
from investigation.tools.substrate_query import (
    MAX_MEMORY_WALK_DEPTH,
    assert_tenant_scoped,
    audit_evidence_id,
    build_substrate_query,
    clamp_walk_depth,
    entity_evidence_id,
    finding_evidence_id,
)

_TENANT = "01HV0T0000000000000000TENA"


def test_max_walk_depth_is_three() -> None:
    assert MAX_MEMORY_WALK_DEPTH == 3


def test_tenant_scoped_passes() -> None:
    assert_tenant_scoped(_TENANT)  # does not raise


def test_empty_tenant_rejected() -> None:
    with pytest.raises(TenantScopeError, match="tenant_id"):
        assert_tenant_scoped("")


def test_clamp_walk_depth() -> None:
    assert clamp_walk_depth(5) == 3 and clamp_walk_depth(2) == 2 and clamp_walk_depth(-1) == 0


def test_build_substrate_query() -> None:
    q = build_substrate_query(tenant_id=_TENANT, requested_depth=10)
    assert q.tenant_id == _TENANT and q.walk_depth == 3


def test_build_rejects_empty_tenant() -> None:
    with pytest.raises(TenantScopeError):
        build_substrate_query(tenant_id="", requested_depth=2)


def test_evidence_ref_namespace() -> None:
    assert audit_evidence_id("corr-1") == "audit_event:corr-1"
    assert finding_evidence_id("F-1") == "finding:F-1"
    assert entity_evidence_id("E-1") == "entity:E-1"
