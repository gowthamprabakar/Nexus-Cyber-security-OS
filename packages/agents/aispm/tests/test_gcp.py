"""Tests for the GCP Vertex AI connector parse + posture rules (D.11 PR3)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from aispm.posture.gcp import GcpAiFindingType, evaluate_gcp_ai
from aispm.tools.gcp_ai import GcpAiInventory, VertexEndpoint, inventory_from_reader
from shared.fabric.envelope import NexusEnvelope

_NOW = datetime(2026, 6, 17, 12, 0, 0, tzinfo=UTC)


class _FakeGcpReader:
    def __init__(self, endpoints: list[dict[str, Any]]) -> None:
        self._e = endpoints

    def vertex_endpoints(self) -> list[dict[str, Any]]:
        return self._e


def _envelope() -> NexusEnvelope:
    return NexusEnvelope(
        correlation_id="c",
        tenant_id="cust_test",
        agent_id="aispm",
        nlah_version="0.1.0",
        model_pin="deterministic",
        charter_invocation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
    )


def test_parse_and_skip_nameless() -> None:
    reader = _FakeGcpReader(
        [
            {"name": "ep-prod", "public": True, "cmk_encrypted": False, "psc_enabled": False},
            {"name": ""},
        ]
    )
    inv = inventory_from_reader(reader, project_id="proj-1", location="us-central1")
    assert [e.name for e in inv.endpoints] == ["ep-prod"]


def test_all_three_checks_fire() -> None:
    inv = GcpAiInventory(
        project_id="proj-1",
        location="us-central1",
        endpoints=(
            VertexEndpoint(name="ep-prod", public=True, cmk_encrypted=False, psc_enabled=False),
        ),
    )
    findings = evaluate_gcp_ai(inv, envelope=_envelope(), detected_at=_NOW)
    assert {f.finding_type for f in findings} == {t.value for t in GcpAiFindingType}
    assert all(f.to_dict()["class_uid"] == 2003 for f in findings)
    assert "AISPM-VERTEX-001-proj-1-ep-prod" in {f.finding_id for f in findings}


def test_clean_and_unknown_skip() -> None:
    clean = GcpAiInventory(
        project_id="proj-1",
        location="us-central1",
        endpoints=(VertexEndpoint(name="ok", public=False, cmk_encrypted=True, psc_enabled=True),),
    )
    assert evaluate_gcp_ai(clean, envelope=_envelope(), detected_at=_NOW) == []
    unknown = GcpAiInventory(
        project_id="proj-1",
        location="us-central1",
        endpoints=(VertexEndpoint(name="u", public=None, cmk_encrypted=None, psc_enabled=None),),
    )
    assert evaluate_gcp_ai(unknown, envelope=_envelope(), detected_at=_NOW) == []
