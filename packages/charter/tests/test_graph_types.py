"""Tests for the fleet-graph type catalogue (ADR-018)."""

from __future__ import annotations

from charter.memory.graph_types import EdgeType, NodeCategory


def test_enums_are_str_subclasses() -> None:
    # StrEnum members are plain str → drop-in for entity_type=/relationship_type=.
    assert isinstance(EdgeType.VULNERABLE_TO, str)
    assert isinstance(NodeCategory.CLOUD_RESOURCE, str)
    assert EdgeType.VULNERABLE_TO == "VULNERABLE_TO"
    assert NodeCategory.CLOUD_RESOURCE == "cloud_resource"


def test_edge_values_are_uppercase_and_match_member_name() -> None:
    for member in EdgeType:
        assert member.value == member.name, f"{member.name} value drifted from name"
        assert member.value.isupper()


def test_node_category_values_are_lowercase() -> None:
    for member in NodeCategory:
        assert member.value == member.value.lower()
        assert member.value.islower() or "_" in member.value


def test_values_are_unique() -> None:
    edge_values = [m.value for m in EdgeType]
    node_values = [m.value for m in NodeCategory]
    assert len(edge_values) == len(set(edge_values))
    assert len(node_values) == len(set(node_values))


def test_catalogue_anchor_edges_present() -> None:
    # Spot-check the load-bearing cross-domain edges from #711 (the code-to-cloud
    # bridge, the access edge, the reachability edge, the correlation edges).
    for name in (
        "BUILT_FROM",
        "DEPLOYED_VIA",
        "HAS_ACCESS_TO",
        "CAN_ESCALATE_TO",
        "CAN_REACH",
        "IRSA_MAPPING",
        "TRAINED_ON",
        "IN_BLAST_RADIUS",
    ):
        assert name in EdgeType.__members__


def test_catalogue_anchor_node_categories_present() -> None:
    for name in (
        "CLOUD_RESOURCE",
        "IDENTITY",
        "DATA_CLASSIFICATION",
        "CONTAINER_IMAGE",
        "CODE_REPOSITORY",
        "SAAS_TENANT",
        "AI_SERVICE",
        "ATTACK_PATH",
    ):
        assert name in NodeCategory.__members__
