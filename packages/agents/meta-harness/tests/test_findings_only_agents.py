"""NEX-105 — compliance is findings-only BY DESIGN (not a dead agent to 'fix' with a fake edge)."""

from charter.memory.graph_types import EdgeType
from meta_harness.path_taxonomy import FINDINGS_ONLY_AGENTS, TRAVERSABLE_EDGES


def test_compliance_is_declared_findings_only():
    assert "compliance" in FINDINGS_ONLY_AGENTS


def test_affects_is_not_attack_progression():
    # compliance's only edge is AFFECTS (finding→resource). It MUST stay non-traversable — if someone
    # made it traversable, compliance would wrongly start producing attack paths. This guards that.
    assert EdgeType.AFFECTS.value not in TRAVERSABLE_EDGES


def test_multi_cloud_posture_is_not_findings_only():
    # NEX-104 connected it to sources; it is a path producer now, not attestation-only.
    assert "multi-cloud-posture" not in FINDINGS_ONLY_AGENTS
