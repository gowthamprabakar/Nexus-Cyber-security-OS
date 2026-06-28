"""BP4 — the candidate feedback loop: dismiss → suppress, confirm → auto-draft an archetype."""

import pytest
from charter.memory.graph_types import EdgeType, NodeCategory
from fleet_testkit import in_memory_semantic_store
from meta_harness.candidate_feedback import (
    FeedbackLog,
    draft_archetype,
    signature_of,
)
from meta_harness.path_engine import (
    CandidatePath,
    GenericPath,
    PathHop,
    find_candidate_paths,
)

_R = NodeCategory.CLOUD_RESOURCE.value
_DC = NodeCategory.DATA_CLASSIFICATION.value
_PE = NodeCategory.PROCESS_EVENT.value


def _candidate(source, sink, edges, score=40):
    hops = tuple(PathHop(e, f"n{i}", f"node{i}") for i, e in enumerate(edges))
    return CandidatePath(GenericPath("s", source, "k", sink, hops, source_label="src"), score)


async def _node(store, t, etype, ext, props):
    return await store.upsert_entity(
        tenant_id=t, entity_type=etype, external_id=ext, properties=props
    )


async def _edge(store, t, src, dst, rel):
    await store.add_relationship(
        tenant_id=t, src_entity_id=src, dst_entity_id=dst, relationship_type=rel, properties={}
    )


def test_signature_is_the_shape_key():
    c = _candidate("runtime_detection", "sensitive_data", ["EXECUTED_ON", "EXPOSES_DATA"])
    assert signature_of(c) == (
        "runtime_detection",
        "sensitive_data",
        ("EXECUTED_ON", "EXPOSES_DATA"),
    )
    # The path and its wrapper resolve to the same signature.
    assert signature_of(c.path) == signature_of(c)


def test_draft_archetype_is_a_reviewable_slice():
    c = _candidate("runtime_detection", "sensitive_data", ["EXECUTED_ON", "EXPOSES_DATA"], score=42)
    draft = draft_archetype(c)
    assert draft.name == "runtime_detection_to_sensitive_data"
    assert draft.named_shape_entry == signature_of(c)  # retires it from the candidate tier
    # Suggested severity is lifted into the named band (above the candidate cap).
    assert 58 <= draft.suggested_severity <= 90
    # The detector sketch walks the actual signature against the real source/sink categories.
    assert "async def find_runtime_detection_to_sensitive_data" in draft.detector_sketch
    assert "process_event" in draft.detector_sketch  # PROCESS_EVENT source category resolved
    assert "'EXECUTED_ON'" in draft.detector_sketch and "'EXPOSES_DATA'" in draft.detector_sketch
    # The checklist names every touch-point a named detector needs.
    joined = " ".join(draft.checklist)
    assert "NAMED_SHAPES" in joined and "_SEVERITY" in joined and "REMEDIATION" in joined
    assert "e2e" in joined


def test_feedback_log_records_and_validates():
    log = FeedbackLog()
    c = _candidate("privileged_workload", "sensitive_data", ["HAS_ACCESS_TO", "EXPOSES_DATA"])
    log.confirm(c)
    log.dismiss(_candidate("identity_principal", "sensitive_data", ["CONTAINS"]))
    assert log.confirmed_signatures() == {signature_of(c)}
    assert ("identity_principal", "sensitive_data", ("CONTAINS",)) in log.suppressed_signatures()
    with pytest.raises(ValueError, match="confirm"):
        log.record("maybe", signature_of(c))


def test_feedback_log_serialization_round_trips():
    log = FeedbackLog()
    log.dismiss(_candidate("identity_principal", "sensitive_data", ["CONTAINS", "EXPOSES_DATA"]))
    log.confirm(_candidate("runtime_detection", "known_vulnerability", ["EXECUTED_ON"]))
    restored = FeedbackLog.from_dict(log.to_dict())
    assert restored.decisions == log.decisions
    assert restored.suppressed_signatures() == log.suppressed_signatures()


@pytest.mark.asyncio
async def test_dismiss_suppresses_the_shape_end_to_end():
    """A dismissed shape stops surfacing as a candidate; a different novel shape still does."""
    t = "t"
    async with in_memory_semantic_store() as store:
        # runtime -> data (a novel candidate shape)
        ev = await _node(store, t, _PE, "RUNTIME-P-1-e", {"finding_type": "process"})
        host = await _node(store, t, _R, "host-1", {})
        data = await _node(store, t, _DC, "host-1:ssn", {"data_type": "ssn"})
        await _edge(store, t, ev, host, EdgeType.EXECUTED_ON.value)
        await _edge(store, t, host, data, EdgeType.EXPOSES_DATA.value)

        before = await find_candidate_paths(store, t)
        assert len(before) == 1
        sig = signature_of(before[0])

        log = FeedbackLog()
        log.dismiss(before[0])
        after = await find_candidate_paths(store, t, suppressed=log.suppressed_signatures())
        assert after == [], "the dismissed shape no longer surfaces"
        # Sanity: suppressing a DIFFERENT shape leaves this candidate visible.
        other = frozenset({("identity_principal", "sensitive_data", ("CONTAINS",))})
        assert len(await find_candidate_paths(store, t, suppressed=other)) == 1
        assert sig not in other
