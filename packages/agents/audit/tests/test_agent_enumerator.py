"""audit v0.2 Task 2 — cross-agent audit chain enumerator tests (Q1/WI-F1)."""

from __future__ import annotations

from audit.aggregation.agent_enumerator import (
    AUDITED_AGENTS,
    ChainSource,
    SourceType,
    by_source_type,
    enumerate_chains,
)


def test_ten_audited_agents() -> None:
    assert len(AUDITED_AGENTS) == 10
    assert {"cloud_posture", "multi_cloud_posture", "compliance", "data_security"} <= set(
        AUDITED_AGENTS
    )


def test_enumerate_charter_jsonl() -> None:
    sources = enumerate_chains(charter_jsonl=["/data/audit.jsonl"])
    assert len(sources) == 1
    assert sources[0].source_type == SourceType.CHARTER_JSONL and sources[0].agent_id == ""


def test_enumerate_f5_episodes() -> None:
    sources = enumerate_chains(f5_episode_agents=["compliance", "identity"])
    assert {s.agent_id for s in sources} == {"compliance", "identity"}
    assert all(s.source_type == SourceType.F5_EPISODES for s in sources)


def test_enumerate_agent_chains() -> None:
    sources = enumerate_chains(agent_chains={"cloud_posture": "/data/cp.jsonl"})
    assert len(sources) == 1
    assert (
        sources[0].source_type == SourceType.AGENT_CHAIN and sources[0].location == "/data/cp.jsonl"
    )


def test_unknown_agent_skipped() -> None:
    # F.6 enumerates only closed-cycle agents.
    sources = enumerate_chains(f5_episode_agents=["not_a_real_agent"], agent_chains={"ghost": "x"})
    assert sources == ()


def test_all_three_source_types() -> None:
    sources = enumerate_chains(
        charter_jsonl=["/a.jsonl"],
        f5_episode_agents=["compliance"],
        agent_chains={"data_security": "/ds.jsonl"},
    )
    assert {s.source_type for s in sources} == set(SourceType)


def test_by_source_type_groups() -> None:
    sources = enumerate_chains(
        charter_jsonl=["/a.jsonl", "/b.jsonl"], f5_episode_agents=["compliance"]
    )
    grouped = by_source_type(sources)
    assert len(grouped[SourceType.CHARTER_JSONL]) == 2
    assert len(grouped[SourceType.F5_EPISODES]) == 1


def test_chain_source_is_metadata_only() -> None:
    assert set(ChainSource.__slots__) == {"source_type", "agent_id", "location"}


def test_empty_enumeration() -> None:
    assert enumerate_chains() == () and by_source_type([]) == {}
