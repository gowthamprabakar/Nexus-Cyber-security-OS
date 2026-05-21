"""Tests — `supervisor.routing.parser` (Task 3).

12 tests covering parser behavior + the bundled `agents.md`:

1.  Bundled `agents.md` parses cleanly.
2.  Bundled file ships 10 rules (one per v0.1 specialist named in
    the plan).
3.  Every bundled rule has a non-empty permitted_tools list.
4.  Every bundled rule's target_agent_declared matches its
    target_agent (the v0.1 "explicit routing" convention).
5.  Missing file -> RoutingRuleParseError.
6.  Empty file (no frontmatter) -> RoutingRuleParseError.
7.  Malformed YAML frontmatter -> RoutingRuleParseError.
8.  Frontmatter missing `rules:` key -> RoutingRuleParseError.
9.  `rules:` is not a list -> RoutingRuleParseError.
10. Duplicate `rule_id` across two entries -> RoutingRuleParseError.
11. Per-rule pydantic validation failure (missing predicate)
    surfaces as RoutingRuleParseError with helpful index.
12. `known_agents` filter rejects unknown target_agent values.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from supervisor.routing.parser import (
    RoutingRuleParseError,
    load_routing_rules,
)

_BUNDLED_AGENTS_MD = (
    Path(__file__).resolve().parent.parent / "src" / "supervisor" / "routing" / "agents.md"
)

_EXPECTED_AGENTS_V0_1 = frozenset(
    {
        "cloud_posture",
        "vulnerability",
        "identity",
        "runtime_threat",
        "audit",
        "investigation",
        "network_threat",
        "multi_cloud_posture",
        "k8s_posture",
        "remediation",
    }
)


# ---------------------------------------------------------------------------
# Bundled agents.md
# ---------------------------------------------------------------------------


def test_bundled_agents_md_parses_cleanly() -> None:
    rules = load_routing_rules(_BUNDLED_AGENTS_MD)
    assert len(rules) == 10


def test_bundled_agents_md_covers_each_v0_1_specialist() -> None:
    rules = load_routing_rules(_BUNDLED_AGENTS_MD)
    targets = {r.target_agent for r in rules}
    assert targets == _EXPECTED_AGENTS_V0_1


def test_every_bundled_rule_has_permitted_tools() -> None:
    rules = load_routing_rules(_BUNDLED_AGENTS_MD)
    for rule in rules:
        assert rule.permitted_tools, f"{rule.rule_id} ships empty permitted_tools"


def test_every_bundled_rule_uses_explicit_target_agent_declared() -> None:
    """v0.1 convention: every shipped rule uses target_agent_declared
    (explicit routing). Pattern-match fallbacks are operator-added."""
    rules = load_routing_rules(_BUNDLED_AGENTS_MD)
    for rule in rules:
        assert rule.target_agent_declared == rule.target_agent, (
            f"{rule.rule_id} target_agent_declared/target_agent mismatch"
        )


# ---------------------------------------------------------------------------
# Error paths
# ---------------------------------------------------------------------------


def test_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(RoutingRuleParseError, match="routing table missing"):
        load_routing_rules(tmp_path / "nope.md")


def test_empty_file_raises(tmp_path: Path) -> None:
    path = tmp_path / "empty.md"
    path.write_text("# no frontmatter here\n", encoding="utf-8")
    with pytest.raises(RoutingRuleParseError, match="frontmatter"):
        load_routing_rules(path)


def test_malformed_yaml_raises(tmp_path: Path) -> None:
    path = tmp_path / "bad.md"
    path.write_text("---\nrules: [::: not yaml\n---\n", encoding="utf-8")
    with pytest.raises(RoutingRuleParseError, match="malformed YAML"):
        load_routing_rules(path)


def test_missing_rules_key_raises(tmp_path: Path) -> None:
    path = tmp_path / "norules.md"
    path.write_text("---\nfoo: bar\n---\n", encoding="utf-8")
    with pytest.raises(RoutingRuleParseError, match="missing required 'rules:'"):
        load_routing_rules(path)


def test_rules_not_a_list_raises(tmp_path: Path) -> None:
    path = tmp_path / "scalar.md"
    path.write_text("---\nrules: not_a_list\n---\n", encoding="utf-8")
    with pytest.raises(RoutingRuleParseError, match="must be a list"):
        load_routing_rules(path)


def test_duplicate_rule_id_raises(tmp_path: Path) -> None:
    path = tmp_path / "dup.md"
    path.write_text(
        "---\n"
        "rules:\n"
        "  - rule_id: r1\n"
        "    target_agent: a\n"
        "    target_agent_declared: a\n"
        "  - rule_id: r1\n"
        "    target_agent: b\n"
        "    target_agent_declared: b\n"
        "---\n",
        encoding="utf-8",
    )
    with pytest.raises(RoutingRuleParseError, match="duplicate rule_id"):
        load_routing_rules(path)


def test_per_rule_validation_failure_surfaces_index(tmp_path: Path) -> None:
    """Rule missing all match predicates fails the pydantic validator."""
    path = tmp_path / "nopred.md"
    path.write_text(
        "---\n"
        "rules:\n"
        "  - rule_id: r1\n"
        "    target_agent: a\n"
        "    target_agent_declared: a\n"
        "  - rule_id: r2\n"
        "    target_agent: b\n"
        "---\n",
        encoding="utf-8",
    )
    with pytest.raises(RoutingRuleParseError, match="rules\\[1\\] failed validation"):
        load_routing_rules(path)


def test_known_agents_filter_rejects_unknown(tmp_path: Path) -> None:
    path = tmp_path / "unknown.md"
    path.write_text(
        "---\n"
        "rules:\n"
        "  - rule_id: r1\n"
        "    target_agent: ghost\n"
        "    target_agent_declared: ghost\n"
        "---\n",
        encoding="utf-8",
    )
    with pytest.raises(RoutingRuleParseError, match="not in known_agents"):
        load_routing_rules(path, known_agents=frozenset({"cloud_posture"}))
