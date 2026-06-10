"""D.3 v0.2 Task 3 — Falco rule-pack management tests."""

from __future__ import annotations

from runtime_threat.falco.rule_packs import (
    DEFAULT_RULE_PACK,
    FalcoRule,
    RulePack,
    RulePackManager,
    parse_rule_pack,
)


def test_parse_rule_pack() -> None:
    pack = parse_rule_pack(
        "custom",
        [
            {"rule": "R1", "priority": "Critical", "tags": ["network"], "enabled": True},
            {"rule": "R2"},  # defaults
            {"priority": "Warning"},  # no name → skipped
        ],
    )
    assert pack.name == "custom"
    assert [r.name for r in pack.rules] == ["R1", "R2"]
    assert pack.rules[0].priority == "Critical" and pack.rules[0].tags == ("network",)
    assert pack.rules[1].priority == "Notice" and pack.rules[1].enabled is True


def test_default_pack_present() -> None:
    mgr = RulePackManager()
    assert "default" in mgr.pack_names
    assert len(DEFAULT_RULE_PACK.rules) == 4


def test_register_custom_pack() -> None:
    mgr = RulePackManager(include_default=False)
    mgr.register(RulePack("c", (FalcoRule("X", "Warning", ("t1",)),)))
    assert mgr.pack_names == ("c",)
    assert mgr.is_enabled("X") and mgr.tags_for("X") == ("t1",)


def test_enabled_rules_excludes_disabled() -> None:
    mgr = RulePackManager(include_default=False)
    mgr.register(RulePack("c", (FalcoRule("on"), FalcoRule("off", enabled=False))))
    names = {r.name for r in mgr.enabled_rules()}
    assert names == {"on"}


def test_later_pack_overrides_rule_by_name() -> None:
    mgr = RulePackManager(include_default=False)
    mgr.register(RulePack("a", (FalcoRule("R", "Notice"),)))
    mgr.register(RulePack("b", (FalcoRule("R", "Critical"),)))
    [rule] = [r for r in mgr.enabled_rules() if r.name == "R"]
    assert rule.priority == "Critical"  # pack b won


def test_hot_reload_swaps_atomically() -> None:
    mgr = RulePackManager(include_default=False)
    mgr.register(RulePack("c", (FalcoRule("old"),)))
    mgr.register(RulePack("keep", (FalcoRule("kept"),)))
    mgr.hot_reload("c", [{"rule": "new", "priority": "Critical"}])
    names = {r.name for r in mgr.enabled_rules()}
    assert names == {"new", "kept"}  # 'old' gone, 'keep' pack untouched


def test_remove_pack() -> None:
    mgr = RulePackManager(include_default=False)
    mgr.register(RulePack("c", (FalcoRule("X"),)))
    mgr.remove("c")
    assert mgr.pack_names == () and mgr.is_enabled("X") is False


def test_unknown_rule_lookup() -> None:
    mgr = RulePackManager(include_default=False)
    assert mgr.is_enabled("nope") is False and mgr.tags_for("nope") == ()
