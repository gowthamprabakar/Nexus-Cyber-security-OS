"""D.4 v0.2 Task 4 — Suricata rule-pack management tests."""

from __future__ import annotations

from network_threat.suricata.rule_packs import (
    DEFAULT_RULE_PACK,
    RulePack,
    RulePackManager,
    SuricataRule,
    parse_rule_pack,
)


def test_parse_rule_pack() -> None:
    pack = parse_rule_pack(
        "custom",
        [
            {"sid": 1000001, "msg": "M1", "classtype": "trojan-activity", "enabled": True},
            {"sid": 1000002},
            {"msg": "no sid"},  # skipped
            {"sid": 0},  # non-positive sid skipped
        ],
    )
    assert [r.sid for r in pack.rules] == [1000001, 1000002]
    assert pack.rules[0].classtype == "trojan-activity"


def test_default_pack_present() -> None:
    mgr = RulePackManager()
    assert "et-open-subset" in mgr.pack_names
    assert len(DEFAULT_RULE_PACK.rules) == 4


def test_register_custom_pack() -> None:
    mgr = RulePackManager(include_default=False)
    mgr.register(RulePack("c", (SuricataRule(42, "X", "scan"),)))
    assert mgr.is_enabled(42) and mgr.classtype_for(42) == "scan"


def test_enabled_rules_excludes_disabled() -> None:
    mgr = RulePackManager(include_default=False)
    mgr.register(RulePack("c", (SuricataRule(1, enabled=True), SuricataRule(2, enabled=False))))
    assert {r.sid for r in mgr.enabled_rules()} == {1}


def test_later_pack_overrides_by_sid() -> None:
    mgr = RulePackManager(include_default=False)
    mgr.register(RulePack("a", (SuricataRule(7, classtype="scan"),)))
    mgr.register(RulePack("b", (SuricataRule(7, classtype="trojan-activity"),)))
    [rule] = [r for r in mgr.enabled_rules() if r.sid == 7]
    assert rule.classtype == "trojan-activity"


def test_hot_reload_swaps_atomically() -> None:
    mgr = RulePackManager(include_default=False)
    mgr.register(RulePack("c", (SuricataRule(1),)))
    mgr.register(RulePack("keep", (SuricataRule(9),)))
    mgr.hot_reload("c", [{"sid": 2}])
    assert {r.sid for r in mgr.enabled_rules()} == {2, 9}  # sid 1 gone, 'keep' untouched


def test_remove_pack() -> None:
    mgr = RulePackManager(include_default=False)
    mgr.register(RulePack("c", (SuricataRule(5),)))
    mgr.remove("c")
    assert mgr.pack_names == () and mgr.is_enabled(5) is False


def test_unknown_sid_lookup() -> None:
    mgr = RulePackManager(include_default=False)
    assert mgr.is_enabled(99999) is False and mgr.classtype_for(99999) == ""
