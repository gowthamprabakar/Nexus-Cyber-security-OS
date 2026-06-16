"""Falco rule-pack management (D.3 v0.2 Task 3).

Real-time Falco events reference rules by name; this module manages the **rule packs**
that decide which rules are active + carry their priority/tags for downstream filtering
+ enrichment. Supports a bundled **default** pack, **custom** pack loading, and atomic
**hot-reload** (swap a pack's rules without disturbing the others) — so an operator can
update detection coverage without restarting the real-time subscriber.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class FalcoRule:
    name: str
    priority: str = "Notice"
    tags: tuple[str, ...] = field(default_factory=tuple)
    enabled: bool = True


@dataclass(frozen=True, slots=True)
class RulePack:
    name: str
    rules: tuple[FalcoRule, ...]


def parse_rule_pack(name: str, raw_rules: list[dict[str, Any]]) -> RulePack:
    """Parse a list of raw Falco rule dicts (``rule``/``priority``/``tags``/``enabled``)
    into a typed `RulePack`; entries without a ``rule`` name are skipped."""
    rules: list[FalcoRule] = []
    for r in raw_rules:
        rule_name = r.get("rule")
        if not isinstance(rule_name, str) or not rule_name:
            continue
        rules.append(
            FalcoRule(
                name=rule_name,
                priority=str(r.get("priority", "Notice")),
                tags=tuple(str(t) for t in r.get("tags", [])),
                enabled=bool(r.get("enabled", True)),
            )
        )
    return RulePack(name=name, rules=tuple(rules))


#: A small bundled default pack so the agent has baseline coverage out of the box.
DEFAULT_RULE_PACK = RulePack(
    name="default",
    rules=(
        FalcoRule(
            "Terminal shell in container", "Warning", ("container", "shell", "mitre_execution")
        ),
        FalcoRule(
            "Read sensitive file untrusted", "Warning", ("filesystem", "mitre_credential_access")
        ),
        FalcoRule(
            "Outbound connection to C2", "Critical", ("network", "mitre_command_and_control")
        ),
        FalcoRule(
            "Launch privileged container", "Notice", ("container", "mitre_privilege_escalation")
        ),
        # v0.4 Stage 1.1 expansion — standard runtime-threat detections, each mapped to a
        # MITRE ATT&CK tactic tag (the agent's own rule abstractions, not transcribed
        # upstream Falco rule ids; consistent with the four v0.2 entries above).
        FalcoRule("Reverse shell spawned", "Critical", ("network", "shell", "mitre_execution")),
        FalcoRule("Write below etc", "Warning", ("filesystem", "mitre_persistence")),
        FalcoRule(
            "Modify shell configuration file", "Warning", ("filesystem", "mitre_persistence")
        ),
        FalcoRule("Crypto mining activity detected", "Critical", ("network", "mitre_impact")),
        FalcoRule("Unexpected setuid call", "Warning", ("process", "mitre_privilege_escalation")),
        FalcoRule(
            "Drop and execute new binary in container",
            "Warning",
            ("container", "process", "mitre_execution"),
        ),
        FalcoRule(
            "Cloud or kubectl CLI run in container", "Warning", ("container", "mitre_discovery")
        ),
        FalcoRule(
            "Package management launched in container",
            "Notice",
            ("container", "mitre_persistence"),
        ),
        FalcoRule(
            "Sensitive host path mounted by container",
            "Warning",
            ("container", "mitre_privilege_escalation"),
        ),
        FalcoRule(
            "Clear or tamper system logs", "Warning", ("filesystem", "mitre_defense_evasion")
        ),
    ),
)


class RulePackManager:
    """Holds the registered rule packs (the default + any custom packs), with atomic
    hot-reload. Later-registered packs win on duplicate rule names."""

    def __init__(self, *, include_default: bool = True) -> None:
        self._packs: dict[str, RulePack] = {}
        if include_default:
            self.register(DEFAULT_RULE_PACK)

    def register(self, pack: RulePack) -> None:
        """Register (or hot-reload, if the name exists) a pack — atomic replace."""
        self._packs[pack.name] = pack

    def hot_reload(self, name: str, raw_rules: list[dict[str, Any]]) -> RulePack:
        """Atomically swap a pack's rules from raw dicts; other packs are untouched."""
        pack = parse_rule_pack(name, raw_rules)
        self._packs[name] = pack
        return pack

    def remove(self, name: str) -> None:
        self._packs.pop(name, None)

    @property
    def pack_names(self) -> tuple[str, ...]:
        return tuple(self._packs)

    def _resolved(self) -> dict[str, FalcoRule]:
        # Flatten packs in registration order; later packs override earlier by rule name.
        out: dict[str, FalcoRule] = {}
        for pack in self._packs.values():
            for rule in pack.rules:
                out[rule.name] = rule
        return out

    def enabled_rules(self) -> tuple[FalcoRule, ...]:
        """All enabled rules across packs (deduped by name, last pack wins)."""
        return tuple(r for r in self._resolved().values() if r.enabled)

    def is_enabled(self, rule_name: str) -> bool:
        rule = self._resolved().get(rule_name)
        return rule is not None and rule.enabled

    def tags_for(self, rule_name: str) -> tuple[str, ...]:
        rule = self._resolved().get(rule_name)
        return rule.tags if rule is not None else ()
