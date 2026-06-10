"""Suricata rule-pack management (D.4 v0.2 Task 4).

Real-time Suricata alerts reference rules by ``signature_id`` (sid); this module manages
the **rule packs** that decide which rules are active + carry their classtype/msg for
downstream filtering + enrichment. Supports a bundled **default** pack (an ET-Open
subset), **custom** pack loading, and atomic **hot-reload** — so an operator can update
detection coverage without restarting the real-time subscriber. Mirrors D.3's
`falco/rule_packs` (Group A precedent).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class SuricataRule:
    sid: int
    msg: str = ""
    classtype: str = ""
    enabled: bool = True


@dataclass(frozen=True, slots=True)
class RulePack:
    name: str
    rules: tuple[SuricataRule, ...]


def parse_rule_pack(name: str, raw_rules: list[dict[str, Any]]) -> RulePack:
    """Parse a list of raw Suricata rule dicts (``sid``/``msg``/``classtype``/``enabled``)
    into a typed `RulePack`; entries without a positive ``sid`` are skipped."""
    rules: list[SuricataRule] = []
    for r in raw_rules:
        sid = r.get("sid")
        if not isinstance(sid, int) or sid <= 0:
            continue
        rules.append(
            SuricataRule(
                sid=sid,
                msg=str(r.get("msg", "")),
                classtype=str(r.get("classtype", "")),
                enabled=bool(r.get("enabled", True)),
            )
        )
    return RulePack(name=name, rules=tuple(rules))


#: A small bundled ET-Open subset so the agent has baseline coverage out of the box.
DEFAULT_RULE_PACK = RulePack(
    name="et-open-subset",
    rules=(
        SuricataRule(2019401, "ET MALWARE Suspicious TLS", "trojan-activity"),
        SuricataRule(2024897, "ET POLICY Outbound to Tor", "policy-violation"),
        SuricataRule(2027865, "ET MALWARE DNS Tunneling", "trojan-activity"),
        SuricataRule(2008581, "ET SCAN Potential SSH Scan", "attempted-recon"),
    ),
)


class RulePackManager:
    """Holds the registered rule packs (the default + any custom packs), with atomic
    hot-reload. Later-registered packs win on duplicate sids."""

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

    def _resolved(self) -> dict[int, SuricataRule]:
        out: dict[int, SuricataRule] = {}
        for pack in self._packs.values():
            for rule in pack.rules:
                out[rule.sid] = rule
        return out

    def enabled_rules(self) -> tuple[SuricataRule, ...]:
        """All enabled rules across packs (deduped by sid, last pack wins)."""
        return tuple(r for r in self._resolved().values() if r.enabled)

    def is_enabled(self, sid: int) -> bool:
        rule = self._resolved().get(sid)
        return rule is not None and rule.enabled

    def classtype_for(self, sid: int) -> str:
        rule = self._resolved().get(sid)
        return rule.classtype if rule is not None else ""
