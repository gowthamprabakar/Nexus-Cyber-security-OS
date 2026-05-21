"""Routing rule parser — markdown-with-YAML-frontmatter loader.

Loads ``routing/agents.md`` (or any operator-supplied path) into a
``RoutingRule[]`` pydantic structure. The file format:

```
---
rules:
  - rule_id: cloud_posture_explicit
    target_agent: cloud_posture
    target_agent_declared: cloud_posture
    permitted_tools: [prowler_scan, aws_s3_describe]
    priority: 10
  - ...
---

# Operator-readable prose follows the frontmatter.
```

Operators read the prose; Supervisor reads the YAML frontmatter.
The two stay in lockstep by convention — no automated check on
the prose content.

**Validation discipline.** Each rule is validated through the
``RoutingRule`` pydantic model — at-least-one-match-predicate,
non-empty permitted-tool names, bounded numeric ranges. Unknown
``target_agent`` values are validated against an optional
``known_agents`` set passed by the caller (the heartbeat loop
populates this from the ``nexus_eval_runners`` entry-point names
at startup).

**Errors.** ``RoutingRuleParseError`` raised on:

- File missing.
- Malformed YAML frontmatter.
- Missing ``rules:`` key.
- Duplicate ``rule_id``.
- ``target_agent`` not in ``known_agents`` (when provided).
- Any per-rule pydantic validation failure.

**Q-ARCH-2 compliance.** No LLM import anywhere. No A.4
``parse_nlah_dir`` import. Pure-function over YAML.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from supervisor.schemas import RoutingRule

_FRONTMATTER_RE = re.compile(r"\A\s*---\s*\n(?P<body>.*?)\n---\s*(?:\n|$)", re.DOTALL)


class RoutingRuleParseError(ValueError):
    """Raised when ``agents.md`` violates the routing-rule contract."""


def load_routing_rules(
    path: Path | str,
    *,
    known_agents: frozenset[str] | None = None,
) -> tuple[RoutingRule, ...]:
    """Parse ``agents.md`` into a tuple of validated routing rules.

    Args:
        path: Path to the ``agents.md`` file.
        known_agents: Optional set of valid ``target_agent`` values
            (typically the names of registered
            ``nexus_eval_runners`` entry points). When provided,
            any rule referencing an unknown agent raises.

    Returns:
        A tuple of validated ``RoutingRule`` instances in source
        order.

    Raises:
        RoutingRuleParseError: when the file is missing, the
            frontmatter is malformed, or any rule fails
            validation.
    """
    file = Path(path)
    if not file.is_file():
        raise RoutingRuleParseError(f"routing table missing: {file}")

    text = file.read_text(encoding="utf-8")
    frontmatter = _extract_frontmatter(text, file)
    raw_rules = _extract_rules_block(frontmatter, file)
    return _build_rules(raw_rules, known_agents=known_agents, file=file)


def _extract_frontmatter(text: str, file: Path) -> str:
    """Pull the YAML frontmatter out of ``agents.md``."""
    match = _FRONTMATTER_RE.match(text)
    if match is None:
        raise RoutingRuleParseError(
            f"{file}: missing YAML frontmatter (expected document to start with '---')"
        )
    return match.group("body")


def _extract_rules_block(frontmatter: str, file: Path) -> list[dict[str, object]]:
    """Parse the frontmatter and return the ``rules`` list."""
    try:
        parsed = yaml.safe_load(frontmatter)
    except yaml.YAMLError as exc:
        raise RoutingRuleParseError(f"{file}: malformed YAML frontmatter: {exc}") from exc

    if not isinstance(parsed, dict):
        raise RoutingRuleParseError(
            f"{file}: frontmatter must be a YAML mapping; got {type(parsed).__name__}"
        )
    rules = parsed.get("rules")
    if rules is None:
        raise RoutingRuleParseError(f"{file}: frontmatter missing required 'rules:' key")
    if not isinstance(rules, list):
        raise RoutingRuleParseError(f"{file}: 'rules:' must be a list; got {type(rules).__name__}")

    typed_rules: list[dict[str, object]] = []
    for i, entry in enumerate(rules):
        if not isinstance(entry, dict):
            raise RoutingRuleParseError(
                f"{file}: rules[{i}] must be a mapping; got {type(entry).__name__}"
            )
        typed_rules.append(entry)
    return typed_rules


def _build_rules(
    raw_rules: list[dict[str, object]],
    *,
    known_agents: frozenset[str] | None,
    file: Path,
) -> tuple[RoutingRule, ...]:
    """Validate each raw rule + dedup-check rule_ids + agent-id check."""
    out: list[RoutingRule] = []
    seen_ids: set[str] = set()
    for i, entry in enumerate(raw_rules):
        try:
            rule = RoutingRule.model_validate(entry)
        except Exception as exc:  # pydantic.ValidationError + others
            raise RoutingRuleParseError(f"{file}: rules[{i}] failed validation: {exc}") from exc

        if rule.rule_id in seen_ids:
            raise RoutingRuleParseError(f"{file}: duplicate rule_id {rule.rule_id!r} at rules[{i}]")
        seen_ids.add(rule.rule_id)

        if known_agents is not None and rule.target_agent not in known_agents:
            raise RoutingRuleParseError(
                f"{file}: rules[{i}] target_agent={rule.target_agent!r} not in known_agents"
            )
        out.append(rule)

    return tuple(out)


__all__ = ["RoutingRuleParseError", "load_routing_rules"]
