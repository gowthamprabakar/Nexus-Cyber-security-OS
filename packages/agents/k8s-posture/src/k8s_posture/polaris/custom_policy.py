"""Polaris custom-policy support (D.6 v0.2 Task 7).

Loads **custom Polaris policies** from the customer profile (`customer_context.md` YAML
frontmatter) — per-check enable/disable + severity overrides — and exposes a `PolicyOverlay`
the live scan path applies on top of the default checks. Additive: the v0.1 default
behavior is preserved when no custom policies are declared.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import yaml


@dataclass(frozen=True, slots=True)
class PolarisPolicy:
    check_id: str
    severity: str = "warning"
    enabled: bool = True


def parse_custom_policies(raw_policies: list[dict[str, Any]]) -> tuple[PolarisPolicy, ...]:
    """Parse raw policy dicts (``check_id`` / ``severity`` / ``enabled``); entries without
    a check_id are skipped."""
    out: list[PolarisPolicy] = []
    for r in raw_policies:
        check_id = r.get("check_id")
        if not isinstance(check_id, str) or not check_id:
            continue
        out.append(
            PolarisPolicy(
                check_id=check_id,
                severity=str(r.get("severity", "warning")),
                enabled=bool(r.get("enabled", True)),
            )
        )
    return tuple(out)


def _extract_frontmatter(text: str) -> dict[str, Any]:
    stripped = text.lstrip()
    if not stripped.startswith("---"):
        return {}
    body = stripped[3:]
    end = body.find("\n---")
    if end == -1:
        return {}
    try:
        data = yaml.safe_load(body[:end])
    except yaml.YAMLError:
        return {}
    return data if isinstance(data, dict) else {}


def load_custom_policies(text: str) -> tuple[PolarisPolicy, ...]:
    """Load custom Polaris policies from ``customer_context.md`` frontmatter (the
    ``polaris_policies:`` list); `()` if none declared."""
    raw = _extract_frontmatter(text).get("polaris_policies")
    return parse_custom_policies(raw) if isinstance(raw, list) else ()


class PolicyOverlay:
    """Applies custom policies on top of the defaults — per-check enable/severity lookups."""

    __slots__ = ("_by_id",)

    def __init__(self, policies: tuple[PolarisPolicy, ...] = ()) -> None:
        self._by_id = {p.check_id: p for p in policies}

    def is_enabled(self, check_id: str, *, default: bool = True) -> bool:
        policy = self._by_id.get(check_id)
        return policy.enabled if policy is not None else default

    def severity_for(self, check_id: str, *, default: str) -> str:
        policy = self._by_id.get(check_id)
        return policy.severity if policy is not None else default
