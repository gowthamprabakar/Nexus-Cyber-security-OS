"""Customer tech-stack profile loading (D.8 v0.2 Task 11).

Loads the customer's tech stack (cloud providers / languages / frameworks /
containers) from ``customer_context.md`` YAML frontmatter. Per **Q4** the tech stack is
an **optional** input: when provided, `cve_relevant_to_stack` filters CVEs to the
stack; when absent, callers correlate broadly. The profile is loaded here; wiring the
filter into the continuous correlation pipeline is a later integration.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True, slots=True)
class TechStackProfile:
    cloud_providers: tuple[str, ...] = field(default_factory=tuple)
    languages: tuple[str, ...] = field(default_factory=tuple)
    frameworks: tuple[str, ...] = field(default_factory=tuple)
    containers: tuple[str, ...] = field(default_factory=tuple)

    @property
    def keywords(self) -> frozenset[str]:
        """The flat, lowercased keyword set across all categories."""
        return frozenset(
            k.lower()
            for k in (*self.cloud_providers, *self.languages, *self.frameworks, *self.containers)
        )


def _as_tuple(value: Any) -> tuple[str, ...]:
    if isinstance(value, str):
        return tuple(p.strip() for p in value.split(",") if p.strip())
    if isinstance(value, list):
        return tuple(str(p).strip() for p in value if str(p).strip())
    return ()


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


def load_tech_stack_profile(text: str) -> TechStackProfile | None:
    """Build a `TechStackProfile` from customer-context frontmatter, or `None` if no
    tech stack is declared."""
    ts = _extract_frontmatter(text).get("tech_stack")
    if not isinstance(ts, dict):
        return None
    profile = TechStackProfile(
        cloud_providers=_as_tuple(ts.get("cloud")),
        languages=_as_tuple(ts.get("languages")),
        frameworks=_as_tuple(ts.get("frameworks")),
        containers=_as_tuple(ts.get("containers")),
    )
    return profile if profile.keywords else None


def load_tech_stack_profile_from_path(path: Path) -> TechStackProfile | None:
    if not path.is_file():
        return None
    return load_tech_stack_profile(path.read_text(encoding="utf-8"))


def cve_relevant_to_stack(profile: TechStackProfile, description: str) -> bool:
    """Q4 filter: True iff any stack keyword appears in the CVE description (case-
    insensitive). Callers correlate broadly (skip this filter) when no profile is set."""
    text = description.lower()
    return any(kw in text for kw in profile.keywords)
