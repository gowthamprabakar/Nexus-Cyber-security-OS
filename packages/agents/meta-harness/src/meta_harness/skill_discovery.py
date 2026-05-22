"""Per-agent skill discovery — Task 5 of A.4 v0.2.

Walks every agent's ``nlah/skills/`` subdir and cross-references with
the shadow-path overlay. Produces an ``AgentSkillRegistry`` that A.4's
later stages (Task 6 SKILL_TRIGGER novelty check, Task 8 eval-gate
overlay context, Task 9 first-of-class registry) build on.

Two layers of discovery, mirroring the v0.1 ``batch_eval`` shape:

1. **Entry-point discovery.** Agents register via the
   ``nexus_eval_runners`` group in their ``pyproject.toml``;
   ``discover_all_agent_skills`` walks every registered name to find
   target agents (matches ``batch.BatchEvalRunner._discover_entry_points``
   for stable lexicographic ordering).

2. **Per-agent skill walk.** For each ``agent_id``, resolve the agent's
   nlah directory via the workspace-relative convention
   ``<workspace>/packages/agents/<kebab>/src/<snake>/nlah`` (same shape
   as ``agent.default_nlah_dir_resolver``) and call
   ``charter.nlah_loader.load_skill_metadata_index`` to get the merged
   (bundled + overlay) metadata index.

Overlay path convention (Q1 of the v0.2 plan):
``<workspace>/.nexus/candidate-skills/<agent_id>/<category>/<skill>/SKILL.md``.
Overlay precedence matches ``charter.nlah_loader``'s contract — the
candidate shadow masks the bundled version when both share a
``skill_id``.

Backwards-compat (drift #5 of the v0.2 plan): agents with no skills
dir produce an empty registry. No errors, no warnings — v0.1 agents
behave exactly as before.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from importlib.metadata import EntryPoint, entry_points
from pathlib import Path

from charter.nlah_loader import (
    SkillMetadataEntry,
    load_skill_metadata_index,
)

_ENTRY_POINT_GROUP = "nexus_eval_runners"
_SHADOW_ROOT_NAME = ".nexus"
_SHADOW_SKILLS_DIRNAME = "candidate-skills"


@dataclass(frozen=True)
class AgentSkillRegistry:
    """Per-agent skill registry — bundled + overlay merged with overlay precedence.

    Source-of-truth for "what skills can this agent see right now."
    Used by Task 6's novelty check (compare candidate against
    ``entries``), Task 8's eval-gate (``skills_overlay`` threads through
    to the eval runner), and Task 9's first-of-class registry
    (``categories``).
    """

    agent_id: str
    nlah_dir: Path
    skills_overlay: Path | None
    entries: tuple[SkillMetadataEntry, ...]

    @property
    def bundled_entries(self) -> tuple[SkillMetadataEntry, ...]:
        return tuple(e for e in self.entries if e.source == "bundled")

    @property
    def overlay_entries(self) -> tuple[SkillMetadataEntry, ...]:
        return tuple(e for e in self.entries if e.source == "overlay")

    @property
    def categories(self) -> tuple[str, ...]:
        """Deterministic set of categories visible in the registry."""
        return tuple(sorted({e.category for e in self.entries}))


def default_bundled_nlah_dir(workspace_root: Path | str, agent_id: str) -> Path:
    """Return ``<workspace>/packages/agents/<kebab>/src/<snake>/nlah``.

    Matches ``meta_harness.agent.default_nlah_dir_resolver`` so the v0.1
    bundled-NLAH path and the v0.2 bundled-skills path share a single
    convention.
    """
    dirname = agent_id.replace("_", "-")
    return Path(workspace_root) / "packages" / "agents" / dirname / "src" / agent_id / "nlah"


def default_shadow_skills_dir(workspace_root: Path | str, agent_id: str) -> Path:
    """Per-agent shadow overlay root.

    Returns ``<workspace>/.nexus/candidate-skills/<agent_id>``. Skills
    beneath it are laid out as ``<category>/<skill>/SKILL.md`` — the
    same shape as the bundled ``nlah/skills/`` tree, so the path can be
    passed verbatim as ``charter.nlah_loader.load_skill_metadata_index``'s
    ``skills_overlay`` argument.
    """
    return Path(workspace_root) / _SHADOW_ROOT_NAME / _SHADOW_SKILLS_DIRNAME / agent_id


def discover_agent_skills(
    agent_id: str,
    *,
    workspace_root: Path | str,
    skills_overlay: Path | str | None = None,
) -> AgentSkillRegistry:
    """Build one agent's registry (bundled merged with overlay).

    When ``skills_overlay`` is ``None`` the default per-agent shadow
    path is used; pass it explicitly to override (tests, non-default
    candidate paths).

    A non-existent overlay directory is treated as "no overlay" — the
    registry's ``skills_overlay`` field is ``None`` in that case.
    """
    nlah_dir = default_bundled_nlah_dir(workspace_root, agent_id)
    overlay_path = (
        Path(skills_overlay)
        if skills_overlay is not None
        else default_shadow_skills_dir(workspace_root, agent_id)
    )
    overlay_active = overlay_path if overlay_path.is_dir() else None
    entries = load_skill_metadata_index(nlah_dir, skills_overlay=overlay_active)
    return AgentSkillRegistry(
        agent_id=agent_id,
        nlah_dir=nlah_dir,
        skills_overlay=overlay_active,
        entries=entries,
    )


def _discover_entry_points(
    *,
    agent_filter: Iterable[str] | None = None,
) -> list[EntryPoint]:
    """Walk the ``nexus_eval_runners`` group; stable lexicographic order."""
    filter_set = set(agent_filter) if agent_filter is not None else None
    eps = entry_points(group=_ENTRY_POINT_GROUP)
    selected = [ep for ep in eps if filter_set is None or ep.name in filter_set]
    selected.sort(key=lambda ep: ep.name)
    return selected


def discover_all_agent_skills(
    *,
    workspace_root: Path | str,
    skills_overlay_root: Path | str | None = None,
    agent_filter: Iterable[str] | None = None,
) -> dict[str, AgentSkillRegistry]:
    """Walk every ``nexus_eval_runners`` entry point and build per-agent registries.

    Returns a dict keyed by ``agent_id`` (lexicographically ordered via
    Python 3.7+ insertion-ordered dicts). Agents with no skills dir
    produce empty registries.

    ``skills_overlay_root`` is treated as the parent of per-agent
    shadows — each agent's overlay path becomes
    ``<skills_overlay_root>/<agent_id>``. When ``None``, each agent
    falls back to ``default_shadow_skills_dir`` per the workspace
    convention.
    """
    eps = _discover_entry_points(agent_filter=agent_filter)
    registries: dict[str, AgentSkillRegistry] = {}
    for ep in eps:
        per_agent_overlay = (
            Path(skills_overlay_root) / ep.name if skills_overlay_root is not None else None
        )
        registries[ep.name] = discover_agent_skills(
            ep.name,
            workspace_root=workspace_root,
            skills_overlay=per_agent_overlay,
        )
    return registries


__all__ = [
    "AgentSkillRegistry",
    "default_bundled_nlah_dir",
    "default_shadow_skills_dir",
    "discover_agent_skills",
    "discover_all_agent_skills",
]
