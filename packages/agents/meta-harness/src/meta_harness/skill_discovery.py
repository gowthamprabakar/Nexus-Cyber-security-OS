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

import logging
import traceback
from collections.abc import Iterable
from dataclasses import dataclass, replace
from importlib.metadata import EntryPoint, entry_points
from pathlib import Path
from typing import TypedDict

from charter.audit import AuditLog
from charter.nlah_loader import (
    SkillMetadataEntry,
    load_skill_metadata_index,
)
from shared.skill_telemetry import ACTION_META_HARNESS_SKILL_EFFECTIVENESS_ERROR

from meta_harness.effectiveness_store import get_effectiveness_score

_logger = logging.getLogger(__name__)

_DEFAULT_TENANT_ID = "default"


class _EffectivenessFields(TypedDict):
    """The three Task 4 ``SkillMetadataEntry`` effectiveness fields, as a
    mapping ready for ``dataclasses.replace(entry, **fields)``."""

    effectiveness_score: float | None
    effectiveness_confidence: float | None
    effectiveness_last_updated: str | None


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
    audit_log: AuditLog,
    skills_overlay: Path | str | None = None,
    tenant_id: str = _DEFAULT_TENANT_ID,
) -> AgentSkillRegistry:
    """Build one agent's registry (bundled merged with overlay), enriched
    with G1 effectiveness scores (G2 Task 5).

    When ``skills_overlay`` is ``None`` the default per-agent shadow
    path is used; pass it explicitly to override (tests, non-default
    candidate paths).

    A non-existent overlay directory is treated as "no overlay" — the
    registry's ``skills_overlay`` field is ``None`` in that case.

    Each Level 0 entry's ``effectiveness_*`` fields are populated from
    G1's ``get_effectiveness_score`` (Task 4 schema). Skills with no G1
    score keep ``None`` values; a G1 read failure is emitted to
    ``audit_log`` as ``meta_harness.skill.effectiveness_error`` and also
    falls back to ``None`` values (CF #2 graceful-degradation pattern).
    ``audit_log`` is required so the failure path always has a sink.
    """
    nlah_dir = default_bundled_nlah_dir(workspace_root, agent_id)
    overlay_path = (
        Path(skills_overlay)
        if skills_overlay is not None
        else default_shadow_skills_dir(workspace_root, agent_id)
    )
    overlay_active = overlay_path if overlay_path.is_dir() else None
    entries = load_skill_metadata_index(nlah_dir, skills_overlay=overlay_active)
    # G2 Task 5 — enrich with G1 effectiveness data (no-op when scores absent).
    workspace = Path(workspace_root)
    entries = tuple(
        replace(
            e,
            **_enrich_with_effectiveness(
                e.skill_id,
                agent_id,
                audit_log=audit_log,
                workspace_root=workspace,
                tenant_id=tenant_id,
            ),
        )
        for e in entries
    )
    return AgentSkillRegistry(
        agent_id=agent_id,
        nlah_dir=nlah_dir,
        skills_overlay=overlay_active,
        entries=entries,
    )


def _enrich_with_effectiveness(
    skill_id: str,
    agent_id: str,
    *,
    audit_log: AuditLog,
    workspace_root: Path,
    tenant_id: str = _DEFAULT_TENANT_ID,
) -> _EffectivenessFields:
    """Look up a skill's G1 effectiveness score → Level 0 metadata fields.

    Returns a mapping of the three ``SkillMetadataEntry`` effectiveness
    fields, suitable for ``dataclasses.replace(entry, **result)``:

    * G1 score present  → populated from ``EffectivenessScore``.
    * No G1 score        → all three fields ``None`` (backwards-compat:
      skills predating G1, or agents not emitting effectiveness data).
    * G1 read failure    → emit ``meta_harness.skill.effectiveness_error``
      to ``audit_log`` and return all-``None`` fields (CF #2 pattern;
      effectiveness data must never break skill discovery).

    Read-only G1 consumer — never writes G1 state. ``get_effectiveness_score``
    already returns ``None`` for absent / unparseable / wrong-tenant
    sidecars; the ``try`` here guards against *unexpected* read failures
    (e.g. filesystem errors) so discovery degrades gracefully.
    """
    none_fields: _EffectivenessFields = {
        "effectiveness_score": None,
        "effectiveness_confidence": None,
        "effectiveness_last_updated": None,
    }
    try:
        score = get_effectiveness_score(
            skill_id,
            agent_id,
            workspace_root=workspace_root,
            tenant_id=tenant_id,
        )
    except Exception as exc:  # CF #2: never let a G1 read failure break discovery
        _logger.warning(
            "G1 effectiveness read failed for skill_id=%s agent_id=%s: %s",
            skill_id,
            agent_id,
            exc,
        )
        audit_log.append(
            ACTION_META_HARNESS_SKILL_EFFECTIVENESS_ERROR,
            {
                "skill_id": skill_id,
                "agent_id": agent_id,
                "tenant_id": tenant_id,
                "error_type": "effectiveness_read_failed",
                "exception_message": str(exc),
                "stack_trace": traceback.format_exc(),
            },
        )
        return none_fields
    if score is None:
        return none_fields
    return {
        "effectiveness_score": score.global_score,
        "effectiveness_confidence": score.confidence,
        "effectiveness_last_updated": (
            score.computed_at.isoformat() if score.computed_at else None
        ),
    }


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
    audit_log: AuditLog,
    skills_overlay_root: Path | str | None = None,
    agent_filter: Iterable[str] | None = None,
    tenant_id: str = _DEFAULT_TENANT_ID,
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

    ``audit_log`` and ``tenant_id`` thread through to
    ``discover_agent_skills`` for G1 effectiveness enrichment (Task 5).
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
            audit_log=audit_log,
            skills_overlay=per_agent_overlay,
            tenant_id=tenant_id,
        )
    return registries


__all__ = [
    "AgentSkillRegistry",
    "default_bundled_nlah_dir",
    "default_shadow_skills_dir",
    "discover_agent_skills",
    "discover_all_agent_skills",
]
