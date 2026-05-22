"""Skill-class registry — Task 9 of A.4 v0.2.

The persistent **source of truth** for two questions A.4 v0.2 asks
on every skill-lifecycle decision:

1. **Is this ``(agent_id, category)`` class already operator-approved?**
   (Q5 first-of-class gate.) Refinements of a registered class auto-
   deploy on eval-gate pass; a brand-new class requires operator
   approval before deployment.

2. **What ``tool_sequence_hash`` values are already deployed?**
   (Task 6 ``detect_skill_trigger`` input.) Task 6 stays decoupled
   from the registry — Task 13's driver wires this output to that
   input.

Lives at ``<workspace>/.nexus/skill-class-registry.json``. JSON
round-trips through frozen pydantic, so the registry survives process
restarts and CI workspace teardown.

Mutation API is **functional**: every mutator returns a new
``SkillClassRegistry``. Frozen-by-default keeps concurrent reads safe
and lets callers reason about state at the value level. Persistence
is explicit — call ``save_skill_class_registry`` after every mutation
the caller wants durable.

Re-registration is idempotent — re-calling ``register_class`` with an
already-registered ``(agent_id, category)`` returns the registry
unchanged, preserving the original ``first_approved_at`` and
``first_skill_id``. That's load-bearing for the audit trail: the
"first approval" stays pinned to the operator's actual first
decision.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from meta_harness.schemas import SkillClassKey

_REGISTRY_RELATIVE_PATH = Path(".nexus") / "skill-class-registry.json"


class SkillRegistryError(RuntimeError):
    """Raised when the registry cannot be loaded (malformed JSON) or a
    mutation precondition is violated (e.g. recording a deployment
    against an unregistered class)."""


class SkillClassRegistryEntry(BaseModel):
    """One ``(agent_id, category)`` class entry.

    Fields:
        first_approved_at: when the operator approved this class.
            Pinned at register-time; never updated.
        first_skill_id: which skill earned the first-of-class approval.
            Pinned at register-time; never updated.
        deployed_skill_ids: all skills currently deployed under this
            class. Includes ``first_skill_id``.
        deployed_tool_sequence_hashes: the Task 6 novelty-check input.
            One hash per deployed skill (1:1 with ``deployed_skill_ids``
            on initial deploys, but may diverge if a skill ships
            multiple versions — Task 6's novelty check fires on the
            hash, not the skill_id).
    """

    model_config = ConfigDict(frozen=True)

    agent_id: str = Field(min_length=1, max_length=64)
    category: str = Field(min_length=1, max_length=64)
    first_approved_at: datetime
    first_skill_id: str = Field(min_length=1, max_length=128)
    deployed_skill_ids: tuple[str, ...] = ()
    deployed_tool_sequence_hashes: tuple[str, ...] = ()

    @property
    def class_key(self) -> SkillClassKey:
        return SkillClassKey(agent_id=self.agent_id, category=self.category)


class SkillClassRegistry(BaseModel):
    """The persistent skill-class registry.

    ``entries`` is sorted by ``(agent_id, category)`` whenever the
    registry is constructed via the mutator functions in this module,
    so JSON serialisation is deterministic.
    """

    model_config = ConfigDict(frozen=True)

    entries: tuple[SkillClassRegistryEntry, ...] = ()

    def entry_for(self, agent_id: str, category: str) -> SkillClassRegistryEntry | None:
        for entry in self.entries:
            if entry.agent_id == agent_id and entry.category == category:
                return entry
        return None

    def is_class_registered(self, agent_id: str, category: str) -> bool:
        """Q5 first-of-class gate accessor — True iff the operator has
        approved this ``(agent_id, category)`` pair at least once."""
        return self.entry_for(agent_id, category) is not None

    def deployed_tool_sequence_hashes(
        self,
        agent_id: str | None = None,
    ) -> frozenset[str]:
        """Set of hashes currently deployed.

        Filtered by ``agent_id`` when supplied — that's the Task 6
        ``detect_skill_trigger`` input shape. Returns ``frozenset()``
        when no entries match.
        """
        hashes: set[str] = set()
        for entry in self.entries:
            if agent_id is not None and entry.agent_id != agent_id:
                continue
            hashes.update(entry.deployed_tool_sequence_hashes)
        return frozenset(hashes)


def compute_registry_path(workspace_root: Path | str) -> Path:
    """Return ``<workspace>/.nexus/skill-class-registry.json``."""
    return Path(workspace_root) / _REGISTRY_RELATIVE_PATH


def load_skill_class_registry(workspace_root: Path | str) -> SkillClassRegistry:
    """Read the registry from disk.

    Returns an empty ``SkillClassRegistry`` when the JSON file does not
    exist — that's the v0.2 first-run state. Raises
    ``SkillRegistryError`` when the file exists but is malformed.
    """
    path = compute_registry_path(workspace_root)
    if not path.is_file():
        return SkillClassRegistry()
    try:
        return SkillClassRegistry.model_validate_json(path.read_text(encoding="utf-8"))
    except ValidationError as exc:
        raise SkillRegistryError(f"malformed registry at {path}: {exc}") from exc


def save_skill_class_registry(
    registry: SkillClassRegistry,
    *,
    workspace_root: Path | str,
) -> Path:
    """Write the registry to disk; return the file path."""
    path = compute_registry_path(workspace_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(registry.model_dump_json(indent=2), encoding="utf-8")
    return path


def register_class(
    registry: SkillClassRegistry,
    *,
    agent_id: str,
    category: str,
    skill_id: str,
    tool_sequence_hash: str,
    approved_at: datetime,
) -> SkillClassRegistry:
    """Add a first-of-class entry.

    Idempotent — re-calling with an already-registered ``(agent_id,
    category)`` returns the registry unchanged. The original
    ``first_approved_at`` and ``first_skill_id`` stay pinned. Use
    ``record_deployment`` to register a refinement skill within an
    already-approved class.
    """
    if registry.entry_for(agent_id, category) is not None:
        return registry
    new_entry = SkillClassRegistryEntry(
        agent_id=agent_id,
        category=category,
        first_approved_at=approved_at,
        first_skill_id=skill_id,
        deployed_skill_ids=(skill_id,),
        deployed_tool_sequence_hashes=(tool_sequence_hash,),
    )
    new_entries = tuple(
        sorted(
            (*registry.entries, new_entry),
            key=lambda e: (e.agent_id, e.category),
        )
    )
    return SkillClassRegistry(entries=new_entries)


def record_deployment(
    registry: SkillClassRegistry,
    *,
    agent_id: str,
    category: str,
    skill_id: str,
    tool_sequence_hash: str,
) -> SkillClassRegistry:
    """Add a refinement deployment to an existing class entry.

    Raises ``SkillRegistryError`` when the class isn't registered yet —
    the caller MUST call ``register_class`` for the operator-approved
    first deployment before recording subsequent refinements.

    Idempotent on ``skill_id`` and ``tool_sequence_hash``: re-recording
    the same pair returns the registry unchanged.
    """
    existing = registry.entry_for(agent_id, category)
    if existing is None:
        raise SkillRegistryError(
            f"cannot record deployment for unregistered class "
            f"({agent_id!r}, {category!r}) — call register_class first"
        )

    skill_ids = tuple(dict.fromkeys((*existing.deployed_skill_ids, skill_id)))
    hashes = tuple(dict.fromkeys((*existing.deployed_tool_sequence_hashes, tool_sequence_hash)))
    if (
        skill_ids == existing.deployed_skill_ids
        and hashes == existing.deployed_tool_sequence_hashes
    ):
        return registry

    updated_entry = existing.model_copy(
        update={
            "deployed_skill_ids": skill_ids,
            "deployed_tool_sequence_hashes": hashes,
        }
    )
    new_entries = tuple(
        updated_entry if entry.agent_id == agent_id and entry.category == category else entry
        for entry in registry.entries
    )
    return SkillClassRegistry(entries=new_entries)


__all__ = [
    "SkillClassRegistry",
    "SkillClassRegistryEntry",
    "SkillRegistryError",
    "compute_registry_path",
    "load_skill_class_registry",
    "record_deployment",
    "register_class",
    "save_skill_class_registry",
]
