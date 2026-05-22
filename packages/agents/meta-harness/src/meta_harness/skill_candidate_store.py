"""Sidecar metadata for candidate skills — Task 15 of A.4 v0.2.

Task 7's ``write_skill_candidate`` writes the shadow ``SKILL.md`` but
the ``SkillCandidate`` pydantic object carries fields the SKILL.md
frontmatter doesn't (notably ``tool_sequence_hash`` and
``emitted_at``). Task 15's CLI subcommands (``approve-skill`` /
``reject-skill`` / ``list-skills``) need to *reconstruct* a
``SkillCandidate`` from disk; without a sidecar that carries the
out-of-band fields, the reconstruction would lose ``tool_sequence_hash``
and Task 9's registry could not record the deployment hash on
approval.

This module is the sidecar storage layer:

* ``compute_candidate_meta_path(workspace_root, agent_id, skill_id)``
  returns ``<workspace>/.nexus/candidate-skills/<agent>/<skill_id>/candidate_meta.json``.
* ``write_candidate_meta(candidate, workspace_root)`` serialises the
  ``SkillCandidate`` pydantic to that path.
* ``load_candidate_meta(workspace_root, agent_id, skill_id)``
  rehydrates the ``SkillCandidate``.
* ``find_candidate_by_skill_id(workspace_root, skill_id)`` walks every
  per-agent ``candidate-skills/<agent>/<skill_id>/`` directory and
  returns the matching candidate (CLI uses this when the operator
  passes only ``skill_id``).
* ``list_pending_candidates(workspace_root)`` returns every candidate
  currently in the shadow tree (skill_id + agent_id + path triple).

The sidecar is **additive** — Task 7 writes it alongside the SKILL.md,
Task 10's promotion deletes both sidecar and shadow on auto-deploy or
rejection. Backwards-compat with the v0.2 tests written before this
module: passing absence of the sidecar (legacy candidates) raises
``CandidateNotFoundError`` from ``load_candidate_meta`` rather than
silently producing a malformed candidate.
"""

from __future__ import annotations

import contextlib
from collections.abc import Iterator
from pathlib import Path

from pydantic import ValidationError

from meta_harness.schemas import SkillCandidate

_CANDIDATE_META_FILENAME = "candidate_meta.json"
_CANDIDATE_SKILLS_DIRNAME = "candidate-skills"


class CandidateNotFoundError(FileNotFoundError):
    """Raised when no candidate sidecar exists for a given skill_id."""


def compute_candidate_meta_path(
    *,
    workspace_root: Path | str,
    agent_id: str,
    skill_id: str,
) -> Path:
    """Path to the sidecar JSON beside the shadow SKILL.md."""
    return (
        Path(workspace_root)
        / ".nexus"
        / _CANDIDATE_SKILLS_DIRNAME
        / agent_id
        / skill_id
        / _CANDIDATE_META_FILENAME
    )


def write_candidate_meta(
    candidate: SkillCandidate,
    *,
    workspace_root: Path | str,
) -> Path:
    """Serialise ``candidate`` to its sidecar JSON path; return the path.

    Called by Task 7's ``write_skill_candidate`` right after the
    shadow SKILL.md write; ensures the CLI can rehydrate the
    candidate later.
    """
    path = compute_candidate_meta_path(
        workspace_root=workspace_root,
        agent_id=candidate.skill.target_agent,
        skill_id=candidate.skill_id,
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(candidate.model_dump_json(indent=2), encoding="utf-8")
    return path


def load_candidate_meta(
    *,
    workspace_root: Path | str,
    agent_id: str,
    skill_id: str,
) -> SkillCandidate:
    """Rehydrate a ``SkillCandidate`` from its sidecar JSON.

    Raises:
        CandidateNotFoundError: when no sidecar file exists.
        pydantic.ValidationError: when the sidecar file is malformed —
            propagated unchanged so the CLI surfaces a precise error.
    """
    path = compute_candidate_meta_path(
        workspace_root=workspace_root,
        agent_id=agent_id,
        skill_id=skill_id,
    )
    if not path.is_file():
        raise CandidateNotFoundError(
            f"candidate sidecar missing for agent_id={agent_id!r} skill_id={skill_id!r} at {path}"
        )
    return SkillCandidate.model_validate_json(path.read_text(encoding="utf-8"))


def find_candidate_by_skill_id(
    *,
    workspace_root: Path | str,
    skill_id: str,
) -> SkillCandidate:
    """Walk every per-agent shadow tree to find a candidate by skill_id.

    The CLI ``approve-skill`` / ``reject-skill`` commands take only a
    skill_id; this helper resolves the matching ``agent_id`` by
    walking ``<workspace>/.nexus/candidate-skills/<agent>/<skill_id>/``.

    Raises:
        CandidateNotFoundError: when no candidate matches; carries
        the skill_id + the searched root for operator debug.
    """
    root = Path(workspace_root) / ".nexus" / _CANDIDATE_SKILLS_DIRNAME
    if not root.is_dir():
        raise CandidateNotFoundError(
            f"no candidate-skills directory at {root}; skill_id={skill_id!r}"
        )
    for agent_dir in sorted(root.iterdir()):
        if not agent_dir.is_dir():
            continue
        meta = agent_dir / skill_id / _CANDIDATE_META_FILENAME
        if meta.is_file():
            try:
                return SkillCandidate.model_validate_json(meta.read_text(encoding="utf-8"))
            except ValidationError:
                continue  # malformed sidecar; keep searching
    raise CandidateNotFoundError(
        f"no pending candidate found with skill_id={skill_id!r} under {root}"
    )


def list_pending_candidates(
    workspace_root: Path | str,
) -> Iterator[SkillCandidate]:
    """Yield every candidate currently in the shadow tree.

    Used by ``meta-harness list-skills`` to show the operator what's
    pending. Iteration order is deterministic (sorted by agent_id,
    then skill_id).
    """
    root = Path(workspace_root) / ".nexus" / _CANDIDATE_SKILLS_DIRNAME
    if not root.is_dir():
        return
    for agent_dir in sorted(root.iterdir()):
        if not agent_dir.is_dir():
            continue
        for meta in sorted(agent_dir.rglob(_CANDIDATE_META_FILENAME)):
            try:
                yield SkillCandidate.model_validate_json(meta.read_text(encoding="utf-8"))
            except ValidationError:
                continue  # malformed sidecar; skip


def delete_candidate_meta(
    *,
    workspace_root: Path | str,
    agent_id: str,
    skill_id: str,
) -> None:
    """Remove the sidecar JSON and the enclosing skill directory.

    Called by ``_promote_to_canonical`` and ``reject_candidate`` to
    clean up alongside the shadow ``SKILL.md`` removal. Removes the
    ``candidate_meta.json`` file, then the per-skill directory, then
    the per-agent directory if empty. Does NOT raise if any of the
    paths are already gone (idempotent clean-up).
    """
    meta_path = compute_candidate_meta_path(
        workspace_root=workspace_root,
        agent_id=agent_id,
        skill_id=skill_id,
    )
    if meta_path.is_file():
        meta_path.unlink()
    skill_dir = meta_path.parent
    with contextlib.suppress(OSError):
        skill_dir.rmdir()
    agent_dir = skill_dir.parent
    with contextlib.suppress(OSError):
        agent_dir.rmdir()


__all__ = [
    "CandidateNotFoundError",
    "compute_candidate_meta_path",
    "delete_candidate_meta",
    "find_candidate_by_skill_id",
    "list_pending_candidates",
    "load_candidate_meta",
    "write_candidate_meta",
]
