"""agentskills.io YAML-frontmatter parser + writer — Task 3 of A.4 v0.2.

A Nexus skill is a single ``SKILL.md`` file with two parts:

1. **YAML frontmatter** (between leading + trailing ``---`` fences) —
   carries agentskills.io required fields (``name`` / ``description`` /
   ``version`` / ``platforms``) plus the Nexus-specific extensions
   (``target_agent`` / ``category`` / ``created_by`` / ``provenance`` /
   ``eval_gate_status`` / ``deployment_status``). Per Q2 of the v0.2
   plan + the ADR-007 v1.4 amendment landing in Task 4.
2. **Markdown body** — everything after the closing ``---`` fence.
   Free-form procedural content the LLM reads at Level 1.

This module is the *only* place ``SKILL.md`` text touches the
filesystem. ``skill_writer`` (Task 7) calls ``write_skill_md`` to
emit candidates to the shadow path; ``skill_discovery`` (Task 5)
calls ``parse_skill_md`` to load deployed skills.

**Read-only against speculation.** No fabric, no LLM, no agent
state. Pure-function over text. Q-ARCH-1 / WI-6 carry-forward.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from meta_harness.schemas import (
    Skill,
    SkillDeploymentStatus,
    SkillEvalGateStatus,
)

_FRONTMATTER_RE = re.compile(
    r"\A\s*---\s*\n(?P<frontmatter>.*?)\n---\s*(?:\n(?P<body>.*))?\Z", re.DOTALL
)


class SkillFormatError(ValueError):
    """Raised when a ``SKILL.md`` file violates the agentskills.io contract."""


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


def parse_skill_md(path: Path | str) -> Skill:
    """Parse a ``SKILL.md`` file into a validated ``Skill`` instance."""
    file = Path(path)
    if not file.is_file():
        raise SkillFormatError(f"SKILL.md not found: {file}")
    text = file.read_text(encoding="utf-8")
    return parse_skill_md_content(text, source=str(file))


def parse_skill_md_content(text: str, *, source: str = "<string>") -> Skill:
    """Parse SKILL.md text (frontmatter + body) into a validated ``Skill``."""
    match = _FRONTMATTER_RE.match(text)
    if match is None:
        raise SkillFormatError(
            f"{source}: missing YAML frontmatter (expected document to start with '---')"
        )

    try:
        parsed = yaml.safe_load(match.group("frontmatter"))
    except yaml.YAMLError as exc:
        raise SkillFormatError(f"{source}: malformed YAML frontmatter: {exc}") from exc

    if not isinstance(parsed, dict):
        raise SkillFormatError(
            f"{source}: frontmatter must be a YAML mapping; got {type(parsed).__name__}"
        )

    body = match.group("body") or ""
    return _build_skill(parsed, body=body, source=source)


def _build_skill(frontmatter: dict[str, Any], *, body: str, source: str) -> Skill:
    """Validate frontmatter + pass through pydantic for full enforcement."""
    required = (
        "name",
        "description",
        "version",
        "platforms",
        "target_agent",
        "category",
        "created_by",
    )
    missing = [key for key in required if key not in frontmatter]
    if missing:
        raise SkillFormatError(f"{source}: frontmatter missing required keys: {', '.join(missing)}")

    # Coerce known structured fields.
    platforms_raw = frontmatter.get("platforms")
    if not isinstance(platforms_raw, list):
        raise SkillFormatError(
            f"{source}: 'platforms' must be a list; got {type(platforms_raw).__name__}"
        )

    provenance_raw = frontmatter.get("provenance") or []
    if not isinstance(provenance_raw, list):
        raise SkillFormatError(
            f"{source}: 'provenance' must be a list; got {type(provenance_raw).__name__}"
        )
    provenance_pairs: list[tuple[str, str]] = []
    for i, entry in enumerate(provenance_raw):
        if not isinstance(entry, list) or len(entry) != 2:
            raise SkillFormatError(
                f"{source}: provenance[{i}] must be a 2-item list [audit_log_path, entry_hash]"
            )
        path_part, hash_part = entry
        provenance_pairs.append((str(path_part), str(hash_part)))

    eval_gate_status_raw = frontmatter.get("eval_gate_status", "not_run")
    deployment_status_raw = frontmatter.get("deployment_status", "candidate")
    try:
        eval_gate_status = SkillEvalGateStatus(str(eval_gate_status_raw))
    except ValueError as exc:
        raise SkillFormatError(
            f"{source}: eval_gate_status={eval_gate_status_raw!r} not in "
            f"{[s.value for s in SkillEvalGateStatus]}"
        ) from exc
    try:
        deployment_status = SkillDeploymentStatus(str(deployment_status_raw))
    except ValueError as exc:
        raise SkillFormatError(
            f"{source}: deployment_status={deployment_status_raw!r} not in "
            f"{[s.value for s in SkillDeploymentStatus]}"
        ) from exc

    try:
        return Skill(
            name=str(frontmatter["name"]),
            description=str(frontmatter["description"]),
            version=str(frontmatter["version"]),
            platforms=tuple(str(p) for p in platforms_raw),
            target_agent=str(frontmatter["target_agent"]),
            category=str(frontmatter["category"]),
            created_by=str(frontmatter["created_by"]),
            provenance=tuple(provenance_pairs),
            eval_gate_status=eval_gate_status,
            deployment_status=deployment_status,
            body=body,
        )
    except Exception as exc:
        raise SkillFormatError(f"{source}: pydantic validation failed: {exc}") from exc


# ---------------------------------------------------------------------------
# Writer
# ---------------------------------------------------------------------------


def serialize_skill_md(skill: Skill) -> str:
    """Render a ``Skill`` instance back to ``SKILL.md`` text.

    Round-trip safe: ``parse_skill_md_content(serialize_skill_md(skill))``
    produces a Skill equivalent to ``skill`` for all frontmatter fields
    + body. The serialised form uses block YAML for readability;
    operators read these files in git diffs.
    """
    frontmatter = {
        "name": skill.name,
        "description": skill.description,
        "version": skill.version,
        "platforms": list(skill.platforms),
        "target_agent": skill.target_agent,
        "category": skill.category,
        "created_by": skill.created_by,
        "provenance": [list(entry) for entry in skill.provenance],
        "eval_gate_status": skill.eval_gate_status.value,
        "deployment_status": skill.deployment_status.value,
    }
    yaml_text = yaml.safe_dump(
        frontmatter,
        default_flow_style=False,
        sort_keys=False,
        allow_unicode=True,
    ).rstrip()
    body = skill.body
    # Trailing newline on body keeps the file POSIX-clean.
    if body and not body.endswith("\n"):
        body = body + "\n"
    return f"---\n{yaml_text}\n---\n\n{body}"


def write_skill_md(skill: Skill, path: Path | str) -> Path:
    """Render ``skill`` and write to ``path``; returns the resolved path.

    The parent directory is created if it doesn't exist. Used by
    ``skill_writer`` (Task 7) to emit candidates to the shadow path
    and by ``skill_approval`` (Task 10) to promote candidates to
    the canonical location.
    """
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(serialize_skill_md(skill), encoding="utf-8")
    return target


__all__ = [
    "SkillFormatError",
    "parse_skill_md",
    "parse_skill_md_content",
    "serialize_skill_md",
    "write_skill_md",
]
