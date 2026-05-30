"""Concatenate an NLAH directory into a single LLM system prompt.

**Per ADR-007 v1.2** (post-D.2 amendment): hoisted from per-agent
`nlah_loader.py` copies once cloud-posture + vulnerability + identity
all shipped materially identical implementations. ADR-007 v1.1's
"amend on the third duplicate" discipline triggers this consolidation
before a fourth agent (D.3) would inherit the duplication.

Agents now ship a thin shim that binds their own `__file__` to
discover the local `nlah/` directory; the load logic lives here.

Concatenation order (unchanged from the per-agent copies):

1. `README.md`            (canonical NLAH — required)
2. `tools.md`             (tool index — optional)
3. `examples/*.md`        (few-shot examples, lexicographic — optional)

The legacy zero-argument `default_nlah_dir()` of the per-agent shims
maps onto `default_nlah_dir(__file__)` here, where `__file__` is the
calling module's path. Tests pass an explicit `nlah_dir` to exercise
the loader against synthetic content.

**Per ADR-007 v1.4** (2026-05-22 amendment): the progressive-
disclosure skill-loader extension lands here, additive to the v1.2
NLAH-loader surface. ``default_nlah_dir`` and ``load_system_prompt``
are unchanged; the v1.4 surface adds ``default_skills_dir`` +
``load_skill_metadata_index`` (Level 0) + ``load_skill`` (Level 1)
+ ``load_skill_reference`` (Level 2) so any agent can opt-in to
SKILL.md-based procedural memory without disturbing v1.2 consumers.
See `docs/_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md`
§v1.4 for the architectural rationale + agentskills.io conformance.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

_TOOLS_HEADER = "\n\n---\n\n# Tools reference\n\n"
_EXAMPLES_HEADER = "\n\n---\n\n# Few-shot examples\n"

# ADR-007 v1.4 — progressive-disclosure skill loader.
#
# Each SKILL.md file is parsed for two things only by the substrate:
#  (1) YAML frontmatter — extracted into a SkillMetadataEntry for
#      Level 0; the raw text is returned at Level 1 so each agent
#      can apply its own typed parser (e.g. meta_harness.skill_format).
#  (2) Markdown body — included in the Level 1 return value but not
#      structurally interpreted here.
#
# This keeps charter dumb (no pydantic dependency, no Skill type
# bound to A.4) while still surfacing the metadata index agents
# need to pick a skill before paying the Level 1 token cost.
_SKILL_FRONTMATTER_RE = re.compile(r"\A\s*---\s*\n(?P<frontmatter>.*?)\n---\s*(?:\n|$)", re.DOTALL)

_REQUIRED_SKILL_FRONTMATTER_KEYS = (
    "name",
    "description",
    "version",
    "platforms",
    "target_agent",
    "category",
)


def default_nlah_dir(package_file: str | Path) -> Path:
    """Return the `nlah/` directory adjacent to `package_file`.

    Callers pass their own `__file__`:

        from charter.nlah_loader import default_nlah_dir
        NLAH_DIR = default_nlah_dir(__file__)
    """
    return Path(package_file).parent / "nlah"


def load_system_prompt(nlah_dir: Path | str) -> str:
    """Build the LLM system prompt by concatenating `nlah_dir`'s contents.

    Raises:
        FileNotFoundError: if `nlah_dir` is missing or has no `README.md`.
    """
    base = Path(nlah_dir)
    if not base.is_dir():
        raise FileNotFoundError(f"NLAH directory missing: {base}")
    readme = base / "README.md"
    if not readme.is_file():
        raise FileNotFoundError(f"NLAH/README.md missing in {base}")

    parts: list[str] = [readme.read_text(encoding="utf-8")]

    tools = base / "tools.md"
    if tools.is_file():
        parts.append(_TOOLS_HEADER + tools.read_text(encoding="utf-8"))

    examples_dir = base / "examples"
    if examples_dir.is_dir():
        example_files = sorted(examples_dir.glob("*.md"))
        if example_files:
            parts.append(_EXAMPLES_HEADER)
            for example in example_files:
                parts.append("\n\n" + example.read_text(encoding="utf-8"))

    return "".join(parts)


# ---------------------------------------------------------------------------
# ADR-007 v1.4 — progressive-disclosure skill loader (additive)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SkillMetadataEntry:
    """Level 0 metadata-index row for one SKILL.md file.

    Minimal shape — only the fields an agent's LLM needs to decide
    *which* skill to load at Level 1. The full SKILL.md text comes
    back from ``load_skill`` once the LLM has picked.

    Per ADR-007 v1.4 / Q2 of A.4 Meta-Harness v0.2.
    """

    skill_id: str  # ``<category>/<skill-name>`` relative to the skills dir
    name: str
    description: str
    version: str
    category: str
    target_agent: str
    platforms: tuple[str, ...]
    source: str  # "bundled" (in nlah_dir/skills) or "overlay" (skills_overlay)
    # G2 Task 4 — effectiveness fields (per G2-Q2 Hermes-pattern selection).
    # Populated by meta_harness.effectiveness_store in Task 5.
    effectiveness_score: float | None = None
    """Composite effectiveness score from G1 (0.0-1.0). None if not yet computed."""
    effectiveness_confidence: float | None = None
    """Composite confidence score from G1 (0.0-1.0). None if no data yet."""
    effectiveness_last_updated: str | None = None
    """ISO 8601 timestamp of last effectiveness score update. None if never computed."""


class SkillLoaderError(ValueError):
    """Raised when a SKILL.md file under a skills directory violates the
    ADR-007 v1.4 contract (missing frontmatter, missing required keys,
    malformed YAML)."""


def default_skills_dir(package_file: str | Path) -> Path:
    """Return the `nlah/skills/` directory adjacent to `package_file`.

    Sibling helper to ``default_nlah_dir``. The agent's progressive-
    disclosure loader binds its own ``__file__`` to discover the local
    skill library:

        from charter.nlah_loader import default_skills_dir
        SKILLS_DIR = default_skills_dir(__file__)
    """
    return Path(package_file).parent / "nlah" / "skills"


def load_skill_metadata_index(
    nlah_dir: Path | str,
    *,
    skills_overlay: Path | str | None = None,
) -> tuple[SkillMetadataEntry, ...]:
    """Level 0 — return lightweight metadata for every shipped + overlay skill.

    Walks ``<nlah_dir>/skills/<category>/<skill-name>/SKILL.md`` and
    (when provided) ``<skills_overlay>/<category>/<skill-name>/SKILL.md``,
    parses each YAML frontmatter, and returns a tuple of
    ``SkillMetadataEntry``. Entries from the overlay carry
    ``source="overlay"``; entries from the bundled tree carry
    ``source="bundled"``.

    The overlay is the eval-gate's ``with_candidate_skill_overlay``
    surface — A.4 v0.2 threads the shadow path through here when
    running the target agent's eval suite with a candidate loaded.

    **Backwards-compat:** when ``<nlah_dir>/skills/`` does not exist,
    returns an empty tuple. v0.1 agents that ship no skills dir
    behave exactly as they did before — no error, no warning. WI-4
    backwards-compat guarantee (drift #5 of the A.4 v0.2 plan).

    Raises ``SkillLoaderError`` only when a SKILL.md file is present
    but malformed.
    """
    bundled = Path(nlah_dir) / "skills"
    overlay = Path(skills_overlay) if skills_overlay is not None else None

    entries: list[SkillMetadataEntry] = []
    seen_ids: set[str] = set()

    # Overlay entries take precedence (eval-gate candidate context):
    # walk overlay first so a same-skill_id in the bundled tree is
    # masked by the overlay version.
    if overlay is not None and overlay.is_dir():
        for path in _iter_skill_md_files(overlay):
            entry = _parse_skill_metadata(path, base=overlay, source="overlay")
            seen_ids.add(entry.skill_id)
            entries.append(entry)

    if bundled.is_dir():
        for path in _iter_skill_md_files(bundled):
            entry = _parse_skill_metadata(path, base=bundled, source="bundled")
            if entry.skill_id in seen_ids:
                continue
            entries.append(entry)

    return tuple(sorted(entries, key=lambda e: e.skill_id))


def load_skill(
    nlah_dir: Path | str,
    skill_id: str,
    *,
    skills_overlay: Path | str | None = None,
) -> str:
    """Level 1 — return the full SKILL.md text for a single skill.

    Resolution order:
    1. ``<skills_overlay>/<skill_id>/SKILL.md`` (if overlay provided).
    2. ``<nlah_dir>/skills/<skill_id>/SKILL.md``.

    Raises ``FileNotFoundError`` if neither path resolves.

    The returned string is the verbatim SKILL.md content (frontmatter
    + body). Callers that want typed parsing pass the text into their
    own parser (e.g. ``meta_harness.skill_format.parse_skill_md_content``).
    """
    target = _resolve_skill_path(
        nlah_dir=nlah_dir,
        skill_id=skill_id,
        skills_overlay=skills_overlay,
        filename="SKILL.md",
    )
    return target.read_text(encoding="utf-8")


def load_skill_reference(
    nlah_dir: Path | str,
    skill_id: str,
    ref_filename: str,
    *,
    skills_overlay: Path | str | None = None,
) -> str:
    """Level 2 — return the content of one ``references/<ref_filename>``
    file beneath the skill's directory.

    Resolution order: overlay first, then bundled. Raises
    ``FileNotFoundError`` if the file doesn't exist in either tree.
    """
    target = _resolve_skill_path(
        nlah_dir=nlah_dir,
        skill_id=skill_id,
        skills_overlay=skills_overlay,
        filename=f"references/{ref_filename}",
    )
    return target.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Internal helpers — keep dumb; no pydantic, no Skill type
# ---------------------------------------------------------------------------


def _iter_skill_md_files(skills_root: Path) -> list[Path]:
    """Yield SKILL.md paths beneath ``skills_root`` in deterministic order."""
    if not skills_root.is_dir():
        return []
    return sorted(p for p in skills_root.rglob("SKILL.md") if p.is_file())


def _parse_skill_metadata(
    path: Path,
    *,
    base: Path,
    source: str,
) -> SkillMetadataEntry:
    """Parse the YAML frontmatter of one SKILL.md into a metadata row."""
    raw = path.read_text(encoding="utf-8")
    match = _SKILL_FRONTMATTER_RE.match(raw)
    if match is None:
        raise SkillLoaderError(f"{path}: missing YAML frontmatter (expected leading '---' fence)")
    try:
        parsed = yaml.safe_load(match.group("frontmatter"))
    except yaml.YAMLError as exc:
        raise SkillLoaderError(f"{path}: malformed YAML frontmatter: {exc}") from exc

    if not isinstance(parsed, dict):
        raise SkillLoaderError(
            f"{path}: frontmatter must be a YAML mapping; got {type(parsed).__name__}"
        )

    missing = [key for key in _REQUIRED_SKILL_FRONTMATTER_KEYS if key not in parsed]
    if missing:
        raise SkillLoaderError(f"{path}: frontmatter missing required keys: {', '.join(missing)}")

    platforms_raw = parsed["platforms"]
    if not isinstance(platforms_raw, list):
        raise SkillLoaderError(
            f"{path}: 'platforms' must be a list; got {type(platforms_raw).__name__}"
        )

    # skill_id is the relative path from skills_root to the skill's
    # parent dir: <category>/<skill-name>.
    skill_id = path.parent.relative_to(base).as_posix()

    return SkillMetadataEntry(
        skill_id=skill_id,
        name=str(parsed["name"]),
        description=str(parsed["description"]),
        version=str(parsed["version"]),
        category=str(parsed["category"]),
        target_agent=str(parsed["target_agent"]),
        platforms=tuple(str(p) for p in platforms_raw),
        source=source,
    )


def _resolve_skill_path(
    *,
    nlah_dir: Path | str,
    skill_id: str,
    skills_overlay: Path | str | None,
    filename: str,
) -> Path:
    """Find ``<skill_id>/<filename>`` in overlay first, then bundled tree."""
    candidates: list[Path] = []
    if skills_overlay is not None:
        candidates.append(Path(skills_overlay) / skill_id / filename)
    candidates.append(Path(nlah_dir) / "skills" / skill_id / filename)
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise FileNotFoundError(
        f"skill resource not found: skill_id={skill_id!r} filename={filename!r}; "
        f"searched: {[str(c) for c in candidates]}"
    )


# Reference the internal _parse_skill_metadata to satisfy strict
# linters; not exported.
_: Any = _parse_skill_metadata


__all__ = [
    "SkillLoaderError",
    "SkillMetadataEntry",
    "default_nlah_dir",
    "default_skills_dir",
    "load_skill",
    "load_skill_metadata_index",
    "load_skill_reference",
    "load_system_prompt",
]
