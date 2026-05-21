"""Read-only NLAH directory walker — Stage 1 INTROSPECT helper.

Walks an agent's ``nlah/`` directory per ADR-007 v1.2 conventions
and produces an ``AgentManifest``. The contract:

- ``README.md`` — required. Persona is extracted from its first
  non-heading paragraph.
- ``tools.md`` — optional. Declared tool names are parsed from
  level-2 headers shaped like ``## `tool_name(...)``` (the
  convention used by every agent shipped to date — see
  cloud-posture, vulnerability, identity, data-security, etc.).
- ``examples/*.md`` — optional. The file count is the example
  count (lexicographic order, ignored for the count itself).

Eval-case count is cross-referenced from each agent's
``eval/cases/*.yaml`` files when an ``eval/cases/`` directory
exists at the conventional location (sibling of ``src/<pkg>/``,
i.e. ``packages/agents/<agent>/eval/cases/``).

**Read-only contract.** Every read goes through
``Path.read_text(encoding="utf-8")`` — no ``open(..., "w"/"a"/"x")``
and no ``write_text`` / ``write_bytes`` call appears in this
module. The companion WI-4 integration test in
``tests/test_tools_nlah_parser.py`` patches ``Path.open`` and
``builtins.open`` to intercept any call that arrives with a
non-read mode while the parser runs against a real agent's NLAH
directory.

**Q-ARCH-2 reminder.** No bus / subject reference appears here;
this module is the read-only end of A.4's introspection surface.
"""

from __future__ import annotations

import re
from pathlib import Path

from meta_harness.schemas import AgentManifest

# Pattern for `## `tool_name(...)`` level-2 headers in tools.md.
# Captures the bare identifier before the open paren.
_TOOL_HEADER = re.compile(r"^##\s+`([A-Za-z_][A-Za-z0-9_]*)\s*\(", re.MULTILINE)

# Pattern for the agent README.md title (the first line `# ...`).
# Used only to skip when extracting persona.
_HEADING_LINE = re.compile(r"^#+\s")


class NlahParseError(ValueError):
    """Raised when an NLAH directory violates the ADR-007 v1.2 contract."""


def parse_nlah_dir(
    nlah_dir: Path | str,
    *,
    agent_id: str,
    eval_cases_dir: Path | str | None = None,
) -> AgentManifest:
    """Parse one agent's NLAH directory into an ``AgentManifest``.

    Args:
        nlah_dir: Path to the agent's ``nlah/`` directory.
        agent_id: The agent identifier (e.g. ``"cloud_posture"``).
            Surfaced verbatim on the resulting manifest.
        eval_cases_dir: Optional path to the agent's
            ``eval/cases/`` directory. When provided and the
            directory exists, the count of ``*.yaml`` files is
            recorded as ``eval_case_count``. When ``None`` or the
            directory is missing, ``eval_case_count`` is ``0``.

    Raises:
        NlahParseError: when the directory layout violates the
            ADR-007 v1.2 contract (no README.md, or README.md is
            empty).
    """
    base = Path(nlah_dir)
    if not base.is_dir():
        raise NlahParseError(f"NLAH directory missing: {base}")

    readme = base / "README.md"
    if not readme.is_file():
        raise NlahParseError(f"NLAH/README.md missing in {base}")

    readme_text = readme.read_text(encoding="utf-8")
    if not readme_text.strip():
        raise NlahParseError(f"NLAH/README.md is empty in {base}")

    persona = _extract_persona(readme_text)

    declared_tools: tuple[str, ...] = ()
    tools_md = base / "tools.md"
    if tools_md.is_file():
        declared_tools = _parse_declared_tools(tools_md.read_text(encoding="utf-8"))

    example_count = 0
    examples_dir = base / "examples"
    if examples_dir.is_dir():
        example_count = sum(1 for p in examples_dir.iterdir() if p.suffix == ".md" and p.is_file())

    eval_case_count = 0
    if eval_cases_dir is not None:
        cases_path = Path(eval_cases_dir)
        if cases_path.is_dir():
            eval_case_count = sum(
                1 for p in cases_path.iterdir() if p.suffix == ".yaml" and p.is_file()
            )

    return AgentManifest(
        agent_id=agent_id,
        persona=persona,
        declared_tools=declared_tools,
        example_count=example_count,
        eval_case_count=eval_case_count,
        nlah_dir=str(base),
    )


def _extract_persona(readme_text: str, max_chars: int = 1024) -> str:
    """Return the first non-heading paragraph from a README.md body.

    Splits on blank lines, finds the first block whose first line
    is not a markdown heading (``#``, ``##``, ...), and returns it
    trimmed + bounded.
    """
    blocks = re.split(r"\n\s*\n", readme_text.strip())
    for block in blocks:
        first_line = block.lstrip().split("\n", 1)[0]
        if _HEADING_LINE.match(first_line):
            continue
        # Found a paragraph. Collapse internal whitespace to keep
        # the manifest field compact + comparable.
        collapsed = " ".join(line.strip() for line in block.splitlines() if line.strip())
        return collapsed[:max_chars]
    return ""


def _parse_declared_tools(tools_md_text: str) -> tuple[str, ...]:
    """Return tool names declared via ``## `tool_name(...)``` headers.

    Preserves textual order, deduplicates while preserving first-
    occurrence position.
    """
    seen: list[str] = []
    seen_set: set[str] = set()
    for match in _TOOL_HEADER.finditer(tools_md_text):
        name = match.group(1)
        if name in seen_set:
            continue
        seen.append(name)
        seen_set.add(name)
    return tuple(seen)


__all__ = ["NlahParseError", "parse_nlah_dir"]
