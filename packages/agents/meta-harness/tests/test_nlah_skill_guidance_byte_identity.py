"""G2.5 Task 11 / G2-WI-6 — NLAH skill-guidance byte-identity guard.

Programmatic regression guard ensuring the ``## Skill selection guidance``
section is **byte-identical** across all 17 Wave 1 agent NLAH bundles. G2 Task 6
verified this by hand; this codifies it so CI catches drift — divergence would
silently degrade G2's skill-selection consistency across the platform.

Three guards (count / presence / byte-identity), each with an actionable failure
message. Test-only; no persona edits (the invariant already holds). Discovery is
repo-root glob, matching the existing bootstrap test patterns.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[4]
_AGENTS_ROOT = _REPO_ROOT / "packages" / "agents"
_NLAH_BUNDLES_GLOB = "*/src/*/nlah/README.md"
_SECTION_HEADING = "## Skill selection guidance"
_EXPECTED_AGENT_COUNT = 17

_HEADING_RE = re.compile(rf"^{re.escape(_SECTION_HEADING)}\s*$", re.MULTILINE)
_NEXT_H2_RE = re.compile(r"^## ", re.MULTILINE)


def _discover_nlah_bundles() -> list[Path]:
    """All agent NLAH README bundles, discovered from the repo root."""
    return sorted(_AGENTS_ROOT.glob(_NLAH_BUNDLES_GLOB))


def _agent_id(bundle: Path) -> str:
    """``packages/agents/<agent>/src/<pkg>/nlah/README.md`` → ``<agent>``."""
    return bundle.relative_to(_AGENTS_ROOT).parts[0]


def _extract_skill_guidance_section(bundle: Path) -> str | None:
    """Section bytes from the ``## Skill selection guidance`` heading up to (but
    excluding) the next ``## `` heading, or ``None`` when the section is absent."""
    content = bundle.read_text(encoding="utf-8")
    match = _HEADING_RE.search(content)
    if not match:
        return None
    rest = content[match.end() :]
    nxt = _NEXT_H2_RE.search(rest)
    end = match.end() + (nxt.start() if nxt else len(rest))
    return content[match.start() : end]


def _sections_by_agent() -> dict[str, str | None]:
    return {_agent_id(b): _extract_skill_guidance_section(b) for b in _discover_nlah_bundles()}


def test_seventeen_nlah_bundles_discovered() -> None:
    """Exactly 17 agent NLAH bundles exist (catches a new/removed agent dir)."""
    bundles = _discover_nlah_bundles()
    found = sorted(_agent_id(b) for b in bundles)
    assert len(bundles) == _EXPECTED_AGENT_COUNT, (
        f"Expected exactly {_EXPECTED_AGENT_COUNT} agent NLAH bundles; found {len(bundles)}: {found}"
    )


def test_every_bundle_has_skill_guidance_section() -> None:
    """Every agent NLAH bundle contains the ``## Skill selection guidance`` section."""
    missing = sorted(a for a, s in _sections_by_agent().items() if s is None)
    assert not missing, (
        f"Agents missing '{_SECTION_HEADING}' section: {missing}. Every Wave 1 agent "
        f"NLAH bundle must carry this section (G2-WI-6)."
    )


def test_skill_guidance_section_byte_identical_across_agents() -> None:
    """All agents' skill-guidance sections are byte-identical (single md5)."""
    sections = {a: s for a, s in _sections_by_agent().items() if s is not None}
    hashes = {
        a: hashlib.md5(s.encode("utf-8"), usedforsecurity=False).hexdigest()
        for a, s in sections.items()
    }
    distinct = set(hashes.values())
    assert len(distinct) == 1, (
        "NLAH skill-guidance section diverged across agents (G2-WI-6 violation).\n"
        f"Expected a single md5 across all agents; found {len(distinct)}.\n"
        "Per-agent hashes:\n" + "\n".join(f"  {a}: {h}" for a, h in sorted(hashes.items()))
    )
