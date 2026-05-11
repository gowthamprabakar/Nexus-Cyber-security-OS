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
"""

from __future__ import annotations

from pathlib import Path

_TOOLS_HEADER = "\n\n---\n\n# Tools reference\n\n"
_EXAMPLES_HEADER = "\n\n---\n\n# Few-shot examples\n"


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


__all__ = ["default_nlah_dir", "load_system_prompt"]
