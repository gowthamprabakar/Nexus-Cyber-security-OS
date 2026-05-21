"""Stage-3 HYPOTHESIZE prompt template for D.12's LLM call.

v0.1 ships a single markdown template (``hypothesis.md``) loaded via
``importlib.resources``. The hypothesizer (Task 6) calls this once
per run; the template instructs the LLM to return structured JSON
matching the ``Hypothesis`` schema (Task 2).

**Q6 reminder in template.** Per the D.12 plan §Q6, the hypothesis
template explicitly instructs the LLM to NEVER reproduce classifier-
matched substrings (SSN values, credit-card numbers, AWS access
keys, JWTs). Reused-from-D.13's reviewer (Task 7) is the second
line of defence; this is the first.
"""

from __future__ import annotations

from importlib import resources

_VALID_PROMPT_NAMES = frozenset({"hypothesis"})


def load_prompt(name: str) -> str:
    """Return the markdown text of a named prompt template.

    Raises ``ValueError`` for unknown names and ``FileNotFoundError``
    if the bundled template file is missing (which would indicate a
    packaging bug).
    """
    if name not in _VALID_PROMPT_NAMES:
        raise ValueError(
            f"unknown prompt template {name!r}; valid names: {sorted(_VALID_PROMPT_NAMES)}"
        )
    pkg = resources.files("curiosity.prompts")
    candidate = pkg / f"{name}.md"
    return candidate.read_text(encoding="utf-8")


__all__ = ["load_prompt"]
