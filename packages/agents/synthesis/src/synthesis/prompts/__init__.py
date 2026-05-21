"""Stage-3 NARRATE prompt templates for the LLM calls.

v0.1 ships three markdown templates, loaded via
``importlib.resources``:

- ``outline.md`` — Stage-3 outline call (structured JSON output).
- ``narration.md`` — Stage-3 per-section narration call (markdown body).
- ``executive_summary.md`` — Stage-3 executive-summary call.

The :func:`load_prompt` helper resolves a template name to its text
content. The narrator (Task 6) calls this once per call type per
agent run and substitutes the context-bundle JSON into the
template's placeholders.

**Q6 reminder in templates.** Per the D.13 plan §Q6, the narration
template explicitly instructs the LLM to NEVER reproduce classifier-
matched substrings (the matched SSNs / credit-card numbers / AWS
access keys / JWTs that triggered a D.5 finding). The reviewer
(Task 7) is the second line of defence; this is the first.
"""

from __future__ import annotations

from importlib import resources

_VALID_PROMPT_NAMES = frozenset(
    {
        "outline",
        "narration",
        "executive_summary",
    }
)


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
    pkg = resources.files("synthesis.prompts")
    candidate = pkg / f"{name}.md"
    return candidate.read_text(encoding="utf-8")


__all__ = ["load_prompt"]
