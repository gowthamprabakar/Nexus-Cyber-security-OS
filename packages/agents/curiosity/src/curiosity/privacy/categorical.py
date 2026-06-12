"""Categorical-only invariant — code-level (curiosity v0.2 Task 12, WI-X9).

**Inherited from D.13** (the institutional LLM-agent template, Cycle 13; proven by D.7, Cycle 14).
D.12's hypothesis statements, rationale, and probe-directive text discuss sensitive data
**categorically** — by classification label, never by value. ``assert_categorical_only`` is the
hard guard; any plaintext sensitive value raises. Applied to every LLM-emitted text chunk before
it reaches a CuriosityClaim / OCSF finding / probe directive.
"""

from __future__ import annotations

import re

_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_AWS_KEY_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\b")
_PAN_RE = re.compile(r"\b(?:\d[ -]?){12,18}\d\b")


class CategoricalContractViolationError(RuntimeError):
    """Raised when a curiosity text chunk carries plaintext sensitive content (WI-X9)."""


def _luhn_valid(digits: str) -> bool:
    total = 0
    for i, digit in enumerate(reversed(digits)):
        n = int(digit)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def _detect_plaintext_pii(text: str) -> bool:
    if _SSN_RE.search(text) or _AWS_KEY_RE.search(text) or _JWT_RE.search(text):
        return True
    return any(_luhn_valid(re.sub(r"[ -]", "", match.group())) for match in _PAN_RE.finditer(text))


def assert_categorical_only(text_chunk: str) -> None:
    """Hard guard — raise if ``text_chunk`` contains plaintext PII/PAN/secrets (WI-X9/Q4).

    Discuss sensitive data by classification LABEL (e.g. ``[SSN]``), never by value.
    """
    if _detect_plaintext_pii(text_chunk):
        raise CategoricalContractViolationError(
            "Curiosity text contains plaintext sensitive content. The categorical-only contract "
            "requires classification LABELS (e.g. '[SSN]'), never values (WI-X9)."
        )
