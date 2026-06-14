"""Categorical-only LLM-output invariant — shared canonical implementation (Phase D P3-2 hoist).

The Q4/Q6 privacy contract for every LLM-emitting agent: narratives, hypotheses, claims, and
probe text discuss sensitive data **categorically** — by classification **label** (``[SSN]``,
``[CREDIT_CARD]``), never by **value**. ``assert_categorical_only`` is the hard, code-level guard;
any plaintext sensitive value in a text chunk raises.

This is the single source of truth, hoisted from the three LLM agents (D.13 synthesis, D.7
investigation, D.12 curiosity), which previously each carried a byte-near-identical copy. Labels
pass naturally: the detectors match concrete values (``123-45-6789``), so a label token (``[SSN]``)
never matches.
"""

from __future__ import annotations

import re

_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_AWS_KEY_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\b")
# Credit card shape: 13-19 digits with optional space/hyphen separators (Luhn-filtered below).
_PAN_RE = re.compile(r"\b(?:\d[ -]?){12,18}\d\b")


class CategoricalContractViolationError(RuntimeError):
    """Raised when an LLM-emitted text chunk carries plaintext sensitive content (Q4/Q6)."""


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
    for match in _PAN_RE.finditer(text):
        digits = re.sub(r"[ -]", "", match.group())
        if _luhn_valid(digits):
            return True
    return False


def assert_categorical_only(text_chunk: str) -> None:
    """Hard guard — raise if ``text_chunk`` contains plaintext PII/PAN/secrets.

    LLM output must refer to sensitive data by classification LABEL (e.g. ``[SSN]``), never by
    value (Q4/Q6; never invent/echo a matched substring).
    """
    if _detect_plaintext_pii(text_chunk):
        raise CategoricalContractViolationError(
            "LLM output contains plaintext sensitive content. The categorical-only contract "
            "requires classification LABELS (e.g. '[SSN]'), never values."
        )
