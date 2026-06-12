"""Categorical-only narrative invariant — code-level (synthesis v0.2 Task 15, WI-Y8/Q4).

The Q6/Q4 privacy contract: D.13's narrative discusses sensitive data **categorically** — it
refers to PII/PHI/PAN by classification **label** (e.g. ``[SSN]``, ``[CREDIT_CARD]``), never by
**value**. ``assert_categorical_only`` is the hard, code-level guard (the first of this cycle's
three LLM-agent invariants), mirroring D.3 ``assert_authorized``, D.4 ``assert_block_authorized``,
data-security ``assert_privacy_contract``, F.6 ``assert_audit_readonly``, and supervisor
``assert_no_peer_to_peer``. Any plaintext sensitive value in a narrative chunk raises.

Labels pass naturally: the detectors match concrete values (``123-45-6789``), so a label token
(``[SSN]``) never matches.
"""

from __future__ import annotations

import re

_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_AWS_KEY_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\b")
# Credit card shape: 13-19 digits with optional space/hyphen separators (Luhn-filtered below).
_PAN_RE = re.compile(r"\b(?:\d[ -]?){12,18}\d\b")


class CategoricalContractViolationError(RuntimeError):
    """Raised when a narrative chunk carries plaintext sensitive content (WI-Y8)."""


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


def assert_categorical_only(narrative_chunk: str) -> None:
    """Hard guard — raise if ``narrative_chunk`` contains plaintext PII/PAN/secrets.

    The narrative must refer to sensitive data by classification LABEL (e.g. ``[SSN]``), never
    by value (Q4/Q6; H4 — never invent/echo a matched substring).
    """
    if _detect_plaintext_pii(narrative_chunk):
        raise CategoricalContractViolationError(
            "Narrative contains plaintext sensitive content. The Q6/Q4 invariant requires "
            "categorical-only discussion — use classification LABELS (e.g. '[SSN]'), not values."
        )
