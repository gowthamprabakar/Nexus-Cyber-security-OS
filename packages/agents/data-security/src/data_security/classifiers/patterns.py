"""Sensitive-data classifier — regex + Luhn over ``ClassifierLabel`` return type.

Q6 PRIVACY CONTRACT (LOAD-BEARING — plan §"Resolved questions" Q6).
================================================================

Per PRD §7.1.4 lines 957-966, D.5 enforces a hard privacy contract: the
classifier returns a **label only**, NEVER the matched substring. The
public API is::

    def classify(text: str) -> ClassifierLabel: ...

This function returns the label enum and nothing else. It MUST NEVER:

- Return the matched substring.
- Return start / end span positions.
- Return any reference to the input text beyond the label.
- Persist the input text to module-level state.
- Log the input text at any level.

The Task-13 ``no_pii_leak_in_report`` eval case is the acceptance probe;
violations are P0 bugs.

This invariant is enforced by four layers:

1. **Return-type annotation.** ``-> ClassifierLabel`` (mypy strict).
   ``ClassifierLabel`` is a ``StrEnum`` whose values are stable label
   tokens; there is no ``MatchSpan`` type and no overload that would
   permit returning the substring.
2. **No module-level state.** No "last match" attribute, no cache that
   stores input fragments.
3. **No input logging.** The implementation does not call any logger
   on the input text. (Downstream callers MUST also discard the input
   immediately after calling ``classify`` — that's not the classifier's
   responsibility but is documented at every call site.)
4. **Test gate.** ``test_classifiers_patterns.py::
   test_q6_privacy_contract_signature_returns_label_only`` introspects
   the function signature and asserts the return annotation is
   ``ClassifierLabel``.

Match precedence
================

Patterns are evaluated in the order below. The first match wins. More
specific / less ambiguous patterns are evaluated first to reduce false
positives:

1. **AWS access key** — ``AKIA[0-9A-Z]{16}``. The ``AKIA`` prefix is
   unambiguous and high-impact.
2. **JWT** — three-segment base64url string with ``eyJ`` prefix on the
   header segment. Also unambiguous in practice.
3. **SSN (US)** — ``\\d{3}-\\d{2}-\\d{4}``. Format is unmistakable when
   hyphens are present.
4. **Credit card** — 13-19 digits (with optional separators) that pass
   the **Luhn check**. The Luhn filter is critical: a 16-digit ID with
   the right format but wrong Luhn digit is NOT a card.
5. **Email** — standard RFC-5322-ish pattern.
6. **US phone** — area-code-prefixed format with optional separators.
7. **Generic API token** — 40+ char alphanumeric/url-safe string
   adjacent to a ``secret`` / ``token`` / ``api_key`` keyword. Most
   permissive; catch-all for things that don't match the above.
8. **NONE** — no match.

The classifier is conservative on the GENERIC_API_TOKEN bucket
specifically — only matches when the keyword precedes the value. This
trades recall for precision; falsely classifying random hashes /
checksums as tokens would over-uplift severity in downstream detectors.

Extension notes (deferred to D.5 v0.2)
======================================

- Date-of-birth, postal addresses, healthcare IDs (HIPAA): plan v0.2.
- ML / NER classifier: plan v0.5+ (Presidio integration).
- Multi-locale phone / SSN: not supported in v0.1 (US-only).
- True positive rate vs Macie cross-validation: plan v0.2.
"""

from __future__ import annotations

import re

from data_security.schemas import ClassifierLabel

# Patterns ordered by precedence (more specific first). Match returns the
# first hit's label; the matched substring is NEVER returned.
_AWS_ACCESS_KEY_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\b")
_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
# Credit card: 13-19 digits, with optional space / hyphen separators.
# Luhn validation filters non-card numbers in `classify` below.
_CREDIT_CARD_RE = re.compile(r"\b(?:\d[ -]?){12,18}\d\b")
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
# US phone — area code + 7 digits with optional separators / country code.
_PHONE_RE = re.compile(r"\b(?:\+?1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b")
# Generic API token: keyword-adjacent 40+-char alphanumeric / url-safe value.
# Conservative — requires the keyword to precede the value to reduce false
# positives on random hashes / commit SHAs / etc. Lower-precedence catch-all.
_GENERIC_API_TOKEN_RE = re.compile(
    r"(?:secret|token|api[_-]?key)[\s:=]+['\"]?[A-Za-z0-9_/+=-]{40,}",
    re.IGNORECASE,
)


def _luhn_valid(digits: str) -> bool:
    """Return True iff ``digits`` (digit-only string) passes the Luhn check.

    The Luhn algorithm is the standard credit-card check-digit validation.
    Used to filter credit-card-shaped numbers that aren't actually valid
    card numbers (random 16-digit IDs, etc.).
    """
    total = 0
    for i, digit in enumerate(reversed(digits)):
        n = int(digit)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def classify(text: str) -> ClassifierLabel:
    """Return the ``ClassifierLabel`` for the first sensitive pattern in ``text``.

    Q6 INVARIANT: returns a label only. The matched substring is NEVER
    returned. Callers MUST treat the return value as a label and MUST
    NOT store the input ``text`` alongside it in any persistent artifact.

    Match precedence (most specific first):

    1. AWS access key (``AKIA[0-9A-Z]{16}``) — unambiguous.
    2. JWT (3-segment base64url with ``eyJ`` prefix) — unambiguous.
    3. SSN (US 9-digit ``###-##-####``).
    4. Credit card (13-19 digits + Luhn-valid).
    5. Email.
    6. US phone.
    7. Generic API token (40+ char value adjacent to secret/token/api_key).
    8. ``ClassifierLabel.NONE`` — no match.

    Empty / whitespace-only strings return ``NONE``. The implementation
    is pure (no side effects) and deterministic.
    """
    if _AWS_ACCESS_KEY_RE.search(text):
        return ClassifierLabel.AWS_ACCESS_KEY
    if _JWT_RE.search(text):
        return ClassifierLabel.JWT
    if _SSN_RE.search(text):
        return ClassifierLabel.SSN
    cc_match = _CREDIT_CARD_RE.search(text)
    if cc_match:
        digits = re.sub(r"[^0-9]", "", cc_match.group(0))
        if 13 <= len(digits) <= 19 and _luhn_valid(digits):
            return ClassifierLabel.CREDIT_CARD
    if _EMAIL_RE.search(text):
        return ClassifierLabel.EMAIL
    if _PHONE_RE.search(text):
        return ClassifierLabel.PHONE
    if _GENERIC_API_TOKEN_RE.search(text):
        return ClassifierLabel.GENERIC_API_TOKEN
    return ClassifierLabel.NONE


__all__ = ["classify"]
