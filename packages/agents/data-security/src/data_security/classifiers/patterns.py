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

import base64
import binascii
import contextlib
import gzip
import re

from data_security.schemas import ClassifierLabel

_BASE64_RE = re.compile(r"^[A-Za-z0-9+/\s]+={0,2}$")

# Patterns ordered by precedence (more specific first). Match returns the
# first hit's label; the matched substring is NEVER returned.
# AWS access-key id — long-term (AKIA) OR temporary (ASIA); both are credentials.
_AWS_ACCESS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
# Modern secret formats (distinctive prefixes → very low false-positive risk). Added after
# adversarial red-teaming found the v0.2 classifier missed all of these. High precedence.
_PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----")
_GITHUB_TOKEN_RE = re.compile(r"\b(?:gh[posru]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b")
_GOOGLE_API_KEY_RE = re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")
_STRIPE_KEY_RE = re.compile(r"\b[sr]k_live_[0-9A-Za-z]{20,}\b")
_SLACK_TOKEN_RE = re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")
# AWS *secret* access key — no fixed prefix (40-char base64), so require the
# `secret access key` label (any separator / camelCase) to bound false positives.
_AWS_SECRET_KEY_RE = re.compile(
    r"secret[\s_-]?access[\s_-]?key['\"]?\s*[:=]\s*['\"]?[A-Za-z0-9/+]{40}",
    re.IGNORECASE,
)
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


# --- v0.2 Task 8: PHI (HIPAA-aligned). Context-required / distinctive so they only fire on
# genuine PHI, keeping prior classify() matches byte-identical (WI-S5). ---
# Medical record number: an MRN context word, then a 6-12 alphanumeric id.
_MRN_RE = re.compile(
    r"(?:\bMRN\b|medical record (?:number|no|#))[\s:#-]*[A-Z0-9]{6,12}", re.IGNORECASE
)
# ICD-10 diagnostic code in the distinctive dotted form (letter + 2 digits + .dddd).
_ICD10_RE = re.compile(r"\b[A-TV-Z]\d{2}\.\d{1,4}\b")
# NPI: an NPI context word, then a 10-digit number (Luhn-validated below).
_NPI_RE = re.compile(
    r"(?:\bNPI\b|national provider id(?:entifier)?)[\s:#-]*(\d{10})", re.IGNORECASE
)
# --- v0.2 Task 9: PCI expansion (beyond PAN-with-Luhn). Context-required / sentinel-based. ---
# CVV / CVC: a verification-code context word, then 3-4 digits.
_CVV_RE = re.compile(
    r"(?:cvv2?|cvc2?|card verification(?: value)?)[\s:#-]*\d{3,4}\b", re.IGNORECASE
)
# Card expiration: an expiry context word, then MM/YY or MM/YYYY.
_CARD_EXP_RE = re.compile(
    r"(?:exp(?:iry|iration)?(?: date)?|valid thru)[\s:#-]*(?:0[1-9]|1[0-2])/\d{2,4}\b",
    re.IGNORECASE,
)
# Track 1 / Track 2 magnetic-stripe data — distinctive %B…^ / ;…= sentinels.
_TRACK_DATA_RE = re.compile(r"%B\d{12,19}\^|;\d{12,19}=")


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


def _npi_valid(npi: str) -> bool:
    """NPI check-digit: a valid 10-digit NPI passes Luhn when prefixed by the '80840' issuer
    code (the HIPAA NPI check-digit scheme)."""
    return _luhn_valid("80840" + npi)


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
    if _AWS_ACCESS_KEY_RE.search(text) or _AWS_SECRET_KEY_RE.search(text):
        # Both the AKIA/ASIA access-key ID and the secret access key are AWS credentials.
        return ClassifierLabel.AWS_ACCESS_KEY
    # Modern distinctive-prefix secrets — high precedence (before the greedy credit-card / email
    # patterns) so e.g. a Slack token is not misread as a credit card.
    if _PRIVATE_KEY_RE.search(text):
        return ClassifierLabel.PRIVATE_KEY
    if _GITHUB_TOKEN_RE.search(text):
        return ClassifierLabel.GITHUB_TOKEN
    if _GOOGLE_API_KEY_RE.search(text):
        return ClassifierLabel.GOOGLE_API_KEY
    if _STRIPE_KEY_RE.search(text):
        return ClassifierLabel.STRIPE_KEY
    if _SLACK_TOKEN_RE.search(text):
        return ClassifierLabel.SLACK_TOKEN
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
    # v0.2 Task 8 — PHI, appended after the v0.1 precedence so prior matches are unchanged.
    if _MRN_RE.search(text):
        return ClassifierLabel.MEDICAL_RECORD_NUMBER
    npi_match = _NPI_RE.search(text)
    if npi_match and _npi_valid(npi_match.group(1)):
        return ClassifierLabel.NPI
    if _ICD10_RE.search(text):
        return ClassifierLabel.ICD10_CODE
    # v0.2 Task 9 — PCI expansion, appended after PHI so prior matches stay byte-identical.
    if _TRACK_DATA_RE.search(text):
        return ClassifierLabel.TRACK_DATA
    if _CVV_RE.search(text):
        return ClassifierLabel.CVV
    if _CARD_EXP_RE.search(text):
        return ClassifierLabel.CARD_EXPIRATION
    return ClassifierLabel.NONE


_HEX_RE = re.compile(r"^[0-9A-Fa-f\s]+$")
_BASE32_RE = re.compile(r"^[A-Z2-7\s]+=*$")
#: How many nested encodings to peel — handles double-base64, base64+gzip combos, etc. Bounded so
#: a maliciously deeply-nested blob can't drive unbounded work. Found by adversarial red-teaming:
#: the prior code peeled exactly one gzip OR one base64 layer, so any other encoding (hex, base32,
#: url) or any *combination* hid a secret.
_MAX_DECODE_DEPTH = 3


def _decode_candidates(data: bytes, text: str) -> list[bytes]:
    """Plausible single-layer decodings of ``data`` (charset/magic-guarded to stay cheap)."""
    out: list[bytes] = []
    stripped = text.strip()
    if data[:2] == b"\x1f\x8b":  # gzip magic
        with contextlib.suppress(OSError, EOFError):
            out.append(gzip.decompress(data))
    if "%" in text:  # url-encoding (restores delimiters/word-boundaries around a token)
        from urllib.parse import unquote

        decoded_url = unquote(text)
        if decoded_url != text:
            out.append(decoded_url.encode("utf-8", errors="replace"))
    if len(stripped) >= 16 and _BASE64_RE.match(stripped):
        with contextlib.suppress(binascii.Error, ValueError):
            out.append(base64.b64decode(stripped, validate=True))
    if len(stripped) >= 16 and _BASE32_RE.match(stripped):
        with contextlib.suppress(binascii.Error, ValueError):
            out.append(base64.b32decode(stripped))
    if len(stripped) >= 16 and len(stripped) % 2 == 0 and _HEX_RE.match(stripped):
        with contextlib.suppress(ValueError):
            out.append(bytes.fromhex("".join(stripped.split())))
    return [d for d in out if d and d != data]


def _peel(data: bytes, depth: int) -> ClassifierLabel:
    text = data.decode("utf-8", errors="replace")
    label = classify(text)
    if label is not ClassifierLabel.NONE or depth <= 0:
        return label
    for decoded in _decode_candidates(data, text):
        label = _peel(decoded, depth - 1)
        if label is not ClassifierLabel.NONE:
            return label
    return ClassifierLabel.NONE


def classify_bytes(data: bytes) -> ClassifierLabel:
    """Classify object bytes, transparently peeling nested encodings before matching.

    Recursively tries the text as-is then each plausible decoding — **gzip, base64, base32, hex,
    url** — up to ``_MAX_DECODE_DEPTH`` layers, so a secret hidden under double-base64, base64+gzip,
    hex, base32, or url-encoding is still found. ``classify`` patterns are specific (no entropy
    guesses), so random blobs decoding to noise stay ``NONE`` — false positives remain low.
    """
    return _peel(data, _MAX_DECODE_DEPTH)


__all__ = ["classify", "classify_bytes"]
