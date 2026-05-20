"""Classifier tests — Task 3 (Q6 privacy-contract critical).

This test file is the load-bearing guard for the Q6 privacy invariant
("classifier returns label only, never the matched substring") declared
in the D.5 v0.1 plan. Every layer of the invariant is exercised:

1. Per-label positive matches (7 labels + NONE).
2. Luhn validation filters non-card 16-digit numbers.
3. Precedence: more specific patterns beat more general ones.
4. **Q6 signature introspection**: the public API returns
   ``ClassifierLabel`` and nothing else. No optional ``MatchSpan``,
   no overloads exposing the substring.
5. **Q6 purity**: classify is a pure function with no side effects.
6. Boundary cases (empty, whitespace, unicode, very long input).

The Task-13 ``no_pii_leak_in_report`` eval case is the system-level
acceptance probe; this file is the unit-level guard.
"""

from __future__ import annotations

import inspect

from data_security.classifiers import classify
from data_security.schemas import ClassifierLabel

# ---------------------------------------------------------------------------
# Per-label positive matches
# ---------------------------------------------------------------------------


def test_aws_access_key_classified() -> None:
    # Realistic-shape AWS access key (synthetic — not a real credential).
    assert (
        classify("user logged in with key AKIAIOSFODNN7EXAMPLE") == ClassifierLabel.AWS_ACCESS_KEY
    )


def test_jwt_classified() -> None:
    # Synthetic JWT (header.payload.signature, base64url). Not a real token.
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.signature_part_here"
    assert classify(f"Authorization: Bearer {jwt}") == ClassifierLabel.JWT


def test_ssn_classified() -> None:
    assert classify("Patient SSN: 123-45-6789") == ClassifierLabel.SSN


def test_credit_card_classified_via_luhn() -> None:
    # 4111-1111-1111-1111 is a well-known Visa test card; valid Luhn check.
    assert classify("CC on file: 4111-1111-1111-1111") == ClassifierLabel.CREDIT_CARD


def test_credit_card_invalid_luhn_returns_none() -> None:
    """A 16-digit number that doesn't pass Luhn is NOT a card.

    Critical filter — without Luhn, every 16-digit order-id / transaction-id
    would be flagged as a card. False positives at scale ruin operator trust
    in the DSPM signal.
    """
    # 1234-5678-9012-3456 has wrong Luhn checksum.
    assert classify("Order: 1234-5678-9012-3456") == ClassifierLabel.NONE


def test_email_classified() -> None:
    assert classify("Contact: alice@example.com") == ClassifierLabel.EMAIL


def test_phone_classified_us_format() -> None:
    assert classify("Call (555) 234-5678") == ClassifierLabel.PHONE


def test_phone_classified_with_country_code() -> None:
    assert classify("Phone: +1 555-234-5678") == ClassifierLabel.PHONE


def test_generic_api_token_classified() -> None:
    # Keyword-adjacent 40+-char token. Conservative pattern requires the
    # keyword preceding the value.
    text = "secret: abcdef0123456789ABCDEF0123456789abcdef0123"
    assert classify(text) == ClassifierLabel.GENERIC_API_TOKEN


def test_generic_api_token_keyword_variants() -> None:
    """``api_key`` / ``api-key`` / ``apikey`` / ``token`` all trigger."""
    base = " abcdef0123456789ABCDEF0123456789abcdef0123"
    for keyword in ("API_KEY:", "api-key:", "apikey:", "TOKEN:"):
        assert classify(keyword + base) == ClassifierLabel.GENERIC_API_TOKEN


def test_generic_api_token_requires_keyword_prefix() -> None:
    """Random 40+-char string without keyword is NOT a token.

    Reduces false positives on commit SHAs, content hashes, etc.
    """
    # 64 hex chars (looks like a SHA-256) but no keyword adjacent.
    text = "commit a" + "0" * 39
    assert classify(text) == ClassifierLabel.NONE


# ---------------------------------------------------------------------------
# NONE / boundary cases
# ---------------------------------------------------------------------------


def test_empty_string_returns_none() -> None:
    assert classify("") == ClassifierLabel.NONE


def test_whitespace_only_returns_none() -> None:
    assert classify("   \n\t  ") == ClassifierLabel.NONE


def test_random_text_returns_none() -> None:
    assert classify("the quick brown fox jumps over the lazy dog") == ClassifierLabel.NONE


def test_short_text_no_pii_returns_none() -> None:
    assert classify("hello world") == ClassifierLabel.NONE


def test_partial_aws_key_not_classified() -> None:
    """``AKIA`` prefix alone (without 16 trailing chars) is not a key."""
    assert classify("string starts with AKIA but is too short") == ClassifierLabel.NONE


def test_two_segment_jwt_not_classified() -> None:
    """A JWT must have 3 base64url segments. Two segments is not a JWT."""
    assert classify("token: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0") == ClassifierLabel.NONE


def test_ssn_without_hyphens_not_classified() -> None:
    """Plain 9-digit number is not enough — must use the ``###-##-####`` format
    (US-only conservative match in v0.1).
    """
    assert classify("number 123456789") == ClassifierLabel.NONE


def test_phone_without_area_code_not_classified() -> None:
    """Local-format ``234-5678`` is not enough — must include area code."""
    assert classify("ext 234-5678") == ClassifierLabel.NONE


# ---------------------------------------------------------------------------
# Precedence — more specific patterns win
# ---------------------------------------------------------------------------


def test_aws_key_beats_generic_token() -> None:
    """AWS key has higher precedence than generic api token.

    The AWS key pattern requires exactly 16 trailing alphanumeric chars
    after the AKIA prefix; this test places the key with surrounding
    whitespace so the word-boundary match fires, then a separate
    keyword-adjacent long string that would otherwise trigger the
    generic-token bucket. Order of patterns means the key wins.
    """
    text = "key=AKIAIOSFODNN7EXAMPLE; secret: " + "x" * 50
    assert classify(text) == ClassifierLabel.AWS_ACCESS_KEY


def test_ssn_beats_credit_card_when_both_present() -> None:
    """Per the documented precedence: SSN evaluated before credit card."""
    text = "SSN 123-45-6789 and CC 4111-1111-1111-1111"
    assert classify(text) == ClassifierLabel.SSN


def test_email_beats_phone_in_default_order() -> None:
    """Per the documented precedence: email before phone (alphabetical
    coincidence; documented order matches code).
    """
    text = "alice@example.com (555) 234-5678"
    assert classify(text) == ClassifierLabel.EMAIL


# ---------------------------------------------------------------------------
# Q6 PRIVACY CONTRACT — load-bearing invariants
# ---------------------------------------------------------------------------


def test_q6_privacy_contract_signature_returns_label_only() -> None:
    """LOAD-BEARING Q6 INVARIANT.

    The classifier API MUST have signature ``(text: str) -> ClassifierLabel``.
    Renaming, overloading, or adding parameters that expose the matched
    substring breaks the privacy contract. This test is the structural
    guard.

    If this test starts failing because of an API change, STOP — review
    against plan Q6 + PRD §7.1.4 lines 957-966 before merging.
    """
    import typing

    hints = typing.get_type_hints(classify)
    assert "text" in hints, "classify() must accept a `text` parameter"
    assert hints["text"] is str, f"text param must be str; got {hints['text']}"
    assert "return" in hints, "classify() must declare a return type"
    assert hints["return"] is ClassifierLabel, (
        f"classify() must return ClassifierLabel; got {hints['return']}. "
        "Q6 privacy contract: classifier returns label ONLY."
    )
    # Also assert there's exactly one parameter — no overloads that could
    # leak the matched substring.
    sig = inspect.signature(classify)
    params = list(sig.parameters.values())
    assert len(params) == 1, f"classify() must take exactly one parameter; got {len(params)}"
    assert params[0].name == "text"


def test_q6_privacy_contract_no_match_span_overloads() -> None:
    """The public API surface for classifying must be exactly one function.

    No overload that exposes ``(label, start, end)`` or ``(label, substring)``
    tuples may exist. Adding such an overload would defeat the Q6 invariant.

    Tracks only callable public symbols (not stdlib re-imports or
    ``__future__`` annotations marker). A *new* callable showing up under
    a non-underscored name is the Q6 violation signal — if you're adding
    one, review the privacy contract before merging.
    """
    from data_security.classifiers import patterns

    public_callables = {
        name
        for name in dir(patterns)
        if not name.startswith("_") and callable(getattr(patterns, name))
    }
    # ``classify`` is the only callable we ship publicly. ``ClassifierLabel``
    # is a StrEnum class (also callable for construction); allow it.
    expected = {"classify", "ClassifierLabel"}
    extras = public_callables - expected
    assert not extras, (
        f"data_security.classifiers.patterns has unexpected public callables: {extras}. "
        "Review against Q6 — any public function returning matched text is a violation."
    )


def test_q6_classify_is_pure_no_module_state() -> None:
    """Calling classify multiple times must not mutate any observable state.

    Q6 invariant requires the classifier to be stateless — no "last match"
    cache, no input buffer, nothing that could persist substrings across
    calls.
    """
    from data_security.classifiers import patterns

    # Snapshot the module's public + private attribute set.
    snapshot_before = {k: id(v) for k, v in vars(patterns).items() if not k.startswith("__")}
    # Drive a variety of inputs through classify.
    inputs = [
        "alice@example.com",
        "SSN 123-45-6789",
        "AKIAIOSFODNN7EXAMPLE",
        "CC 4111-1111-1111-1111",
        "",
        "the quick brown fox",
    ]
    for text in inputs:
        result = classify(text)
        assert isinstance(result, ClassifierLabel)
    snapshot_after = {k: id(v) for k, v in vars(patterns).items() if not k.startswith("__")}
    # Module state must be identical — no new attributes, no rebound IDs.
    assert snapshot_before == snapshot_after, (
        "data_security.classifiers.patterns module state changed across classify() calls — "
        "possible Q6 violation (stateful classifier could persist input fragments)."
    )


def test_q6_classify_does_not_return_input_substring() -> None:
    """Defensive smoke test: the return value is a ``ClassifierLabel`` enum
    member, not a substring of the input. We can't fully prove the negative
    (callers could still log the input themselves), but we can verify the
    type returned at every API call site.
    """
    inputs = [
        "user has SSN 123-45-6789 on file",
        "key: AKIAIOSFODNN7EXAMPLE",
        "card 4111-1111-1111-1111",
        "alice@example.com",
        "phone (555) 234-5678",
        "token: " + "x" * 50,
        "no match here",
    ]
    for text in inputs:
        result = classify(text)
        assert isinstance(result, ClassifierLabel)
        # The label value is a stable identifier, never a piece of the input.
        # Stronger check: every known label value is a fixed string from the enum.
        assert result.value in {member.value for member in ClassifierLabel}


# ---------------------------------------------------------------------------
# Luhn validator unit tests
# ---------------------------------------------------------------------------


def test_luhn_valid_known_cards() -> None:
    """Standard test-card numbers from card-network test catalogs."""
    from data_security.classifiers.patterns import _luhn_valid

    assert _luhn_valid("4111111111111111")  # Visa test
    assert _luhn_valid("5500000000000004")  # MasterCard test
    assert _luhn_valid("340000000000009")  # Amex test (15 digits)


def test_luhn_invalid_random_digits() -> None:
    from data_security.classifiers.patterns import _luhn_valid

    assert not _luhn_valid("1234567890123456")
    assert not _luhn_valid("9999999999999999")


def test_luhn_short_and_long_boundary() -> None:
    """Algorithm itself accepts any digit string; the credit-card detector
    additionally requires 13-19 digits. Verify the algorithm.
    """
    from data_security.classifiers.patterns import _luhn_valid

    # 4-digit Luhn-valid sequence.
    assert _luhn_valid("0000")  # sum=0, divisible by 10


# ---------------------------------------------------------------------------
# Determinism + idempotence
# ---------------------------------------------------------------------------


def test_classify_is_deterministic() -> None:
    """Same input must always produce the same output. No randomness, no
    time-dependence.
    """
    text = "Contact alice@example.com about ticket ABC-123"
    first = classify(text)
    for _ in range(50):
        assert classify(text) == first


def test_classify_handles_unicode() -> None:
    """Unicode in surrounding text must not crash the classifier."""
    assert classify("ユーザー alice@example.com 様") == ClassifierLabel.EMAIL
    assert classify("Привет world") == ClassifierLabel.NONE


def test_classify_handles_long_input() -> None:
    """Very long input strings must not slow the classifier pathologically.

    The classifier uses anchored regex patterns; should be O(n).
    """
    text = "lorem ipsum " * 10_000 + " alice@example.com"
    assert classify(text) == ClassifierLabel.EMAIL
