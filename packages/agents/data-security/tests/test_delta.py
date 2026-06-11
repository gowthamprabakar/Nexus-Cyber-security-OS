"""data-security v0.2 Task 17 — delta detection tests."""

from __future__ import annotations

from data_security.continuous.delta import (
    compute_delta,
    finding_key,
    per_bucket_delta,
)


def test_finding_key() -> None:
    assert finding_key("pii-bucket", "ssn") == "pii-bucket/ssn"


def test_newly_detected() -> None:
    d = compute_delta(["b/ssn"], ["b/ssn", "b/credit_card"])
    assert d.newly_detected == ("b/credit_card",) and d.resolved == ()


def test_resolved() -> None:
    # A finding that disappears = data deleted / encrypted / access tightened.
    d = compute_delta(["b/ssn", "b/credit_card"], ["b/ssn"])
    assert d.resolved == ("b/credit_card",)


def test_persisting_no_changes() -> None:
    d = compute_delta(["b/ssn"], ["b/ssn"])
    assert d.has_changes is False and d.persisting == ("b/ssn",)


def test_has_changes() -> None:
    assert compute_delta([], ["b/ssn"]).has_changes is True


def test_sorted_output() -> None:
    d = compute_delta([], ["c/ssn", "a/ssn", "b/ssn"])
    assert d.newly_detected == ("a/ssn", "b/ssn", "c/ssn")


def test_per_bucket_delta() -> None:
    d = compute_delta([], ["a/ssn", "b/ssn", "b/credit_card"])
    nb = per_bucket_delta(d, "b")
    assert set(nb.newly_detected) == {"b/ssn", "b/credit_card"}
    assert "a/ssn" not in nb.newly_detected


def test_empty() -> None:
    d = compute_delta([], [])
    assert d.has_changes is False and d.newly_detected == ()
