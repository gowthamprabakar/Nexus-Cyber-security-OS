"""D.4 v0.2 Task 11 — DGA detection refinement tests."""

from __future__ import annotations

from network_threat.detectors.dga_refine import (
    dga_threshold,
    is_allowlisted_suffix,
    is_dga_refined,
)


def test_allowlisted_suffix_exact() -> None:
    assert is_allowlisted_suffix("amazonaws.com") is True


def test_allowlisted_suffix_subdomain() -> None:
    assert is_allowlisted_suffix("d3a7xk29.cloudfront.net") is True
    assert is_allowlisted_suffix("RANDOM123.s3.amazonaws.com") is True  # case-insensitive


def test_non_allowlisted_suffix() -> None:
    assert is_allowlisted_suffix("kq8f3jx9z.example.com") is False


def test_allowlisted_never_dga_even_high_entropy() -> None:
    # A random-looking CloudFront subdomain with high entropy must NOT be flagged.
    assert is_dga_refined("d3a7xk29zq.cloudfront.net", entropy=4.2) is False


def test_threshold_inf_for_allowlisted() -> None:
    assert dga_threshold("x.cloudfront.net") == float("inf")


def test_high_entropy_non_allowlisted_is_dga() -> None:
    assert is_dga_refined("kq8f3jx9zqw.example.com", entropy=4.2) is True


def test_low_entropy_not_dga() -> None:
    assert is_dga_refined("google.com", entropy=2.1) is False


def test_threshold_default_for_non_allowlisted() -> None:
    assert dga_threshold("example.com") == 3.5
