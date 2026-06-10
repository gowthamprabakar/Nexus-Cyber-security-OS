"""Tests for the hoisted partial-scan degradation contract (Pattern E, Task 2)."""

from __future__ import annotations

from charter import degraded_marker, sanitize_scan_error
from charter.degradation import degraded_marker as dm_direct


class _ClientError(Exception):
    """Stand-in for botocore ClientError — carries a `.response` dict."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


class _HttpResponseError(Exception):
    """Stand-in for azure-core HttpResponseError — carries `.status_code`."""

    def __init__(self, status: int) -> None:
        super().__init__(str(status))
        self.status_code = status


class _GoogleApiError(Exception):
    """Stand-in for google-api-core error — carries an int `.code`."""

    def __init__(self, code: int) -> None:
        super().__init__(str(code))
        self.code = code


def test_botocore_client_error_returns_type_and_code() -> None:
    assert sanitize_scan_error(_ClientError("AccessDenied")) == "_ClientError: AccessDenied"


def test_azure_status_code() -> None:
    assert sanitize_scan_error(_HttpResponseError(403)) == "_HttpResponseError: 403"


def test_google_int_code() -> None:
    assert sanitize_scan_error(_GoogleApiError(404)) == "_GoogleApiError: 404"


def test_generic_exception_returns_type_name_only() -> None:
    assert sanitize_scan_error(ValueError("boom")) == "ValueError"


def test_no_message_or_secret_leaks() -> None:
    # The full message ("super secret arn:aws:...") must never appear.
    out = sanitize_scan_error(RuntimeError("arn:aws:iam::123:role/secret request-id=abc"))
    assert out == "RuntimeError"
    assert "arn" not in out and "request-id" not in out


def test_degraded_marker_shape_region() -> None:
    m = degraded_marker("region", "us-east-1", _ClientError("Throttling"))
    assert m == {"region": "us-east-1", "error": "_ClientError: Throttling"}


def test_degraded_marker_shape_image() -> None:
    m = dm_direct("image", "123.dkr.ecr/app:latest", _HttpResponseError(401))
    assert m == {"image": "123.dkr.ecr/app:latest", "error": "_HttpResponseError: 401"}


def test_marker_keys_are_unit_then_error() -> None:
    m = degraded_marker("feed", "vpc-flow", ValueError("x"))
    assert list(m.keys()) == ["feed", "error"]
