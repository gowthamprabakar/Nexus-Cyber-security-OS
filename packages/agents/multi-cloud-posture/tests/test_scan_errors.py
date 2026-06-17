"""D.15 v0.2 Task 5 — Azure scan-error sanitizer + partial-scan degradation."""

from __future__ import annotations

from azure.core.exceptions import (
    ClientAuthenticationError,
    HttpResponseError,
    ServiceRequestError,
)
from google.api_core import exceptions as gcp_exc
from multi_cloud_posture.scan_errors import degraded_marker, sanitize_scan_error
from multi_cloud_posture.summarizer import _append_degraded


def _http_error(status: int, message: str = "boom") -> HttpResponseError:
    err = HttpResponseError(message=message)
    err.status_code = status
    return err


def test_sanitize_http_error_uses_status_only() -> None:
    assert sanitize_scan_error(_http_error(403)) == "HttpResponseError: 403"


def test_sanitize_throttle_429() -> None:
    assert sanitize_scan_error(_http_error(429)) == "HttpResponseError: 429"


def test_sanitize_auth_error_is_type_name() -> None:
    # ClientAuthenticationError carries no int status_code → type name only.
    assert sanitize_scan_error(ClientAuthenticationError()) == "ClientAuthenticationError"


def test_sanitize_service_request_error_is_type_name() -> None:
    assert sanitize_scan_error(ServiceRequestError(message="x")) == "ServiceRequestError"


def test_sanitize_generic_exception_is_type_name() -> None:
    assert sanitize_scan_error(ValueError("nope")) == "ValueError"


def test_sanitize_leaks_no_secret_or_url() -> None:
    err = _http_error(403, message="token AKIAEXAMPLE at https://secret.internal/path?sig=xyz")
    out = sanitize_scan_error(err)
    assert "AKIAEXAMPLE" not in out
    assert "https://" not in out
    assert "secret.internal" not in out
    assert out == "HttpResponseError: 403"


def test_sanitize_has_no_traceback() -> None:
    try:
        raise _http_error(500)
    except HttpResponseError as exc:
        assert "Traceback" not in sanitize_scan_error(exc)


def test_sanitize_non_int_status_is_type_name() -> None:
    err = HttpResponseError(message="x")
    err.status_code = None
    assert sanitize_scan_error(err) == "HttpResponseError"


def test_degraded_marker_shape() -> None:
    assert degraded_marker("eastus", _http_error(429)) == {
        "region": "eastus",
        "error": "HttpResponseError: 429",
    }


def test_append_degraded_noop_when_empty() -> None:
    lines: list[str] = []
    _append_degraded(lines, None)
    _append_degraded(lines, [])
    assert lines == []  # byte-identical when nothing degraded


def test_append_degraded_renders_section() -> None:
    lines: list[str] = []
    _append_degraded(
        lines,
        [
            {"region": "eastus", "error": "HttpResponseError: 429"},
            {"region": "westus", "error": "ClientAuthenticationError"},
        ],
    )
    text = "\n".join(lines)
    assert "## Degraded regions" in text
    assert "⚠️ `eastus` — HttpResponseError: 429" in text
    assert "⚠️ `westus` — ClientAuthenticationError" in text


# ---------------------------- GCP (google-api-core) -----------------------


def test_sanitize_gcp_permission_denied_403() -> None:
    # .code is an HTTPStatus IntEnum; normalize to a plain int in the output.
    out = sanitize_scan_error(gcp_exc.PermissionDenied("denied"))
    assert out == "PermissionDenied: 403"


def test_sanitize_gcp_throttle_429() -> None:
    assert sanitize_scan_error(gcp_exc.TooManyRequests("slow down")) == "TooManyRequests: 429"
    assert sanitize_scan_error(gcp_exc.ResourceExhausted("quota")) == "ResourceExhausted: 429"


def test_sanitize_gcp_service_unavailable_503() -> None:
    assert sanitize_scan_error(gcp_exc.ServiceUnavailable("down")) == "ServiceUnavailable: 503"


def test_sanitize_gcp_retry_error_is_type_name() -> None:
    # RetryError carries no int .code → type name only.
    assert sanitize_scan_error(gcp_exc.RetryError("gave up", cause=None)) == "RetryError"


def test_sanitize_gcp_leaks_no_secret() -> None:
    err = gcp_exc.PermissionDenied("user secret-token@corp at https://compute.googleapis.com/p")
    out = sanitize_scan_error(err)
    assert out == "PermissionDenied: 403"
    assert "secret-token" not in out
    assert "googleapis.com" not in out
