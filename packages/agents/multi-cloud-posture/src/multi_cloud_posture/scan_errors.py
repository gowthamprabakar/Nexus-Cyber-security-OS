"""Partial-scan degradation primitives for D.5 (v0.2 Tasks 5 + 9).

Mirrors `cloud_posture`'s Pattern E in-package (Q1). When a live per-region /
per-scope scan fails, it is recorded as a **secret-free, traceback-free** degraded
marker and the scan **continues** — a failed region is not a whole-run failure.

`sanitize_scan_error` understands both the **Azure** (`azure-core`,
`.status_code`) and **GCP** (`google-api-core`, `.code` HTTPStatus) error shapes.
It never returns the full message, request URL, resource ids, tokens, or
credential material — only the exception type and (when present) a structured
numeric status/code.
"""

from __future__ import annotations


def sanitize_scan_error(exc: Exception) -> str:
    """A secret-free, traceback-free one-liner for a failed scan.

    azure-core `HttpResponseError` (`.status_code`) and google-api-core
    `GoogleAPICallError` (`.code`, an `HTTPStatus`), incl. 429 throttling /
    403 / 503 → ``"<Type>: <status>"`` using only the numeric code. Anything
    else (e.g. `RetryError`, generic) → the exception **type name** only. Never
    the message / URL / token.
    """
    name = type(exc).__name__
    status = getattr(exc, "status_code", None)  # azure-core HttpResponseError
    if isinstance(status, int):
        return f"{name}: {int(status)}"
    code = getattr(exc, "code", None)  # google-api-core GoogleAPICallError (HTTPStatus)
    if isinstance(code, int):
        return f"{name}: {int(code)}"
    return name


def degraded_marker(region: str, exc: Exception) -> dict[str, str]:
    """A structured degraded-region marker (the scan continues past it)."""
    return {"region": region, "error": sanitize_scan_error(exc)}
