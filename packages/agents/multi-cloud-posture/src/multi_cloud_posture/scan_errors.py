"""Partial-scan degradation primitives for D.5 (v0.2 Tasks 5 + 9).

Mirrors `cloud_posture`'s Pattern E in-package (Q1). When a live per-region /
per-scope scan fails, it is recorded as a **secret-free, traceback-free** degraded
marker and the scan **continues** — a failed region is not a whole-run failure.

`sanitize_scan_error` understands the **Azure** (`azure-core`) error shape now;
Task 9 extends it for **GCP** (`google-api-core`). It never returns the full
message, request URL, resource ids, tokens, or credential material — only the
exception type and (when present) a structured status/code.
"""

from __future__ import annotations


def sanitize_scan_error(exc: Exception) -> str:
    """A secret-free, traceback-free one-liner for a failed scan.

    azure-core `HttpResponseError` (incl. 429 throttling) → ``"<Type>: <status>"``
    using only the numeric status code. Anything else → the exception **type
    name** only. Never the message / URL / token.
    """
    name = type(exc).__name__
    status = getattr(exc, "status_code", None)
    if isinstance(status, int):
        return f"{name}: {status}"
    return name


def degraded_marker(region: str, exc: Exception) -> dict[str, str]:
    """A structured degraded-region marker (the scan continues past it)."""
    return {"region": region, "error": sanitize_scan_error(exc)}
