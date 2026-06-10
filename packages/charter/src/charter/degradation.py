"""Partial-scan degradation contract — Pattern E (hoisted, D.2 v0.2 Task 2).

Hoisted from F.3 cloud-posture (`_sanitize_scan_error` + the per-region
`degraded_regions` markers) and D.1 vulnerability (`scan_errors.sanitize_scan_error`
+ `degraded_image_marker`) into the charter for cross-agent reuse — D.2 Identity is
the third consumer (live AWS IAM + Azure AD partial scans). Per ADR-016/ADR-007 the
canonical pattern lives in one place; agents adopt it instead of re-deriving it.

The contract: a failed **scan unit** (a region, an image, a feed, a principal, …)
is recorded as a secret-free, traceback-free degraded marker and the scan
**continues** — one bad unit is not a whole-run failure. `BudgetExhausted` remains
the one hard stop (enforced by the charter budget, not here). `sanitize_scan_error`
never returns the full exception message, ARNs, request ids, tokens, or any
credential material.
"""

from __future__ import annotations


def sanitize_scan_error(exc: Exception) -> str:
    """A secret-free, traceback-free one-liner for a failed scan unit.

    - botocore ``ClientError`` → ``"<Type>: <Code>"`` (the structured AWS error
      code only — e.g. ``"ClientError: AccessDenied"``).
    - azure-core ``.status_code`` / google-api-core ``.code`` (int) →
      ``"<Type>: <status>"`` (e.g. ``"HttpResponseError: 403"``).
    - otherwise the exception **type name** only.

    Never returns the full message, ARNs, request ids, or credential material, so
    the marker is safe to write to ``summary.md`` / ``report.md``.
    """
    name = type(exc).__name__
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        code = response.get("Error", {}).get("Code")
        if code:
            return f"{name}: {code}"
    status = getattr(exc, "status_code", None)
    if isinstance(status, int):
        return f"{name}: {int(status)}"
    code = getattr(exc, "code", None)
    if isinstance(code, int):
        return f"{name}: {int(code)}"
    return name


def degraded_marker(unit_key: str, unit_value: str, exc: Exception) -> dict[str, str]:
    """A structured degraded marker: ``{<unit_key>: <unit_value>, "error": <sanitized>}``.

    The scan continues past it. ``unit_key`` names the dimension that failed
    (``"region"`` for F.3, ``"image"`` for D.1, ``"feed"``/``"principal"`` for
    future consumers). The error is sanitized via :func:`sanitize_scan_error`.
    """
    return {unit_key: unit_value, "error": sanitize_scan_error(exc)}
