"""Region-scoping precedence for D.5 (v0.2 Tasks 4 + 8).

Mirrors `cloud_posture`'s Pattern C precedence (Q1 — in-package; the literal
charter hoist is deferred to D.2). Both the Azure (Task 4) and GCP (Task 8) live
paths resolve their scan regions through this one helper, so the precedence is
single-sourced:

    explicit `--<cloud>-regions`  →  discovered regions  →  fallback

`parse_regions_csv` turns the comma-separated CLI value into a clean list.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence


def resolve_scan_regions(
    explicit: Sequence[str] | None,
    discovered: Sequence[str] | None,
    *,
    fallback: Iterable[str] = (),
) -> list[str]:
    """The regions to scan, by precedence.

    Explicit regions win (an operator's `--<cloud>-regions`); else the
    discovered regions (all available for the scope); else `fallback`. Empty /
    `None` for `explicit` or `discovered` means "not specified".
    """
    if explicit:
        return list(explicit)
    if discovered:
        return list(discovered)
    return list(fallback)


def parse_regions_csv(value: str | None) -> list[str] | None:
    """Parse a comma-separated `--<cloud>-regions` value into a list.

    `None` / empty / all-whitespace → `None` ("not specified"); otherwise the
    trimmed, non-empty, order-preserving, de-duplicated region names.
    """
    if not value or not value.strip():
        return None
    seen: dict[str, None] = {}
    for part in value.split(","):
        region = part.strip()
        if region:
            seen.setdefault(region, None)
    return list(seen) or None
