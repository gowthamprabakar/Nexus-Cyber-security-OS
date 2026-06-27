"""The customer-facing rendering of the ranked attack paths — the North Star's "see" half.

:class:`AttackPathRanker` produces the prioritized list; this turns it into what a person actually
reads (a text report) or a machine consumes (JSON). Pure functions over ``list[AttackPath]`` — no
store, no I/O — so they render the same whether the paths came from a live scan or a test scene.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from meta_harness.attack_path_remediation import advice_for

if TYPE_CHECKING:
    from collections.abc import Sequence

    from meta_harness.attack_paths import AttackPath

#: Numeric severity → a triage band a human reads at a glance.
_BANDS = ((90, "CRITICAL"), (70, "HIGH"), (50, "MEDIUM"), (0, "LOW"))

#: path_type → a short human label (fallback: title-case the type).
_LABELS = {
    "crown_jewel": "Crown jewel",
    "public_secret": "Public secret",
    "internet_exposed_vulnerable": "Internet-exposed vulnerable workload",
    "privileged_vulnerable": "Privileged vulnerable workload",
    "public_unencrypted": "Public unencrypted data",
    "external_trust": "External trust",
    "exposed_ai_sensitive_data": "Exposed AI service",
    "resource_based_data": "Resource-based access",
    "fine_grained_data": "Over-permissioned access",
}


def severity_band(severity: int) -> str:
    """The triage band for a numeric severity (CRITICAL / HIGH / MEDIUM / LOW)."""
    return next(label for floor, label in _BANDS if severity >= floor)


def path_label(path_type: str) -> str:
    """A short human label for an attack-path type."""
    return _LABELS.get(path_type, path_type.replace("_", " ").capitalize())


def path_to_dict(path: AttackPath) -> dict[str, object]:
    """JSON-serializable view of one attack path, including remediation advice (for an API)."""
    advice = advice_for(path.path_type)
    return {
        "path_type": path.path_type,
        "label": path_label(path.path_type),
        "severity": path.severity,
        "severity_band": severity_band(path.severity),
        "title": path.title,
        "count": path.count,
        "evidence": list(path.evidence),
        "entities": list(path.entities),
        "fix": advice.steps if advice else "",
        "auto_fixable": advice.auto_fixable if advice else False,
        "auto_via": advice.auto_via if advice else "",
    }


def render_report(paths: Sequence[AttackPath], *, tenant_id: str, limit: int = 10) -> str:
    """A worst-first text report of a tenant's top attack paths.

    Shows the top ``limit`` paths (the North Star's "top ~10"); the header notes the total so a
    truncated list never reads as "this is everything". Empty input → a clean all-clear line.
    """
    total = len(paths)
    if total == 0:
        return f"No attack paths found for tenant {tenant_id}."

    shown = paths[:limit]
    header = f"Top attack paths for tenant {tenant_id} ({total} found"
    header += f", showing {len(shown)}):" if total > len(shown) else "):"
    lines = [header, ""]
    for i, p in enumerate(shown, start=1):
        lines.append(f"  {i}. [{severity_band(p.severity)} {p.severity}] {path_label(p.path_type)}")
        lines.append(f"     {p.title}")
        lines.append(
            f"     {p.count} finding{'s' if p.count != 1 else ''}"
            f" · {len(p.entities)} resource{'s' if len(p.entities) != 1 else ''}"
        )
        advice = advice_for(p.path_type)
        if advice:
            lines.append(f"     Fix: {advice.steps}")
            auto = f"yes ({advice.auto_via})" if advice.auto_fixable else "no (manual)"
            lines.append(f"     Auto-fix: {auto}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


__all__ = ["path_label", "path_to_dict", "render_report", "severity_band"]
