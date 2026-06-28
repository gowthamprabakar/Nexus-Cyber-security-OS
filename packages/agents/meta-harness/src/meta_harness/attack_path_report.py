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
    from meta_harness.path_engine import CandidatePath

#: Numeric severity → a triage band a human reads at a glance.
_BANDS = ((90, "CRITICAL"), (70, "HIGH"), (50, "MEDIUM"), (0, "LOW"))

#: path_type → a short human label (fallback: title-case the type).
_LABELS = {
    "crown_jewel": "Crown jewel",
    "leaked_credential": "Leaked cloud credential in code",
    "public_secret": "Public secret",
    "runtime_exploit_vulnerable": "Active exploit on vulnerable workload",
    "malicious_destination": "Communicating with malicious IP",
    "lateral_movement": "Network lateral movement",
    "exposed_database": "Exposed managed database",
    "exposed_kms_key": "Exposed KMS key policy",
    "internet_exposed_vulnerable": "Internet-exposed vulnerable workload",
    "internet_exposed_host_vulnerable": "Internet-exposed vulnerable host (EC2/VM)",
    "privileged_vulnerable": "Privileged vulnerable workload",
    "rbac_privilege_escalation": "K8s RBAC privilege escalation",
    "public_unencrypted": "Public unencrypted data",
    "external_trust": "External trust",
    "privilege_escalation": "Privilege escalation",
    "exposed_ai_sensitive_data": "Exposed AI service",
    "resource_based_data": "Resource-based access",
    "fine_grained_data": "Over-permissioned access",
    "iac_misconfig_deployed": "Misconfigured IaC deployed",
}


#: source/sink marker → a human noun phrase (BP3 explainable render).
_MARKER_PHRASE = {
    "public_resource": "Public resource",
    "resource_policy_grant": "Resource with a policy grant",
    "external_identity": "Externally-trusted identity",
    "identity_principal": "Identity principal",
    "privileged_workload": "Privileged workload",
    "exposed_ai_service": "Exposed AI service",
    "runtime_detection": "Active runtime detection",
    "runtime_detection_file": "Active file-integrity detection",
    "sensitive_data": "sensitive data",
    "known_vulnerability": "a known vulnerability",
}

#: edge type → a verb phrase, so a hop reads as English (fallback: the lower-cased edge name).
_EDGE_PHRASE = {
    "HAS_ACCESS_TO": "has access to",
    "ASSUMES": "can assume",
    "RUNS_IMAGE": "runs image",
    "VULNERABLE_TO": "is vulnerable to",
    "EXPOSES_DATA": "exposes",
    "CONTAINS": "contains",
    "EXPOSES_MODEL": "exposes model",
    "OWNED_BY": "is owned by",
    "COMMUNICATES_WITH": "communicates with",
    "MATCHES_INDICATOR": "matches threat indicator",
    "EXECUTED_ON": "executed on",
    "DEPLOYED_VIA": "was deployed via",
    "DEFINED_IN": "is defined in",
}


def _short_label(external_id: str) -> str:
    """The last meaningful segment of an ARN/URI/key — a readable handle for a node in the story."""
    tail = external_id.rsplit("/", 1)[-1].rsplit(":", 1)[-1]
    return tail or external_id


def candidate_story(path: object) -> str:
    """A one-sentence English walk of a candidate path: nodes by label, hops by verb (BP3).

    e.g. ``Public resource `acme-creds` contains `mid`, which exposes `ssn` (sensitive data)`` —
    a reviewer reads what the path *means*, not an edge-type signature.
    """
    labels = path.node_labels  # type: ignore[attr-defined]
    src = _MARKER_PHRASE.get(path.source_marker, path.source_marker)  # type: ignore[attr-defined]
    parts = [f"{src} `{_short_label(labels[0])}`"]
    for i, hop in enumerate(path.hops):  # type: ignore[attr-defined]
        verb = _EDGE_PHRASE.get(hop.edge_type, hop.edge_type.lower().replace("_", " "))
        linker = "" if i == 0 else ", which"
        parts.append(f"{linker} {verb} `{_short_label(labels[i + 1])}`")
    sink = _MARKER_PHRASE.get(path.sink_marker, path.sink_marker)  # type: ignore[attr-defined]
    return "".join(parts) + f" ({sink})"


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


def candidate_to_dict(candidate: CandidatePath) -> dict[str, object]:
    """JSON-serializable view of one generic-engine candidate path (for an API / review queue)."""
    p = candidate.path
    return {
        "source": p.source_marker,
        "sink": p.sink_marker,
        "edge_signature": list(p.edge_signature),
        "hops": len(p.hops),
        "score": candidate.score,
        "confidence": candidate.confidence,
        "story": candidate_story(p),
        "node_labels": list(p.node_labels),
    }


def render_candidates(candidates: Sequence[CandidatePath], *, tenant_id: str) -> str:
    """The candidate tier — novel source→impact paths the generic engine found, clearly UNVERIFIED.

    Separate from :func:`render_report` (the confirmed, named findings) by design: candidates are
    heuristically scored and unverified, a "what should we name next?" review queue, never mixed into
    the prioritized confirmed list.
    """
    if not candidates:
        return f"No candidate attack paths for tenant {tenant_id}."

    lines = [
        f"Candidate attack paths for tenant {tenant_id} ({len(candidates)} found — UNVERIFIED, "
        "review to promote to a named detector):",
        "",
    ]
    for i, c in enumerate(candidates, start=1):
        p = c.path
        lines.append(f"  {i}. [candidate {c.score}] {candidate_story(p)}")
        chain = " -> ".join(p.edge_signature)
        lines.append(
            f"     shape: {p.source_marker} -> {p.sink_marker} via {chain} "
            f"({len(p.hops)} hop{'s' if len(p.hops) != 1 else ''})"
        )
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


__all__ = [
    "candidate_story",
    "candidate_to_dict",
    "path_label",
    "path_to_dict",
    "render_candidates",
    "render_report",
    "severity_band",
]
