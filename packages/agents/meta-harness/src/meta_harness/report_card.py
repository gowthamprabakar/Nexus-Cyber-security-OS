"""The attack-path report card — the customer-facing deliverable.

"Connect an account → see your top ~10 real attack paths, prioritized, each with a fix." This unifies
the two path sources into ONE ranked list with a remediation per path:

- :meth:`AttackPathRanker.find_all` — the polished NAMED paths (over the pre-existing edges).
- :func:`find_candidate_paths` — the NOVEL multi-hop paths the moat edges produce (``CAN_ESCALATE_TO``
  privesc, ``CAN_REACH`` lateral movement, ``OWNED_BY`` leaked-credential blast radius). These are not
  named archetypes, so the named ranker never surfaces them; the generic engine already novelty-filters
  them against the named shapes, so the two sources do not double-count.

The fix is a path-type→remediation hint (the *what to do*), not yet a live one-click action — that is
the remediation agent's job, linked here in a later pass.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from meta_harness.attack_paths import _SEVERITY, AttackPathRanker
from meta_harness.kg_query import KgQuery
from meta_harness.path_engine import find_candidate_paths

if TYPE_CHECKING:
    from charter.memory import SemanticStore

    from meta_harness.path_engine import GenericPath

#: path_type → the remediation a customer should take (the "with a fix" half of the North Star).
_FIX: dict[str, str] = {
    "crown_jewel": "Patch the vulnerable image and remove the internet exposure; scope the workload's role to least privilege.",
    "leaked_credential": "Rotate and revoke the exposed credential now, then purge it from git history.",
    "public_secret": "Make the resource private and rotate any exposed secret.",
    "runtime_exploit_vulnerable": "Isolate the workload, patch the image, and investigate the active detection.",
    "malicious_destination": "Isolate the resource and investigate the connection to the known-bad destination.",
    "exposed_database": "Remove public ingress from the database and require authentication.",
    "lateral_movement": "Tighten the security group: remove the cross-SG ingress that exposes the private host, and patch its CVE.",
    "internet_exposed_vulnerable": "Patch the vulnerable image and remove the internet exposure.",
    "internet_exposed_host_vulnerable": "Patch the host's OS package and remove the internet exposure.",
    "privileged_vulnerable": "Patch the image and drop the pod's privileged securityContext.",
    "rbac_privilege_escalation": "Remove the role-assignment-write grant from the principal; scope to least privilege.",
    "public_unencrypted": "Make the resource private and enable encryption at rest.",
    "exposed_kms_key": "Add a key-policy condition restricting use and remove broad grants.",
    "external_trust": "Restrict the cross-account/external trust to known principals only.",
    "exposed_ai_sensitive_data": "Restrict access to the AI service and the data it can reach.",
    "privilege_escalation": "Remove the privilege-escalation grant (CreatePolicyVersion / PassRole / roleAssignments-write / setIamPolicy) and scope to least privilege.",
    "resource_based_data": "Scope the resource policy to least privilege and make the bucket private.",
    "fine_grained_data": "Scope the principal's data access to least privilege; make the bucket private.",
    "iac_misconfig_deployed": "Fix the misconfiguration in the IaC template and redeploy.",
}
_DEFAULT_FIX = "Review this exposure and apply least privilege."
_DEFAULT_SEVERITY = 50


@dataclass(frozen=True, slots=True)
class AttackPathCard:
    """One ranked row of the report card — what the customer sees and acts on."""

    rank: int
    severity: int
    path_type: str
    title: str
    chain: tuple[str, ...]
    fix: str


def _generic_path_type(path: GenericPath) -> str:
    """Classify a novel generic path into a triage bucket by its most-severe edge / its sink."""
    sig = path.edge_signature
    if "CAN_ESCALATE_TO" in sig:
        return "privilege_escalation"
    if "OWNED_BY" in sig and path.source_marker == "leaked_credential":
        return "leaked_credential"
    if "CAN_REACH" in sig:
        return "lateral_movement"
    if path.sink_marker == "known_vulnerability":
        return "internet_exposed_vulnerable"
    if path.sink_marker == "ai_model":
        return "exposed_ai_sensitive_data"
    return "fine_grained_data"


def _generic_title(path_type: str, path: GenericPath) -> str:
    """A readable, node-id-free narrative for a generic path (the chain holds the ids)."""
    titles = {
        "privilege_escalation": "A principal can escalate to admin and reach sensitive data",
        "leaked_credential": "A credential leaked in code reaches sensitive data through its owner",
        "lateral_movement": "An internet-exposed foothold can move laterally to a vulnerable host",
        "internet_exposed_vulnerable": "An exposed resource reaches a known vulnerability",
        "exposed_ai_sensitive_data": "An exposed path reaches an AI model",
        "fine_grained_data": "An exposed principal reaches sensitive data",
    }
    return titles.get(path_type, f"Novel attack path ({' → '.join(path.edge_signature)})")


async def build_report_card(
    store: SemanticStore, tenant: str, *, top_n: int = 10
) -> list[AttackPathCard]:
    """Build the ranked, fix-annotated report card for ``tenant`` from the shared graph.

    Merges the named ranker and the novel generic paths into one worst-first list (severity desc,
    then title for stability), assigns ranks, and returns the top ``top_n``.
    """
    kq = KgQuery(store, tenant)
    rows: list[tuple[int, str, str, tuple[str, ...]]] = []  # (severity, path_type, title, chain)

    # The named ranker is authoritative for the path types it covers. Index its paths by
    # (path_type → the entity_ids it touches), so a generic path of the SAME type that overlaps it
    # is the same underlying risk found a second way — suppress it rather than double-count.
    named_entities_by_type: dict[str, set[str]] = {}
    for ap in await AttackPathRanker(kq).find_all():
        rows.append((ap.severity, ap.path_type, ap.title, ap.entities))
        named_entities_by_type.setdefault(ap.path_type, set()).update(ap.entities)

    for cand in await find_candidate_paths(store, tenant):
        pt = _generic_path_type(cand.path)
        if named_entities_by_type.get(pt, set()) & set(cand.path.node_ids):
            continue  # same risk a named detector already reported
        rows.append(
            (
                _SEVERITY.get(pt, _DEFAULT_SEVERITY),
                pt,
                _generic_title(pt, cand.path),
                cand.path.node_labels,
            )
        )

    rows.sort(key=lambda r: (-r[0], r[2]))
    return [
        AttackPathCard(
            rank=i + 1,
            severity=sev,
            path_type=pt,
            title=title,
            chain=chain,
            fix=_FIX.get(pt, _DEFAULT_FIX),
        )
        for i, (sev, pt, title, chain) in enumerate(rows[:top_n])
    ]


def render_report_card(cards: list[AttackPathCard], *, tenant: str) -> str:
    """Render the report card as Markdown — the human-facing artifact."""
    if not cards:
        return f"# Attack Path Report Card — {tenant}\n\nNo attack paths found. ✅\n"
    lines = [
        f"# Attack Path Report Card — {tenant}",
        "",
        f"**{len(cards)} attack path(s)** shown, worst first.",
        "",
    ]
    for c in cards:
        lines += [
            f"## {c.rank}. [severity {c.severity}] {c.title}",
            f"- **Type:** `{c.path_type}`",
            f"- **Involves:** {', '.join(c.chain)}",
            f"- **Fix:** {c.fix}",
            "",
        ]
    return "\n".join(lines)


async def render_tenant_report_card(store: SemanticStore, tenant: str, *, top_n: int = 10) -> str:
    """The single entry point (W1): a tenant's populated graph → the rendered Markdown report card.

    Build + render in one call — what a caller (CLI / API / correlation runner) invokes after the
    agents have populated the shared graph. Read-only.
    """
    return render_report_card(await build_report_card(store, tenant, top_n=top_n), tenant=tenant)


__all__ = [
    "AttackPathCard",
    "build_report_card",
    "render_report_card",
    "render_tenant_report_card",
]
