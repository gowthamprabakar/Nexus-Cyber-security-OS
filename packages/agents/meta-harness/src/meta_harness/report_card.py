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
from meta_harness.belief import route_probability, sink_probability
from meta_harness.kg_query import KgQuery
from meta_harness.path_engine import find_candidate_paths
from meta_harness.path_priors import leaf_probability

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
    "kms_key_access": "Scope the KMS key policy + kms:Decrypt grant to least privilege.",
    "supply_chain_sbom": "Bump the vulnerable dependency to a patched version, then rebuild and redeploy the image.",
    "network_topology_lateral": "Remove or tighten the VPC peering; restrict cross-VPC security-group ingress.",
    "container_escape": "Drop the pod's privileged securityContext; scope its service-account/IRSA role to least privilege.",
    "stored_secret_to_data": "Remove the hard-coded credential from the workload and use a secrets manager; rotate the key now.",
    "k8s_escape_to_cloud_data": "Drop the pod's privileged securityContext; scope the SA's IRSA role to least privilege.",
    "escalation_method_to_data": "Remove the escalation-enabling grant (PassRole / CreatePolicyVersion / AttachUserPolicy) and scope the principal to least privilege.",
}
#: Severity for generic-only families not in the named `_SEVERITY` map (report-card local).
_GENERIC_SEVERITY: dict[str, int] = {"supply_chain_sbom": 80, "container_escape": 78}
_DEFAULT_FIX = "Review this exposure and apply least privilege."
_DEFAULT_SEVERITY = 50


#: path_types that begin at an internet-facing exposure (reachable from outside → more exploitable).
_INTERNET_FACING: frozenset[str] = frozenset(
    {
        "crown_jewel",
        "public_secret",
        "public_unencrypted",
        "internet_exposed_vulnerable",
        "internet_exposed_host_vulnerable",
        "lateral_movement",
        "network_topology_lateral",
        "supply_chain_sbom",
        "exposed_database",
        "exposed_kms_key",
        "runtime_exploit_vulnerable",
    }
)


def _exploitability(severity: int, path_type: str, *, kev: bool) -> int:
    """NEX-403: deterministic exploitability score — base severity weighted by real reachability.

    ``+15`` if the path exploits a CISA Known-Exploited (KEV) vulnerability (weaponized in the wild),
    ``+8`` if it begins at an internet-facing exposure. So an internet-facing KEV path outranks an
    internal, same-base-severity one. Deterministic (no Bayesian — that is a measured v0.5 step)."""
    return severity + (15 if kev else 0) + (8 if path_type in _INTERNET_FACING else 0)


@dataclass(frozen=True, slots=True)
class AttackPathCard:
    """One ranked row of the report card — what the customer sees and acts on."""

    rank: int
    severity: int
    path_type: str
    title: str
    chain: tuple[str, ...]
    fix: str
    exploitability: int = 0  # NEX-403: severity weighted by KEV + internet-facing (the rank key)
    blast_radius: int = 1  # NEX-404: distinct sensitive-data stores this path's principal can reach
    probability: float = 0.0  # v0.5: this route's own P (belief over its hops)
    expected_loss: float = 0.0  # v0.5: sink_p x blast_radius (the rank key)


def _generic_path_type(path: GenericPath) -> str:
    """Classify a novel generic path into a triage bucket by its most-severe edge / its sink."""
    sig = path.edge_signature
    if "CAN_ESCALATE_TO" in sig:
        # Must match the named detector's path_type so build_report_card dedup checks the right
        # bucket (named_entities_by_type["escalation_method_to_data"]) and suppresses the generic
        # candidate.  Returning "privilege_escalation" here caused a duplicate card.
        return "escalation_method_to_data"
    if "OWNED_BY" in sig and path.source_marker == "leaked_credential":
        return "leaked_credential"
    if "CAN_REACH" in sig or "PEERED_WITH" in sig:
        return "lateral_movement"
    if "CONTAINS_PACKAGE" in sig:
        return "supply_chain_sbom"
    if path.sink_marker == "known_vulnerability":
        return "internet_exposed_vulnerable"
    if path.sink_marker == "ai_model":
        return "exposed_ai_sensitive_data"
    return "fine_grained_data"


def _generic_title(path_type: str, path: GenericPath) -> str:
    """A readable, node-id-free narrative for a generic path (the chain holds the ids)."""
    titles = {
        "escalation_method_to_data": "A principal can escalate to admin and reach sensitive data",
        "privilege_escalation": "A principal can escalate to admin and reach sensitive data",
        "leaked_credential": "A credential leaked in code reaches sensitive data through its owner",
        "lateral_movement": "An internet-exposed foothold can move laterally to a vulnerable host",
        "internet_exposed_vulnerable": "An exposed resource reaches a known vulnerability",
        "exposed_ai_sensitive_data": "An exposed path reaches an AI model",
        "fine_grained_data": "An exposed principal reaches sensitive data",
        "supply_chain_sbom": "A public workload runs an image with a vulnerable dependency",
        "container_escape": "A privileged pod escapes to its cloud role and reaches data",
    }
    return titles.get(path_type, f"Novel attack path ({' → '.join(path.edge_signature)})")


async def build_report_card(
    store: SemanticStore, tenant: str, *, top_n: int = 10
) -> list[AttackPathCard]:
    """Build the ranked, fix-annotated report card for ``tenant`` from the shared graph.

    v0.5: ranked by EXPECTED LOSS = P(sink compromised) x blast_radius, where P(sink) is the
    noisy-OR over every route reaching that sink (the belief network). Named paths contribute
    ``leaf_probability(severity)`` (severity is the curated per-archetype danger); generic paths
    contribute ``route_probability`` over their real edge signature.
    """
    kq = KgQuery(store, tenant)

    async def _labels(entity_ids: tuple[str, ...]) -> tuple[str, ...]:
        out: list[str] = []
        for eid in entity_ids:
            ent = await store.get_entity(tenant_id=tenant, entity_id=eid)
            out.append(ent.external_id if ent is not None else eid)
        return tuple(out)

    principal_reach: dict[str, set[str]] = {}
    for fg in await kq.find_fine_grained_data_exposure():
        principal_reach.setdefault(fg.principal_id, set()).add(fg.data_classification_id)

    def _blast(entity_ids: tuple[str, ...]) -> int:
        reached: set[str] = set()
        for eid in entity_ids:
            reached |= principal_reach.get(eid, set())
        return max(len(reached), 1)

    # row: (severity, path_type, title, chain, entset, kev, blast, sink_id, route_p)
    rows: list[tuple[int, str, str, tuple[str, ...], frozenset[str], bool, int, str, float]] = []

    named_entities_by_type: dict[str, set[str]] = {}
    for ap in await AttackPathRanker(kq).find_all():
        chain = await _labels(ap.entities)
        route_p = leaf_probability(ap.severity, kev=False)
        rows.append(
            (
                ap.severity,
                ap.path_type,
                ap.title,
                chain,
                frozenset(chain),
                False,
                _blast(ap.entities),
                ap.sink_id,
                route_p,
            )
        )
        named_entities_by_type.setdefault(ap.path_type, set()).update(ap.entities)

    for cand in await find_candidate_paths(store, tenant):
        pt = _generic_path_type(cand.path)
        if named_entities_by_type.get(pt, set()) & set(cand.path.node_ids):
            continue
        chain = cand.path.node_labels
        sev = _GENERIC_SEVERITY.get(pt) or _SEVERITY.get(pt, _DEFAULT_SEVERITY)
        leaf = leaf_probability(sev, kev=cand.path.sink_kev)
        route_p = route_probability(leaf, cand.path.edge_signature)
        rows.append(
            (
                sev,
                pt,
                _generic_title(pt, cand.path),
                chain,
                frozenset(chain),
                cand.path.sink_kev,
                _blast(cand.path.node_ids),
                cand.path.sink_id,
                route_p,
            )
        )

    # C2 subsumption (unchanged): drop a bare fine_grained leg fully contained by a richer path.
    richer = [r for r in rows if r[1] != "fine_grained_data"]
    kept = [
        r
        for r in rows
        if not (r[1] == "fine_grained_data" and any(h[0] >= r[0] and r[4] <= h[4] for h in richer))
    ]

    # Belief network: P(sink) = noisy-OR of every kept route reaching that sink.
    routes_by_sink: dict[str, list[float]] = {}
    for r in kept:
        if r[7]:
            routes_by_sink.setdefault(r[7], []).append(r[8])

    def _sink_p(sink_id: str, route_p: float) -> float:
        return sink_probability(routes_by_sink[sink_id]) if sink_id else route_p

    # Rank by expected loss = P(sink) x blast_radius, then own route probability, then title.
    kept.sort(key=lambda r: (-_sink_p(r[7], r[8]) * r[6], -r[8], r[2]))
    return [
        AttackPathCard(
            rank=i + 1,
            severity=sev,
            path_type=pt,
            title=title,
            chain=chain,
            fix=_FIX.get(pt, _DEFAULT_FIX),
            exploitability=_exploitability(sev, pt, kev=kev),
            blast_radius=blast,
            probability=route_p,
            expected_loss=_sink_p(sink_id, route_p) * blast,
        )
        for i, (sev, pt, title, chain, _es, kev, blast, sink_id, route_p) in enumerate(kept[:top_n])
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
        blast = f"{c.blast_radius} data store{'s' if c.blast_radius != 1 else ''} at risk"
        lines += [
            f"## {c.rank}. [P {c.probability:.2f} · loss {c.expected_loss:.2f} · severity {c.severity}] {c.title}",
            f"- **Type:** `{c.path_type}`  ·  **Blast radius:** {blast}",
            f"- **Evidence:** {' → '.join(c.chain)}",  # NEX-405: the concrete path walk
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
