"""Declarative attack-path taxonomy — the foundation of the generic engine (Track B, B1).

The named detectors encode their attack-path shape as inline ``if`` checks: a SOURCE (where an
attacker starts — an exposure), a hardcoded edge path, and a SINK (where impact lands — sensitive
data or an exploitable vuln). This module lifts those implicit markers into ONE declarative model:

- :data:`SOURCE_MARKERS` — node predicates that make a node an attack source (exposure).
- :data:`SINK_MARKERS` — node predicates that make a node an impact sink.
- :data:`TRAVERSABLE_EDGES` — the attack-progressing edge types the generic walker may follow
  (the ~20 live ones; control-plane/audit/compliance edges like AFFECTS / MAPS_TO_REQUIREMENT /
  REMEDIATES are NOT attack progression and are excluded).

B1 is depth-independent and walker-free: a companion test proves every named archetype's
(source, sink, edges) shape is expressible here. If one isn't, the taxonomy is wrong — fix it
before the generic walker (B2) is built on top of it.

Scope: the model targets **exposure → (sensitive data | vulnerability)** paths — the core attack
shape and where novel multi-hop combinations live. Two named archetypes are a different correlation
shape and out of this model by design (threat-presence: ``malicious_destination``; provenance:
``iac_misconfig_deployed``); they stay named-only. The companion test documents this explicitly.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from charter.memory.graph_types import EdgeType, NodeCategory


@dataclass(frozen=True, slots=True)
class NodeMarker:
    """A named predicate over a node's (category, properties) — a source or sink classifier."""

    name: str
    category: NodeCategory
    predicate: Callable[[Mapping[str, Any]], bool]

    def matches(self, category: str, properties: Mapping[str, Any]) -> bool:
        return category == self.category.value and self.predicate(properties)


def _always(_: Mapping[str, Any]) -> bool:
    return True


#: Scope tokens that mark an OAuth app as over-privileged across providers (Slack "admin",
#: M365 "*.ReadWrite.*", Google "*/auth/admin..."). A read-only app is not an exposure.
_PRIVILEGED_SCOPE_TOKENS = ("admin", "write", "owner", "manage", "full")


def _over_scoped(p: Mapping[str, Any]) -> bool:
    return any(
        any(tok in str(scope).lower() for tok in _PRIVILEGED_SCOPE_TOKENS)
        for scope in (p.get("scopes") or [])
    )


#: Where an attack STARTS — an exposure / foothold. Order is most-specific-first (the first match
#: wins in :func:`match_source`), so ``external_identity`` is checked before the catch-all principal.
SOURCE_MARKERS: tuple[NodeMarker, ...] = (
    NodeMarker(
        "public_resource", NodeCategory.CLOUD_RESOURCE, lambda p: p.get("is_public") is True
    ),
    NodeMarker(
        "resource_policy_grant",
        NodeCategory.CLOUD_RESOURCE,
        lambda p: bool(p.get("policy_readers")),
    ),
    NodeMarker(
        "external_identity", NodeCategory.IDENTITY, lambda p: p.get("external_trust") is True
    ),
    NodeMarker("identity_principal", NodeCategory.IDENTITY, _always),
    NodeMarker(
        "privileged_workload", NodeCategory.K8S_OBJECT, lambda p: p.get("privileged") is True
    ),
    NodeMarker("exposed_ai_service", NodeCategory.AI_SERVICE, _always),
    NodeMarker("runtime_detection", NodeCategory.PROCESS_EVENT, _always),
    NodeMarker("runtime_detection_file", NodeCategory.FILE_INTEGRITY_EVENT, _always),
    # BP6: an over-scoped third-party OAuth app is an external foothold into a SaaS tenant.
    NodeMarker("over_scoped_oauth_app", NodeCategory.OAUTH_APP, _over_scoped),
    # slice #3: a credential leaked in code (appsec ``leaked=True``) is a foothold — its blast
    # radius is everything its owning identity can reach. A merely-inventoried key is not a source.
    NodeMarker("leaked_credential", NodeCategory.SECRET, lambda p: p.get("leaked") is True),
)

#: Where IMPACT lands — a data breach, an exploitable vulnerability, or (BP6) a stolen AI model /
#: a reachable SaaS workspace (impact domains the engine was previously blind to).
SINK_MARKERS: tuple[NodeMarker, ...] = (
    NodeMarker("sensitive_data", NodeCategory.DATA_CLASSIFICATION, _always),
    NodeMarker("known_vulnerability", NodeCategory.CVE_FINDING, _always),
    NodeMarker("ai_model", NodeCategory.AI_MODEL, _always),
    NodeMarker("saas_tenant", NodeCategory.SAAS_TENANT, _always),
)

#: The attack-progressing edges the generic walker may traverse (directional, as written).
TRAVERSABLE_EDGES: frozenset[str] = frozenset(
    e.value
    for e in (
        EdgeType.HAS_ACCESS_TO,
        EdgeType.ASSUMES,
        EdgeType.RUNS_IMAGE,
        EdgeType.VULNERABLE_TO,
        EdgeType.EXPOSES_DATA,
        EdgeType.CONTAINS,
        EdgeType.EXPOSES_MODEL,
        EdgeType.OWNED_BY,
        EdgeType.COMMUNICATES_WITH,
        EdgeType.MATCHES_INDICATOR,
        EdgeType.EXECUTED_ON,
        EdgeType.DEPLOYED_VIA,
        EdgeType.DEFINED_IN,
        EdgeType.SERVES_MODEL,  # BP6: AI service → the model it serves (model theft/abuse)
        EdgeType.AUTHORIZED,  # BP6: OAuth app → the SaaS tenant it can act on
        EdgeType.CAN_ESCALATE_TO,  # slice #1: principal → admin it can escalate to (privesc)
    )
)


def match_source(category: str, properties: Mapping[str, Any]) -> str | None:
    """The name of the first source marker matching this node, or ``None``."""
    return next((m.name for m in SOURCE_MARKERS if m.matches(category, properties)), None)


def match_sink(category: str, properties: Mapping[str, Any]) -> str | None:
    """The name of the first sink marker matching this node, or ``None``."""
    return next((m.name for m in SINK_MARKERS if m.matches(category, properties)), None)


def is_traversable(edge_type: str) -> bool:
    """Whether an edge type is attack-progression (the generic walker may follow it)."""
    return edge_type in TRAVERSABLE_EDGES


__all__ = [
    "SINK_MARKERS",
    "SOURCE_MARKERS",
    "TRAVERSABLE_EDGES",
    "NodeMarker",
    "is_traversable",
    "match_sink",
    "match_source",
]
