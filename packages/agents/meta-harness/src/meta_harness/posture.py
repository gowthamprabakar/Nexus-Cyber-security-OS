"""Posture rollup — read-only aggregation of post-scan graph data into board data.

Pure `compute` + explicit persistence. No writes in compute; no OCSF; no graph node.
See docs/superpowers/specs/2026-07-08-posture-rollup-design.md.
"""

from __future__ import annotations

import dataclasses
import json
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from charter.memory.episodic import EpisodicStore
from charter.memory.graph_types import NodeCategory as NC
from charter.memory.semantic import SemanticStore

from meta_harness.attack_paths import AttackPath, AttackPathRanker
from meta_harness.kg_query import KgQuery


# ---- severity bucketing (attack-path severity is an int 0-100) -------------
def bucket_of(severity: int) -> str:
    if severity >= 90:
        return "critical"
    if severity >= 75:
        return "high"
    if severity >= 50:
        return "medium"
    return "low"


# ---- domain vocabulary -----------------------------------------------------
DOMAINS: frozenset[str] = frozenset(
    {"vulnerability", "cloud", "identity", "data", "container", "appsec", "threat", "ai", "network"}
)

# path_type -> product domain (completeness enforced by test against _SEVERITY)
PATH_DOMAIN: dict[str, str] = {
    "crown_jewel": "data",
    "leaked_credential": "identity",
    "public_secret": "identity",
    "runtime_exploit_vulnerable": "threat",
    "malicious_destination": "threat",
    "exposed_database": "data",
    "lateral_movement": "network",
    "supply_chain_sbom": "appsec",
    "internet_exposed_vulnerable": "vulnerability",
    "internet_exposed_host_vulnerable": "vulnerability",
    "lateral_reachable": "network",
    "privileged_vulnerable": "vulnerability",
    "rbac_privilege_escalation": "container",
    "public_unencrypted": "data",
    "kms_key_access": "data",
    "escalation_method_to_data": "identity",
    "exposed_kms_key_over_data": "data",
    "exposed_kms_key": "data",
    "external_trust": "identity",
    "exposed_ai_sensitive_data": "ai",
    "privilege_escalation": "identity",
    "resource_based_data": "data",
    "fine_grained_data": "data",
    "iac_misconfig_deployed": "appsec",
    "cicd_compromise": "appsec",
    "stored_secret_to_data": "identity",
    "k8s_escape_to_cloud_data": "container",
    "rbac_escalation_to_cloud_data": "container",
    "serverless_lambda_exposure": "cloud",
    "imds_credential_theft": "identity",
}

# domain -> representative node categories, for coverage ("did this domain produce data?")
DOMAIN_CATEGORIES: dict[str, tuple[str, ...]] = {
    "vulnerability": (NC.CVE_FINDING.value, NC.SBOM_PACKAGE.value, NC.EXPLOIT_AVAILABILITY.value),
    "cloud": (NC.CLOUD_RESOURCE.value, NC.CLOUD_ACCOUNT.value, NC.MISCONFIGURATION_FINDING.value),
    "identity": (NC.IDENTITY.value, NC.POLICY.value, NC.SECRET.value, NC.SECRET_FINDING.value),
    "data": (NC.DATA_CLASSIFICATION.value, NC.KMS_KEY.value),
    "container": (NC.K8S_CLUSTER.value, NC.K8S_OBJECT.value, NC.CONTAINER_IMAGE.value),
    "appsec": (
        NC.CODE_REPOSITORY.value,
        NC.SAST_FINDING.value,
        NC.IAC_ARTIFACT.value,
        NC.BUILD.value,
    ),
    "threat": (NC.THREAT_INDICATOR.value, NC.THREAT_ACTOR.value, NC.PROCESS_EVENT.value),
    "ai": (NC.AI_SERVICE.value, NC.AI_MODEL.value),
    "network": (NC.NETWORK_PATH.value, NC.NETWORK_FLOW_EVENT.value),
}

FINDING_CATEGORIES: tuple[str, ...] = (
    NC.CVE_FINDING.value,
    NC.MISCONFIGURATION_FINDING.value,
    NC.SECRET_FINDING.value,
    NC.SAST_FINDING.value,
)
INVENTORY_CATEGORIES: tuple[str, ...] = (
    NC.CLOUD_RESOURCE.value,
    NC.IDENTITY.value,
    NC.DATA_CLASSIFICATION.value,
    NC.CONTAINER_IMAGE.value,
    NC.K8S_OBJECT.value,
    NC.CODE_REPOSITORY.value,
    NC.SBOM_PACKAGE.value,
    NC.AI_MODEL.value,
    NC.SAAS_TENANT.value,
)
EXPOSURE_PATH_TYPES: frozenset[str] = frozenset(
    {"internet_exposed_vulnerable", "internet_exposed_host_vulnerable", "supply_chain_sbom"}
)
EPSS_EXPLOITABLE = 0.5


# ---- data model ------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class DomainCount:
    domain: str
    critical: int
    high: int
    medium: int
    low: int
    total: int


@dataclass(frozen=True, slots=True)
class PathTypeCount:
    path_type: str
    count: int
    max_severity: int


@dataclass(frozen=True, slots=True)
class ExposureFunnel:
    exposed: int
    vulnerable: int
    kev: int
    exploitable: int


@dataclass(frozen=True, slots=True)
class Coverage:
    domains_covered: int
    domains_total: int
    domain_pct: int
    collectors_ok: int | None
    collectors_run: int | None
    collector_pct: int | None
    surfaced_findings: int
    total_findings: int
    surfaced_pct: int


@dataclass(frozen=True, slots=True)
class PostureSummary:
    tenant: str
    scan_at: str
    coverage: Coverage
    totals: dict[str, int]
    severity_distribution: dict[str, int]
    by_domain: tuple[DomainCount, ...]
    by_path_type: tuple[PathTypeCount, ...]
    exposure_funnel: ExposureFunnel
    inventory_counts: dict[str, int]
    top_paths: tuple[dict[str, Any], ...]


@dataclass(frozen=True, slots=True)
class TrendPoint:
    at: str
    attack_paths: int
    critical: int
    high: int


# ---- pure aggregations over list[AttackPath] --------------------------------
def severity_distribution(paths: list[AttackPath]) -> dict[str, int]:
    out = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for p in paths:
        out[bucket_of(p.severity)] += 1
    return out


def by_path_type(paths: list[AttackPath]) -> tuple[PathTypeCount, ...]:
    count: dict[str, int] = defaultdict(int)
    maxsev: dict[str, int] = defaultdict(int)
    for p in paths:
        count[p.path_type] += 1
        maxsev[p.path_type] = max(maxsev[p.path_type], p.severity)
    rows = [PathTypeCount(pt, count[pt], maxsev[pt]) for pt in count]
    return tuple(sorted(rows, key=lambda r: (-r.max_severity, r.path_type)))


def by_domain(paths: list[AttackPath]) -> tuple[DomainCount, ...]:
    buckets: dict[str, dict[str, int]] = defaultdict(
        lambda: {"critical": 0, "high": 0, "medium": 0, "low": 0}
    )
    for p in paths:
        domain = PATH_DOMAIN.get(p.path_type, "other")
        buckets[domain][bucket_of(p.severity)] += 1
    rows = [
        DomainCount(
            d,
            b["critical"],
            b["high"],
            b["medium"],
            b["low"],
            b["critical"] + b["high"] + b["medium"] + b["low"],
        )
        for d, b in buckets.items()
    ]
    return tuple(sorted(rows, key=lambda r: (-r.total, r.domain)))


def exposure_funnel(paths: list[AttackPath]) -> ExposureFunnel:
    exposure = [p for p in paths if p.path_type in EXPOSURE_PATH_TYPES]
    exposed = len(exposure)
    vulnerable = sum(1 for p in exposure if p.count >= 1)
    kev = sum(1 for p in exposure if p.kev)
    exploitable = sum(1 for p in exposure if p.epss is not None and p.epss > EPSS_EXPLOITABLE)
    return ExposureFunnel(exposed=exposed, vulnerable=vulnerable, kev=kev, exploitable=exploitable)


# ---- store-derived helpers -------------------------------------------------
def _pct(num: int, den: int) -> int:
    return round(num / den * 100) if den else 0


def _all_counted() -> tuple[str, ...]:
    seen: dict[str, None] = {}
    for c in (*INVENTORY_CATEGORIES, *FINDING_CATEGORIES):
        seen[c] = None
    for cats in DOMAIN_CATEGORIES.values():
        for c in cats:
            seen[c] = None
    return tuple(seen)


async def count_categories(
    store: SemanticStore, tenant: str, categories: tuple[str, ...]
) -> dict[str, int]:
    out: dict[str, int] = {}
    for cat in categories:
        rows = await store.list_entities_by_type(tenant_id=tenant, entity_type=cat)
        out[cat] = len(rows)
    return out


async def compute_coverage(
    store: SemanticStore,
    tenant: str,
    paths: list[AttackPath],
    feeders: Sequence[object] | None,
    *,
    category_counts: dict[str, int],
) -> Coverage:
    # domain coverage — a domain is "covered" if any of its categories has >=1 node
    domains_covered = sum(
        1 for cats in DOMAIN_CATEGORIES.values() if any(category_counts.get(c, 0) > 0 for c in cats)
    )
    domains_total = len(DOMAIN_CATEGORIES)

    # collector coverage — from FeederOutcome.ok (None when no feeder context)
    collectors_ok: int | None = None
    collectors_run: int | None = None
    collector_pct: int | None = None
    if feeders is not None:
        collectors_run = len(feeders)
        collectors_ok = sum(1 for f in feeders if getattr(f, "ok", False))
        collector_pct = _pct(collectors_ok, collectors_run)

    # surfaced ratio — distinct finding entity ids that appear on any path
    total_findings = sum(category_counts.get(c, 0) for c in FINDING_CATEGORIES)
    finding_ids: set[str] = set()
    for cat in FINDING_CATEGORIES:
        for row in await store.list_entities_by_type(tenant_id=tenant, entity_type=cat):
            finding_ids.add(row.entity_id)
    on_paths: set[str] = set()
    for p in paths:
        on_paths.update(p.entities)
    surfaced_findings = len(finding_ids & on_paths)

    return Coverage(
        domains_covered=domains_covered,
        domains_total=domains_total,
        domain_pct=_pct(domains_covered, domains_total),
        collectors_ok=collectors_ok,
        collectors_run=collectors_run,
        collector_pct=collector_pct,
        surfaced_findings=surfaced_findings,
        total_findings=total_findings,
        surfaced_pct=_pct(surfaced_findings, total_findings),
    )


# ---- orchestration ---------------------------------------------------------
_TOP_N = 10


class PostureRollup:
    """Read-only rollup of the post-scan graph into a PostureSummary. Tenant-scoped."""

    def __init__(self, store: SemanticStore, tenant: str) -> None:
        self._store = store
        self._tenant = tenant

    async def compute(
        self,
        *,
        now: datetime,
        paths: list[AttackPath] | None = None,
        feeders: Sequence[object] | None = None,
    ) -> PostureSummary:
        if paths is None:
            paths = await AttackPathRanker(KgQuery(self._store, self._tenant)).find_all()

        counts = await count_categories(self._store, self._tenant, _all_counted())
        coverage = await compute_coverage(
            self._store, self._tenant, paths, feeders, category_counts=counts
        )
        inventory = {c: counts.get(c, 0) for c in INVENTORY_CATEGORIES}
        totals = {
            "attack_paths": len(paths),
            "findings": sum(counts.get(c, 0) for c in FINDING_CATEGORIES),
            "nodes": sum(counts.values()),
        }
        top = tuple(
            {
                "path_type": p.path_type,
                "severity": p.severity,
                "title": p.title,
                "kev": p.kev,
                "epss": p.epss,
            }
            for p in paths[:_TOP_N]
        )
        return PostureSummary(
            tenant=self._tenant,
            scan_at=now.isoformat(),
            coverage=coverage,
            totals=totals,
            severity_distribution=severity_distribution(paths),
            by_domain=by_domain(paths),
            by_path_type=by_path_type(paths),
            exposure_funnel=exposure_funnel(paths),
            inventory_counts=inventory,
            top_paths=top,
        )


def summary_to_dict(summary: PostureSummary) -> dict[str, Any]:
    return dataclasses.asdict(summary)


def write_posture_json(summary: PostureSummary, workspace_root: Path) -> Path:
    out_dir = workspace_root / "aggregation"
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "posture.json"
    path.write_text(json.dumps(summary_to_dict(summary), indent=2, sort_keys=True))
    return path


def render_posture_summary(summary: PostureSummary) -> str:
    c = summary.coverage
    parts = [f"**Coverage:** {c.domain_pct}% of domains ({c.domains_covered}/{c.domains_total})"]
    if c.collector_pct is not None:
        parts.append(f"{c.collector_pct}% of collectors ({c.collectors_ok}/{c.collectors_run})")
    parts.append(
        f"{c.surfaced_pct}% of findings surfaced ({c.surfaced_findings}/{c.total_findings})"
    )
    lines = [" · ".join(parts), ""]
    d = summary.severity_distribution
    lines.append(
        f"**Attack paths:** {summary.totals['attack_paths']} "
        f"(critical {d['critical']} · high {d['high']} · medium {d['medium']} · low {d['low']})"
    )
    lines.append("")
    lines.append("**By domain:**")
    for row in summary.by_domain:
        lines.append(
            f"- {row.domain}: {row.total} (C{row.critical} H{row.high} M{row.medium} L{row.low})"
        )
    f = summary.exposure_funnel
    lines.append("")
    lines.append(
        f"**Exposure funnel:** {f.exposed} exposed → {f.vulnerable} vulnerable"
        f" → {f.kev} KEV → {f.exploitable} exploitable"
    )
    return "\n".join(lines)


# ---- cross-scan trend snapshots via episodic memory --------------------------
SNAPSHOT_ACTION = "posture_snapshot"
SNAPSHOT_AGENT = "posture-rollup"


async def emit_posture_snapshot(
    episodic: EpisodicStore, tenant: str, summary: PostureSummary, *, correlation_id: str
) -> None:
    await episodic.append_event(
        tenant_id=tenant,
        correlation_id=correlation_id,
        agent_id=SNAPSHOT_AGENT,
        action=SNAPSHOT_ACTION,
        payload={
            "at": summary.scan_at,
            "totals": summary.totals,
            "severity_distribution": summary.severity_distribution,
        },
    )


async def posture_trend(
    episodic: EpisodicStore, tenant: str, *, limit: int = 30
) -> list[TrendPoint]:
    # query_recent returns DESC; over-fetch to survive interleaved actions, filter, reverse to ASC.
    rows = await episodic.query_recent(tenant_id=tenant, limit=max(limit * 4, 100))
    snaps = [r for r in rows if r.action == SNAPSHOT_ACTION]
    snaps.reverse()
    points = [
        TrendPoint(
            at=str(r.payload.get("at", "")),
            attack_paths=int(r.payload.get("totals", {}).get("attack_paths", 0)),
            critical=int(r.payload.get("severity_distribution", {}).get("critical", 0)),
            high=int(r.payload.get("severity_distribution", {}).get("high", 0)),
        )
        for r in snaps
    ]
    return points[-limit:]
