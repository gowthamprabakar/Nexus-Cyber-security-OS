"""Findings router — vulnerabilities list + detail (Endpoints 2 & 3).

A finding = a CVE on a resource, joined across the ``VULNERABLE_TO`` edge
(resource → CVE). The CVE node carries severity/kev/epss/cvss/cwe/description;
the edge carries package + fix_version.
"""

from __future__ import annotations

from typing import Any

from charter.memory.graph_types import EdgeType, NodeCategory
from charter.memory.semantic import SemanticStore
from fastapi import APIRouter, Depends, HTTPException, Query

from read_api.deps import (
    Envelope,
    get_store,
    make_envelope,
    require_entitlement,
    require_tenant,
)

router = APIRouter(
    prefix="/findings",
    tags=["findings"],
    dependencies=[Depends(require_entitlement("findings", "read"))],
)

_VULN_TO = (EdgeType.VULNERABLE_TO.value,)
_SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
_SEV_NAME = {rank: name for name, rank in _SEV_RANK.items()}


async def _catalog_rows(store: SemanticStore, tenant: str) -> list[dict[str, Any]]:
    """One row per unique CVE (deduplicated) with its direct affected-resource count.

    Unlike ``_vuln_rows`` (one row per resource-CVE pair), the catalog collapses to
    the CVE and counts how many resources carry a direct VULNERABLE_TO edge into it.
    Ranked worst-first: KEV, then severity, then EPSS, then blast radius.
    """
    cves = {
        c.entity_id: c
        for c in await store.list_entities_by_type(
            tenant_id=tenant, entity_type=NodeCategory.CVE_FINDING.value
        )
    }
    affected: dict[str, int] = {}
    for res in await store.list_entities_by_type(
        tenant_id=tenant, entity_type=NodeCategory.CLOUD_RESOURCE.value
    ):
        for rel in await store.get_relationships_from(
            tenant_id=tenant, src_entity_id=res.entity_id, edge_types=_VULN_TO
        ):
            if rel.dst_entity_id in cves:
                affected[rel.dst_entity_id] = affected.get(rel.dst_entity_id, 0) + 1

    rows: list[dict[str, Any]] = []
    for eid, cve in cves.items():
        props = cve.properties
        rows.append(
            {
                "cve_id": cve.external_id,
                "severity": str(props.get("severity", "")),
                "kev": bool(props.get("kev", False)),
                "epss": props.get("epss_score"),
                "affected_resources": affected.get(eid, 0),
            }
        )
    rows.sort(
        key=lambda r: (
            r["kev"],
            _SEV_RANK.get(str(r["severity"]).upper(), 0),
            r["epss"] or 0.0,
            r["affected_resources"],
        ),
        reverse=True,
    )
    return rows


async def _vuln_rows(store: SemanticStore, tenant: str) -> list[dict[str, Any]]:
    """One row per (resource, CVE) VULNERABLE_TO edge, joined to the CVE node's props."""
    cves = {
        c.entity_id: c
        for c in await store.list_entities_by_type(
            tenant_id=tenant, entity_type=NodeCategory.CVE_FINDING.value
        )
    }
    resources = await store.list_entities_by_type(
        tenant_id=tenant, entity_type=NodeCategory.CLOUD_RESOURCE.value
    )
    rows: list[dict[str, Any]] = []
    for res in resources:
        rels = await store.get_relationships_from(
            tenant_id=tenant, src_entity_id=res.entity_id, edge_types=_VULN_TO
        )
        for rel in rels:
            cve = cves.get(rel.dst_entity_id)
            if cve is None:
                continue
            props = cve.properties
            rows.append(
                {
                    "cve_id": cve.external_id,
                    "severity": str(props.get("severity", "")),
                    "kev": bool(props.get("kev", False)),
                    "epss": props.get("epss_score"),
                    "resource": res.external_id,
                    "component": str(rel.properties.get("package", "")),
                    "fix_version": str(rel.properties.get("fix_version", "")),
                    "status": "open",
                }
            )
    return rows


async def _available_fixes(store: SemanticStore, tenant: str) -> list[dict[str, Any]]:
    """Group findings that carry a fix_version by patch action (component, fix_version).

    One row per actionable upgrade with its blast radius — how many CVEs it clears,
    across how many resources, at what worst severity. Ranked most-impactful first.
    This is the "available fixes" surface of the Patch chapter (lifecycle/deployment
    tracking is the chapter's own scope).
    """
    groups: dict[tuple[str, str], dict[str, Any]] = {}
    for r in await _vuln_rows(store, tenant):
        fix = str(r["fix_version"])
        component = str(r["component"])
        # An "upgrade <package> to <version>" action is only actionable with both
        # a named package and a target version; skip findings missing either so
        # nameless findings never merge into one bogus "—" patch row.
        if not fix or not component:
            continue
        group = groups.setdefault(
            (component, fix),
            {"component": component, "fix_version": fix, "_cves": set(), "_res": set(), "_sev": 0},
        )
        group["_cves"].add(r["cve_id"])
        group["_res"].add(r["resource"])
        group["_sev"] = max(group["_sev"], _SEV_RANK.get(str(r["severity"]).upper(), 0))

    rows = [
        {
            "component": g["component"],
            "fix_version": g["fix_version"],
            "cve_count": len(g["_cves"]),
            "resource_count": len(g["_res"]),
            "max_severity": _SEV_NAME.get(g["_sev"], ""),
        }
        for g in groups.values()
    ]
    rows.sort(key=lambda x: (x["cve_count"], x["resource_count"]), reverse=True)
    return rows


@router.get("/vulnerabilities", response_model=Envelope)
async def list_vulnerabilities(
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=500),
    severity: str | None = Query(default=None),
    kev: bool | None = Query(default=None),
    tenant: str = Depends(require_tenant),
    store: SemanticStore = Depends(get_store),  # noqa: B008
) -> Envelope:
    """Vulnerability findings (one per resource-CVE pair), tenant-scoped, paginated."""
    rows = await _vuln_rows(store, tenant)
    if severity is not None:
        rows = [r for r in rows if str(r["severity"]).lower() == severity.lower()]
    if kev is not None:
        rows = [r for r in rows if r["kev"] == kev]
    total = len(rows)
    page = rows[offset : offset + limit]
    next_offset: int | None = offset + limit if offset + limit < total else None
    return make_envelope(data=page, offset=next_offset, total=total, tenant=tenant)


@router.get("/catalog", response_model=Envelope)
async def list_catalog(
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=500),
    severity: str | None = Query(default=None),
    kev: bool | None = Query(default=None),
    tenant: str = Depends(require_tenant),
    store: SemanticStore = Depends(get_store),  # noqa: B008
) -> Envelope:
    """CVE catalog — one row per unique CVE, ranked worst-first, tenant-scoped, paginated."""
    rows = await _catalog_rows(store, tenant)
    if severity is not None:
        rows = [r for r in rows if str(r["severity"]).lower() == severity.lower()]
    if kev is not None:
        rows = [r for r in rows if r["kev"] == kev]
    total = len(rows)
    page = rows[offset : offset + limit]
    next_offset: int | None = offset + limit if offset + limit < total else None
    return make_envelope(data=page, offset=next_offset, total=total, tenant=tenant)


@router.get("/available-fixes", response_model=Envelope)
async def list_available_fixes(
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=500),
    tenant: str = Depends(require_tenant),
    store: SemanticStore = Depends(get_store),  # noqa: B008
) -> Envelope:
    """Available fixes — patch actions ranked by blast radius, tenant-scoped, paginated."""
    rows = await _available_fixes(store, tenant)
    total = len(rows)
    page = rows[offset : offset + limit]
    next_offset: int | None = offset + limit if offset + limit < total else None
    return make_envelope(data=page, offset=next_offset, total=total, tenant=tenant)


@router.get("/vulnerabilities/{cve_id}", response_model=Envelope)
async def get_vulnerability(
    cve_id: str,
    tenant: str = Depends(require_tenant),
    store: SemanticStore = Depends(get_store),  # noqa: B008
) -> Envelope:
    """Detail for one CVE: node fields + affected resources + advisory remediation."""
    cves = await store.list_entities_by_type(
        tenant_id=tenant, entity_type=NodeCategory.CVE_FINDING.value
    )
    cve = next((c for c in cves if c.external_id == cve_id), None)
    if cve is None:
        raise HTTPException(status_code=404, detail=f"CVE {cve_id} not found")
    props = cve.properties

    # Affected resources: those with a VULNERABLE_TO edge into this CVE. There is no
    # incoming-edge query, so scan resources' outgoing edges — fine at v1 volumes.
    affected: list[str] = []
    component = ""
    fix_version = ""
    for res in await store.list_entities_by_type(
        tenant_id=tenant, entity_type=NodeCategory.CLOUD_RESOURCE.value
    ):
        for rel in await store.get_relationships_from(
            tenant_id=tenant, src_entity_id=res.entity_id, edge_types=_VULN_TO
        ):
            if rel.dst_entity_id == cve.entity_id:
                affected.append(res.external_id)
                component = component or str(rel.properties.get("package", ""))
                fix_version = fix_version or str(rel.properties.get("fix_version", ""))

    advice = (
        f"Upgrade {component or 'the affected package'} to {fix_version}"
        if fix_version
        else "No fix version available yet"
    )
    detail = {
        "cve_id": cve.external_id,
        "severity": str(props.get("severity", "")),
        "kev": bool(props.get("kev", False)),
        "epss": props.get("epss_score"),
        "cvss_v3_score": props.get("cvss_v3_score"),
        "cwe": props.get("cwe", []),
        "description": props.get("description", ""),
        "component": component,
        "fix_version": fix_version,
        "affected_resources": affected,
        "first_seen": cve.created_at.isoformat() if cve.created_at else None,
        "remediation": {"tier": "advisory", "advice": advice},
    }
    return make_envelope(data=detail, offset=None, total=None, tenant=tenant)
