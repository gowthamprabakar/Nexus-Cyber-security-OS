"""Inventory router — cloud-resources endpoint (Endpoint 1)."""

from __future__ import annotations

from typing import Any

from charter.memory.graph_types import EdgeType, NodeCategory
from charter.memory.semantic import SemanticStore
from fastapi import APIRouter, Depends, Query

from read_api.deps import Envelope, get_store, make_envelope, require_tenant

router = APIRouter(prefix="/inventory", tags=["inventory"])

_VULN_TO = (EdgeType.VULNERABLE_TO.value,)


def _derive_cloud(external_id: str, kind: str) -> str:
    """Derive the cloud provider from the external_id or kind prefix."""
    if external_id.startswith("arn:aws"):
        return "aws"
    if kind.startswith("azure-"):
        return "azure"
    if kind.startswith("gcp-"):
        return "gcp"
    return "unknown"


@router.get("/cloud-resources", response_model=Envelope)
async def list_cloud_resources(
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=500),
    kind: str | None = Query(default=None),
    public: bool | None = Query(default=None),
    tenant: str = Depends(require_tenant),
    store: SemanticStore = Depends(get_store),  # noqa: B008
) -> Envelope:
    """Return all CLOUD_RESOURCE nodes for the tenant, paginated."""
    rows = await store.list_entities_by_type(
        tenant_id=tenant,
        entity_type=NodeCategory.CLOUD_RESOURCE.value,
    )

    items: list[dict[str, Any]] = []
    for row in rows:
        row_kind: str = row.properties.get("kind", "")
        row_is_public: bool = bool(row.properties.get("is_public", False))
        row_region: str | None = row.properties.get("region")

        if kind is not None and row_kind != kind:
            continue
        if public is not None and row_is_public != public:
            continue

        items.append(
            {
                "id": row.external_id,
                "kind": row_kind,
                "cloud": _derive_cloud(row.external_id, row_kind),
                "is_public": row_is_public,
                "region": row_region,
            }
        )

    total = len(items)
    page = items[offset : offset + limit]
    next_offset: int | None = offset + limit if offset + limit < total else None

    return make_envelope(
        data=page,
        offset=next_offset,
        total=total,
        tenant=tenant,
    )


@router.get("/sbom", response_model=Envelope)
async def list_sbom_packages(
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=500),
    tenant: str = Depends(require_tenant),
    store: SemanticStore = Depends(get_store),  # noqa: B008
) -> Envelope:
    """Return SBOM packages for the tenant with their image + vulnerability count."""
    pkgs = await store.list_entities_by_type(
        tenant_id=tenant, entity_type=NodeCategory.SBOM_PACKAGE.value
    )
    items: list[dict[str, Any]] = []
    for pkg in pkgs:
        rels = await store.get_relationships_from(
            tenant_id=tenant, src_entity_id=pkg.entity_id, edge_types=_VULN_TO
        )
        items.append(
            {
                "id": pkg.external_id,
                "name": str(pkg.properties.get("name", "")),
                "image": pkg.external_id.split("#", 1)[0],
                "vulnerabilities": len(rels),
            }
        )
    total = len(items)
    page = items[offset : offset + limit]
    next_offset: int | None = offset + limit if offset + limit < total else None
    return make_envelope(data=page, offset=next_offset, total=total, tenant=tenant)
