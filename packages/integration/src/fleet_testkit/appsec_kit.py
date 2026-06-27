"""In-memory appsec harness — cross-domain path A3 (code-to-cloud feeder).

AppSec discovers source repos + IaC misconfigurations; ``RepoInventory`` + ``AppSecFinding`` are the
agent's native types. ``drive_appsec_iac`` builds a repo inventory + IaC-misconfiguration findings
and runs appsec's REAL ``record`` writer, so the ``IAC_ARTIFACT`` node (written only for a
misconfigured file) + its ``DEFINED_IN`` repo land in the graph for the code-to-cloud bridge
resolver. The deployed cloud resource (carrying the matching ``nexus:iac`` tag) comes from moto.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from appsec.kg_writer import KnowledgeGraphWriter as AppSecKgWriter
from appsec.schemas import (
    AppSecFinding,
    AppSecFindingType,
    RepoInventory,
    RepoRef,
    Severity,
)

if TYPE_CHECKING:
    from charter.memory.semantic import SemanticStore


async def drive_appsec_iac(
    store: SemanticStore, *, tenant_id: str, misconfigs: tuple[tuple[str, str, str, str], ...]
) -> list[str]:
    """Run appsec's REAL ``record`` for each ``(host, owner, name, file)`` IaC misconfiguration.

    Returns the ``IAC_ARTIFACT`` external_ids written (``{repo_slug}:{file}``) — the value a cloud
    resource's ``nexus:iac`` provenance tag must carry for the ``DEPLOYED_VIA`` resolver to match.
    """
    repos = [
        RepoRef(host=h, owner=o, name=n, clone_url=f"https://{h}/{o}/{n}.git")
        for h, o, n, _f in {(h, o, n, f) for h, o, n, f in misconfigs}
    ]
    inventory = RepoInventory(
        agent="appsec",
        agent_version="0.1.0",
        customer_id=tenant_id,
        run_id="run-1",
        discovered_at=datetime(2026, 1, 1, tzinfo=UTC),
        repositories=tuple(repos),
    )
    findings = []
    artifact_ids: list[str] = []
    for i, (host, owner, name, file) in enumerate(misconfigs):
        slug = f"{host}/{owner}/{name}"
        findings.append(
            AppSecFinding(
                finding_id=f"APPSEC-IAC-{i:03d}",
                finding_type=AppSecFindingType.IAC_MISCONFIGURATION,
                rule_id="CKV_AWS_20",
                severity=Severity.HIGH,
                title="public-read ACL in IaC",
                description="the IaC declares a public-read resource",
                repo_slug=slug,
                location=f"{file}:1",
            )
        )
        artifact_ids.append(f"{slug}:{file}")
    await AppSecKgWriter(store, tenant_id).record(inventory, findings)
    return artifact_ids


__all__ = ["drive_appsec_iac"]
