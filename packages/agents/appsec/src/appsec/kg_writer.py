"""AppSec knowledge-graph writer (v0.4 Stage 1.6).

Writes the **code-side inventory** the catalogue (#711) assigns D.14/D.9 AppSec into
the fleet graph: the source **repositories** discovered + the **IaC artifacts**
(files) that carry misconfigurations, linked ``DEFINED_IN`` (artifact → repository).

This is the **code end of the code-to-cloud bridge.** The cross-agent edges the
catalogue names — ``BUILT_FROM`` (container image → repo, needs D.1's image side) and
``DEPLOYED_VIA`` (cloud resource → IaC artifact, needs D.3/D.5's resource side) —
cannot be authored from AppSec's data alone (AppSec discovers repos + findings, not
images or deployed resources). Those edges are written at **Stage 3 correlation**,
once both ends exist in the graph. This writer lays the repository + IaC-artifact
nodes that correlation will bridge to the cloud side.

Subclasses :class:`KnowledgeGraphWriterBase` (ADR-019): tenant scoping, typed
vocabulary (ADR-018), within-run dedup, opt-in/inert when no store. Offline default
(no ``SemanticStore``) writes nothing → artifacts byte-identical.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from charter.memory.graph_types import EdgeType, NodeCategory
from charter.memory.kg_writer_base import KnowledgeGraphWriterBase

from appsec.schemas import AppSecFinding, AppSecFindingType, RepoInventory

if TYPE_CHECKING:
    from collections.abc import Iterable


class KnowledgeGraphWriter(KnowledgeGraphWriterBase):
    """Persists code repositories + IaC artifacts (the code end of code-to-cloud)."""

    async def record(self, inventory: RepoInventory, findings: Iterable[AppSecFinding]) -> None:
        """Upsert repository nodes + IaC-artifact nodes (DEFINED_IN their repo)."""
        repo_ids: dict[str, str | None] = {}
        for repo in inventory.repositories:
            repo_ids[repo.slug] = await self.upsert_node(
                NodeCategory.CODE_REPOSITORY,
                repo.slug,
                {
                    "host": repo.host,
                    "owner": repo.owner,
                    "name": repo.name,
                    "visibility": repo.visibility,
                    "default_branch": repo.default_branch,
                },
            )

        for finding in findings:
            # IaC misconfigurations name a file (the IaC artifact); SAST/secret
            # findings decorate the repo but do not introduce an artifact node here.
            if finding.finding_type is not AppSecFindingType.IAC_MISCONFIGURATION:
                continue
            file_path = finding.location.split(":", 1)[0] if finding.location else ""
            if not file_path:
                continue
            artifact_id = await self.upsert_node(
                NodeCategory.IAC_ARTIFACT,
                f"{finding.repo_slug}:{file_path}",
                {"repo_slug": finding.repo_slug, "file": file_path},
            )
            repo_id = repo_ids.get(finding.repo_slug)
            if repo_id is None:
                # The finding's repo wasn't in the inventory list — upsert it so the
                # DEFINED_IN edge has both ends (idempotent).
                repo_id = await self.upsert_node(
                    NodeCategory.CODE_REPOSITORY, finding.repo_slug, {}
                )
                repo_ids[finding.repo_slug] = repo_id
            await self.add_edge(artifact_id or "", repo_id or "", EdgeType.DEFINED_IN)


__all__ = ["KnowledgeGraphWriter"]
