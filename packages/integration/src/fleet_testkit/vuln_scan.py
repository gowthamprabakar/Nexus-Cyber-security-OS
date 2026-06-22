"""REAL vulnerability-scan harness for fleet path tests (path 2 — KEV vuln leg).

``drive_vulnerability`` runs the **real** Trivy binary (``trivy fs``) against a fixture
directory holding genuinely-vulnerable package manifests, then drives vulnerability's
**own** ``KnowledgeGraphWriter.record_scan_results`` to write the CVE overlay
(``CLOUD_RESOURCE`` artifact + ``CVE_FINDING`` + ``VULNERABLE_TO`` edges) into the store.

Unlike the moto harnesses, this is **not** hermetic: it needs the ``trivy`` binary (and
its vuln DB). Tests gate on :data:`trivy_available`. Where Trivy is present the chain is
REAL — a real scanner detecting real CVEs in a real vulnerable package, through the
agent's real writer. No hand-faked findings.

Production parity: the live agent scans ``trivy image <ref>`` (registry pull), so the
artifact name *is* the image ref. CI has no registry/Docker, so we scan the image's
package manifests with ``trivy fs`` and relabel the artifact to ``image_ref`` — the CVE
detection is the identical real Trivy; only the *fetch* differs. The relabel is what makes
the CVE node share the bridge key with the workload's ``RUNS_IMAGE`` target (path 2).
"""

from __future__ import annotations

import shutil
from pathlib import Path
from tempfile import TemporaryDirectory

from vulnerability.kg_writer import KnowledgeGraphWriter
from vulnerability.tools.trivy import trivy_fs_scan

trivy_available = shutil.which("trivy") is not None


async def drive_vulnerability(
    store: object,
    *,
    tenant_id: str,
    fixture_dir: str | Path,
    image_ref: str,
) -> str:
    """Real ``trivy fs`` scan of ``fixture_dir``, recorded under ``image_ref``.

    Returns ``image_ref`` — the canonical bridge key the CVE artifact node is written
    under (so a workload's ``RUNS_IMAGE`` edge to the same ref joins them). Raises if
    Trivy is unavailable; callers gate on :data:`trivy_available`.
    """
    with TemporaryDirectory() as out:
        result = await trivy_fs_scan(str(fixture_dir), output_dir=Path(out))
    # Production parity: `trivy image <ref>` names the artifact after the image ref;
    # `trivy fs` names it after the path. Relabel so the CVE node keys on the image ref.
    for raw in result.raw_findings:
        raw["_artifact_name"] = image_ref
    await KnowledgeGraphWriter(store, tenant_id).record_scan_results([result])
    return image_ref


__all__ = ["drive_vulnerability", "trivy_available"]
