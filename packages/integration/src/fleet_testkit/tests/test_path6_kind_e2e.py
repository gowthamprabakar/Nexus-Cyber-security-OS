"""Path 6 (privileged K8s workload + vulnerable image) committed e2e — REAL via kind + trivy.

Proves the chain through the agents' own code against a LIVE kind cluster:

- a privileged pod (running ``myreg/app:1.0``) is applied to a throwaway kind namespace.
- k8s-posture's real ``read_privileged_workloads`` reads it via ``kubectl`` and the real
  ``record_privileged_workloads`` writes the privileged ``K8S_OBJECT`` + ``RUNS_IMAGE`` → image.
- vulnerability's real ``record_scan_results`` (real ``trivy fs``) writes CVEs on the SAME image.
- ``KgQuery.find_privileged_vulnerable_workload`` lights up the pod→image→CVE chain.

Gated: needs ``trivy`` AND a kind context (throwaway clusters only — we never apply to a
non-kind context). Not hermetic; REAL where the tools are present.
"""

import subprocess

import pytest
from k8s_posture.kg_writer import KnowledgeGraphWriter as K8sKgWriter
from k8s_posture.tools.privileged_pods import kubectl_available, read_privileged_workloads
from meta_harness.kg_query import KgQuery

from fleet_testkit import in_memory_semantic_store
from fleet_testkit.vuln_scan import drive_vulnerability, trivy_available

_TENANT = "tenant-path6"
_NS = "path6-e2e"
_IMAGE = "myreg/app:1.0"
_POD_MANIFEST = f"""
apiVersion: v1
kind: Pod
metadata:
  name: priv-web
  namespace: {_NS}
spec:
  containers:
  - name: app
    image: {_IMAGE}
    securityContext:
      privileged: true
"""


def _kind_context() -> str | None:
    """Current kube context iff it is a kind cluster (throwaway). Else None → skip."""
    if not kubectl_available():
        return None
    try:
        ctx = subprocess.run(
            ["kubectl", "config", "current-context"],  # noqa: S607
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        ).stdout.strip()
    except (subprocess.SubprocessError, OSError):
        return None
    return ctx if ctx.startswith("kind-") else None


_CTX = _kind_context()
pytestmark = pytest.mark.skipif(
    _CTX is None or not trivy_available, reason="needs trivy + a kind context"
)


def _kubectl(*args: str, stdin: str | None = None) -> None:
    subprocess.run(  # noqa: S603
        ["kubectl", "--context", _CTX or "", *args],  # noqa: S607
        input=stdin,
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
    )


@pytest.fixture
def _privileged_pod():
    _kubectl("create", "namespace", _NS)
    try:
        _kubectl("apply", "-f", "-", stdin=_POD_MANIFEST)
        yield
    finally:
        _kubectl("delete", "namespace", _NS, "--wait=false")


@pytest.mark.asyncio
async def test_privileged_pod_running_vulnerable_image_lights_up(tmp_path, _privileged_pod) -> None:
    (tmp_path / "requirements.txt").write_text("Django==2.0.0\n")
    async with in_memory_semantic_store() as store:
        # Real k8s-posture read of the live cluster, scoped to our privileged pod.
        workloads = [w for w in read_privileged_workloads(context=_CTX) if w.namespace == _NS]
        assert len(workloads) == 1, "real kubectl read found the privileged pod"
        assert workloads[0].image_ref == _IMAGE
        await K8sKgWriter(store, _TENANT).record_privileged_workloads(_CTX, workloads)

        # Real trivy CVEs on the same image node.
        await drive_vulnerability(store, tenant_id=_TENANT, fixture_dir=tmp_path, image_ref=_IMAGE)

        hits = await KgQuery(store, _TENANT).find_privileged_vulnerable_workload()
        assert hits, "privileged pod running a vulnerable image surfaces a path-6 hit"
        assert hits[0].cve_id.startswith("CVE-")
