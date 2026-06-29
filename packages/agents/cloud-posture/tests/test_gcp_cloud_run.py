"""Unit tests for the GCP Cloud Run workload reader (gap #13 path-2 cross-cloud) — parsing teeth."""

from cloud_posture.tools.gcp_cloud_run import CloudRunWorkload, read_cloud_run_workloads


def _service(name: str, *, image: str | None, public: bool, sa: str = "") -> dict:
    containers = [{"image": image}] if image is not None else []
    template: dict = {"containers": containers}
    if sa:
        template["serviceAccount"] = sa
    return {
        "name": f"projects/p/locations/us-central1/services/{name}",
        "template": template,
        "invokers": ["allUsers"] if public else ["user:dev@acme.com"],
    }


class _Client:
    def __init__(self, services: list[dict]) -> None:
        self._services = services

    def list_services(self) -> list[dict]:
        return self._services


def test_public_service_with_image_is_exposed() -> None:
    [w] = read_cloud_run_workloads(_Client([_service("web", image="myreg/app:1.0", public=True)]))
    assert isinstance(w, CloudRunWorkload)
    assert w.image_ref == "myreg/app:1.0"
    assert w.is_public is True
    assert w.resource_id.endswith("/services/web")


def test_service_without_allusers_invoker_is_not_public() -> None:
    [w] = read_cloud_run_workloads(_Client([_service("web", image="myreg/app:1.0", public=False)]))
    assert w.is_public is False


def test_service_with_no_image_is_skipped() -> None:
    assert read_cloud_run_workloads(_Client([_service("web", image=None, public=True)])) == []


def test_service_account_is_resolved_as_member_key() -> None:
    [w] = read_cloud_run_workloads(
        _Client([_service("web", image="myreg/app:1.0", public=True, sa="web@p.iam")])
    )
    assert w.service_account == "serviceAccount:web@p.iam"


def test_no_service_account_is_blank() -> None:
    [w] = read_cloud_run_workloads(_Client([_service("web", image="myreg/app:1.0", public=True)]))
    assert w.service_account == ""


def test_malformed_rows_are_skipped() -> None:
    assert read_cloud_run_workloads(_Client(["nonsense", {"name": "x"}])) == []
