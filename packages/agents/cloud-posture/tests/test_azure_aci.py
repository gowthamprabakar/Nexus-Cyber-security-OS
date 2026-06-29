"""Unit tests for the Azure ACI workload reader (gap #13 path-2 cross-cloud) — parsing teeth."""

from cloud_posture.tools.azure_aci import AciWorkload, read_aci_workloads


def _group(name: str, *, image: str | None, public: bool, principal: str = "") -> dict:
    props: dict = {}
    if public:
        props["ipAddress"] = {"type": "Public", "ip": "20.1.2.3"}
    containers = [{"name": name, "properties": {"image": image}}] if image is not None else []
    group: dict = {
        "id": f"/subscriptions/s/resourceGroups/rg/providers/Microsoft.ContainerInstance"
        f"/containerGroups/{name}",
        "containers": containers,
        "properties": props,
    }
    if principal:
        group["identity"] = {"type": "SystemAssigned", "principalId": principal}
    return group


class _Client:
    def __init__(self, groups: list[dict]) -> None:
        self._groups = groups

    def list_container_groups(self) -> list[dict]:
        return self._groups


def test_public_group_with_image_is_exposed() -> None:
    [w] = read_aci_workloads(_Client([_group("web", image="myreg/app:1.0", public=True)]))
    assert isinstance(w, AciWorkload)
    assert w.image_ref == "myreg/app:1.0"
    assert w.is_public is True
    assert w.resource_id.endswith("/containerGroups/web")


def test_private_group_is_not_exposed() -> None:
    [w] = read_aci_workloads(_Client([_group("web", image="myreg/app:1.0", public=False)]))
    assert w.is_public is False


def test_group_with_no_image_is_skipped() -> None:
    # Nothing to join to a CVE node → not a path-2 workload.
    assert read_aci_workloads(_Client([_group("web", image=None, public=True)])) == []


def test_managed_identity_principal_is_resolved() -> None:
    [w] = read_aci_workloads(
        _Client([_group("web", image="myreg/app:1.0", public=True, principal="mi-1")])
    )
    assert w.identity_principal_id == "mi-1"


def test_no_managed_identity_is_blank() -> None:
    [w] = read_aci_workloads(_Client([_group("web", image="myreg/app:1.0", public=True)]))
    assert w.identity_principal_id == ""


def test_malformed_rows_are_skipped() -> None:
    assert read_aci_workloads(_Client(["nonsense", {"id": "x"}])) == []
