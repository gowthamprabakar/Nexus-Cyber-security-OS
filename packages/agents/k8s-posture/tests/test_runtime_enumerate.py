"""D.6 v0.2 Task 9 — runtime state enumeration tests."""

from __future__ import annotations

from typing import Any

from k8s_posture.runtime.enumerate import ContainerState, PodState, enumerate_pods


def _pod(**overrides: Any) -> dict[str, Any]:
    spec: dict[str, Any] = {
        "containers": [
            {
                "name": "app",
                "image": "evil/img:latest",
                "securityContext": {
                    "privileged": True,
                    "runAsUser": 0,
                    "capabilities": {"add": ["SYS_ADMIN", "NET_RAW"]},
                    "readOnlyRootFilesystem": False,
                    "allowPrivilegeEscalation": True,
                },
            }
        ],
        "hostNetwork": True,
        "hostPID": False,
        "serviceAccountName": "default",
    }
    spec.update(overrides)
    return {"metadata": {"name": "web", "namespace": "prod"}, "spec": spec}


def test_enumerate_pod_and_container() -> None:
    [pod] = enumerate_pods([_pod()])
    assert isinstance(pod, PodState)
    assert pod.name == "web" and pod.namespace == "prod"
    assert pod.host_network is True and pod.host_pid is False
    assert pod.service_account == "default"
    [c] = pod.containers
    assert isinstance(c, ContainerState)
    assert c.privileged is True and c.run_as_user == 0
    assert c.added_capabilities == ("SYS_ADMIN", "NET_RAW")
    assert c.read_only_root_fs is False


def test_pod_without_name_skipped() -> None:
    assert enumerate_pods([{"spec": {"containers": []}}]) == ()


def test_defaults_for_missing_security_context() -> None:
    pod = {"metadata": {"name": "p"}, "spec": {"containers": [{"name": "c"}]}}
    [ps] = enumerate_pods([pod])
    assert ps.namespace == "default"
    [c] = ps.containers
    assert c.privileged is False and c.run_as_user is None and c.added_capabilities == ()
    assert c.allow_privilege_escalation is True  # default-True when unset


def test_allow_privilege_escalation_false() -> None:
    pod = _pod()
    pod["spec"]["containers"][0]["securityContext"]["allowPrivilegeEscalation"] = False
    [ps] = enumerate_pods([pod])
    assert ps.containers[0].allow_privilege_escalation is False


def test_run_as_non_root_user() -> None:
    pod = _pod()
    pod["spec"]["containers"][0]["securityContext"]["runAsUser"] = 1000
    [ps] = enumerate_pods([pod])
    assert ps.containers[0].run_as_user == 1000


def test_empty_pods() -> None:
    assert enumerate_pods([]) == ()


def test_multiple_pods() -> None:
    p2 = _pod()
    p2["metadata"]["name"] = "db"
    assert {p.name for p in enumerate_pods([_pod(), p2])} == {"web", "db"}
