"""D.6 v0.2 Task 10 — runtime posture rules tests."""

from __future__ import annotations

from k8s_posture.runtime.enumerate import ContainerState, PodState
from k8s_posture.runtime.posture_rules import evaluate_runtime_posture


def _pod(container: ContainerState, **pod_kw: object) -> PodState:
    return PodState(name="web", namespace="prod", containers=(container,), **pod_kw)  # type: ignore[arg-type]


def _ids(pod: PodState) -> set[str]:
    return {v.rule_id for v in evaluate_runtime_posture([pod])}


def test_privileged_container_critical() -> None:
    pod = _pod(
        ContainerState(
            "app",
            privileged=True,
            run_as_user=1000,
            read_only_root_fs=True,
            allow_privilege_escalation=False,
        )
    )
    violations = evaluate_runtime_posture([pod])
    [v] = [x for x in violations if x.rule_id == "privileged-container"]
    assert v.severity == "critical" and v.container == "app"


def test_host_network_and_pid() -> None:
    pod = _pod(
        ContainerState(
            "app", run_as_user=1000, read_only_root_fs=True, allow_privilege_escalation=False
        ),
        host_network=True,
        host_pid=True,
    )
    ids = _ids(pod)
    assert "host-network" in ids and "host-pid" in ids


def test_run_as_root() -> None:
    pod = _pod(
        ContainerState(
            "app", run_as_user=0, read_only_root_fs=True, allow_privilege_escalation=False
        )
    )
    assert "run-as-root" in _ids(pod)


def test_missing_run_as_user() -> None:
    pod = _pod(
        ContainerState(
            "app", run_as_user=None, read_only_root_fs=True, allow_privilege_escalation=False
        )
    )
    assert "missing-run-as-user" in _ids(pod)


def test_dangerous_capabilities() -> None:
    pod = _pod(
        ContainerState(
            "app",
            run_as_user=1000,
            added_capabilities=("SYS_ADMIN", "NET_RAW"),
            read_only_root_fs=True,
            allow_privilege_escalation=False,
        )
    )
    [v] = [x for x in evaluate_runtime_posture([pod]) if x.rule_id == "dangerous-capabilities"]
    assert (
        "SYS_ADMIN" in v.message and "NET_RAW" not in v.message
    )  # NET_RAW not in the dangerous set


def test_privilege_escalation_and_writable_fs() -> None:
    pod = _pod(
        ContainerState(
            "app", run_as_user=1000, read_only_root_fs=False, allow_privilege_escalation=True
        )
    )
    ids = _ids(pod)
    assert "privilege-escalation" in ids and "writable-root-fs" in ids


def test_clean_pod_no_violations() -> None:
    clean = ContainerState(
        "app", run_as_user=1000, read_only_root_fs=True, allow_privilege_escalation=False
    )
    assert evaluate_runtime_posture([_pod(clean)]) == ()


def test_empty() -> None:
    assert evaluate_runtime_posture([]) == ()
