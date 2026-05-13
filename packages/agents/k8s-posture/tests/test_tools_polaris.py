"""Tests for `k8s_posture.tools.polaris`."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from k8s_posture.tools.polaris import PolarisReaderError, read_polaris


def _check(
    *,
    check_id: str = "runAsRootAllowed",
    message: str = "Should not be allowed to run as root",
    success: bool = False,
    severity: str = "danger",
    category: str = "Security",
) -> dict[str, Any]:
    return {
        "ID": check_id,
        "Message": message,
        "Success": success,
        "Severity": severity,
        "Category": category,
    }


def _workload(
    *,
    name: str = "frontend",
    namespace: str = "production",
    kind: str = "Deployment",
    workload_results: dict[str, Any] | None = None,
    pod_results: dict[str, Any] | None = None,
    container_results: list[dict[str, Any]] | None = None,
    pod_name: str | None = None,
) -> dict[str, Any]:
    pod_block: dict[str, Any] = {
        "Name": pod_name or f"{name}-pod",
        "Results": pod_results or {},
        "ContainerResults": container_results or [],
    }
    return {
        "Name": name,
        "Namespace": namespace,
        "Kind": kind,
        "Results": workload_results or {},
        "PodResult": pod_block,
    }


def _container(name: str = "nginx", results: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "Name": name,
        "Results": results or {},
    }


def _write_canonical(tmp_path: Path, workloads: list[dict[str, Any]]) -> Path:
    p = tmp_path / "polaris.json"
    p.write_text(
        json.dumps(
            {
                "PolarisOutputVersion": "1.0",
                "AuditTime": "2026-05-13T12:00:00Z",
                "SourceType": "cluster",
                "Results": workloads,
            }
        )
    )
    return p


def _write_bare(tmp_path: Path, workloads: list[dict[str, Any]]) -> Path:
    p = tmp_path / "polaris.json"
    p.write_text(json.dumps(workloads))
    return p


# ---------------------------- happy paths --------------------------------


@pytest.mark.asyncio
async def test_container_level_failing_check_emits_finding(tmp_path: Path) -> None:
    workload = _workload(container_results=[_container(results={"runAsRootAllowed": _check()})])
    path = _write_canonical(tmp_path, [workload])

    out = await read_polaris(path=path)

    assert len(out) == 1
    f = out[0]
    assert f.check_id == "runAsRootAllowed"
    assert f.message == "Should not be allowed to run as root"
    assert f.severity == "danger"
    assert f.category == "Security"
    assert f.workload_kind == "Deployment"
    assert f.workload_name == "frontend"
    assert f.namespace == "production"
    assert f.container_name == "nginx"
    assert f.check_level == "container"


@pytest.mark.asyncio
async def test_pod_level_failing_check_emits_finding(tmp_path: Path) -> None:
    workload = _workload(pod_results={"someCheck": _check(check_id="someCheck")})
    path = _write_canonical(tmp_path, [workload])

    out = await read_polaris(path=path)

    assert len(out) == 1
    assert out[0].check_level == "pod"
    assert out[0].container_name == ""


@pytest.mark.asyncio
async def test_workload_level_failing_check_emits_finding(tmp_path: Path) -> None:
    workload = _workload(workload_results={"someCheck": _check(check_id="someCheck")})
    path = _write_canonical(tmp_path, [workload])

    out = await read_polaris(path=path)

    assert len(out) == 1
    assert out[0].check_level == "workload"


@pytest.mark.asyncio
async def test_three_levels_emit_three_findings(tmp_path: Path) -> None:
    workload = _workload(
        workload_results={"workloadCheck": _check(check_id="workloadCheck")},
        pod_results={"podCheck": _check(check_id="podCheck")},
        container_results=[
            _container(results={"containerCheck": _check(check_id="containerCheck")})
        ],
    )
    path = _write_canonical(tmp_path, [workload])

    out = await read_polaris(path=path)
    assert len(out) == 3
    levels = {f.check_level for f in out}
    assert levels == {"workload", "pod", "container"}


# ---------------------------- top-level shape ----------------------------


@pytest.mark.asyncio
async def test_bare_array_shape(tmp_path: Path) -> None:
    workload = _workload(container_results=[_container(results={"x": _check()})])
    path = _write_bare(tmp_path, [workload])

    out = await read_polaris(path=path)
    assert len(out) == 1


# ---------------------------- success vs failure -------------------------


@pytest.mark.asyncio
async def test_passing_check_dropped(tmp_path: Path) -> None:
    workload = _workload(container_results=[_container(results={"x": _check(success=True)})])
    path = _write_canonical(tmp_path, [workload])
    out = await read_polaris(path=path)
    assert out == ()


@pytest.mark.asyncio
async def test_mixed_success_failure(tmp_path: Path) -> None:
    workload = _workload(
        container_results=[
            _container(
                results={
                    "failingCheck": _check(check_id="failingCheck", success=False),
                    "passingCheck": _check(check_id="passingCheck", success=True),
                }
            )
        ]
    )
    path = _write_canonical(tmp_path, [workload])
    out = await read_polaris(path=path)
    assert len(out) == 1
    assert out[0].check_id == "failingCheck"


# ---------------------------- severity filtering -------------------------


@pytest.mark.parametrize("sev", ["danger", "warning", "DANGER", "Danger"])
@pytest.mark.asyncio
async def test_danger_and_warning_severities_accepted(tmp_path: Path, sev: str) -> None:
    workload = _workload(container_results=[_container(results={"x": _check(severity=sev)})])
    path = _write_canonical(tmp_path, [workload])
    out = await read_polaris(path=path)
    assert len(out) == 1
    assert out[0].severity in {"danger", "warning"}


@pytest.mark.parametrize("sev", ["ignore", "info", ""])
@pytest.mark.asyncio
async def test_other_severities_dropped(tmp_path: Path, sev: str) -> None:
    workload = _workload(container_results=[_container(results={"x": _check(severity=sev)})])
    path = _write_canonical(tmp_path, [workload])
    out = await read_polaris(path=path)
    assert out == ()


# ---------------------------- forgiving on bad data ----------------------


@pytest.mark.asyncio
async def test_missing_workload_name_dropped(tmp_path: Path) -> None:
    bad = _workload(name="", container_results=[_container(results={"x": _check()})])
    good = _workload(name="good", container_results=[_container(results={"x": _check()})])
    path = _write_canonical(tmp_path, [bad, good])

    out = await read_polaris(path=path)
    assert len(out) == 1
    assert out[0].workload_name == "good"


@pytest.mark.asyncio
async def test_non_dict_check_dropped(tmp_path: Path) -> None:
    workload = {
        "Name": "frontend",
        "Namespace": "default",
        "Kind": "Deployment",
        "PodResult": {
            "Name": "frontend-pod",
            "ContainerResults": [{"Name": "nginx", "Results": {"x": "not a dict"}}],
        },
    }
    path = _write_canonical(tmp_path, [workload])
    out = await read_polaris(path=path)
    assert out == ()


@pytest.mark.asyncio
async def test_missing_message_dropped(tmp_path: Path) -> None:
    bad_check = _check()
    bad_check["Message"] = ""
    workload = _workload(container_results=[_container(results={"x": bad_check})])
    path = _write_canonical(tmp_path, [workload])
    out = await read_polaris(path=path)
    assert out == ()


@pytest.mark.asyncio
async def test_check_id_falls_back_to_dict_key(tmp_path: Path) -> None:
    """If the check dict has no ID field, use the dict key as fallback."""
    check_without_id = {
        "Message": "x",
        "Success": False,
        "Severity": "danger",
    }
    workload = _workload(container_results=[_container(results={"keyId": check_without_id})])
    path = _write_canonical(tmp_path, [workload])
    out = await read_polaris(path=path)
    assert len(out) == 1
    assert out[0].check_id == "keyId"


@pytest.mark.asyncio
async def test_default_namespace_applied(tmp_path: Path) -> None:
    workload = _workload(namespace="", container_results=[_container(results={"x": _check()})])
    path = _write_canonical(tmp_path, [workload])
    out = await read_polaris(path=path)
    assert len(out) == 1
    assert out[0].namespace == "default"


# ---------------------------- file errors --------------------------------


@pytest.mark.asyncio
async def test_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(PolarisReaderError, match="not found"):
        await read_polaris(path=tmp_path / "missing.json")


@pytest.mark.asyncio
async def test_directory_path_raises(tmp_path: Path) -> None:
    with pytest.raises(PolarisReaderError, match="not a file"):
        await read_polaris(path=tmp_path)


@pytest.mark.asyncio
async def test_malformed_json_raises(tmp_path: Path) -> None:
    p = tmp_path / "bad.json"
    p.write_text("{not json")
    with pytest.raises(PolarisReaderError, match="malformed"):
        await read_polaris(path=p)


@pytest.mark.asyncio
async def test_empty_results_returns_empty(tmp_path: Path) -> None:
    path = _write_canonical(tmp_path, [])
    out = await read_polaris(path=path)
    assert out == ()
