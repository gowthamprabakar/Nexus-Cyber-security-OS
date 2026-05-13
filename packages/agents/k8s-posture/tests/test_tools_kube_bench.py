"""Tests for `k8s_posture.tools.kube_bench`."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from k8s_posture.tools.kube_bench import KubeBenchReaderError, read_kube_bench


def _result(
    *,
    test_number: str = "1.1.1",
    test_desc: str = "Ensure that the API server pod spec file permissions are set to 644 or more restrictive",
    status: str = "FAIL",
    audit: str = "stat -c %a /etc/kubernetes/manifests/kube-apiserver.yaml",
    actual_value: str = "777",
    remediation: str = "Run the below command...",
    scored: bool = True,
    severity: str | None = None,
) -> dict[str, Any]:
    out: dict[str, Any] = {
        "test_number": test_number,
        "test_desc": test_desc,
        "audit": audit,
        "audit_env": "",
        "AuditConfig": "",
        "AuditConfigEnv": "",
        "type": "",
        "remediation": remediation,
        "test_info": ["info text"],
        "status": status,
        "actual_value": actual_value,
        "scored": scored,
        "IsMultiple": False,
        "expected_result": "permissions are 644 or more restrictive",
    }
    if severity is not None:
        out["severity"] = severity
    return out


def _control(
    *,
    node_type: str = "master",
    section: str = "1.1",
    section_desc: str = "Master Node Configuration Files",
    results: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "id": "1",
        "version": "1.7",
        "detected_version": "1.27",
        "text": "Master Node Security Configuration",
        "node_type": node_type,
        "tests": [
            {
                "section": section,
                "desc": section_desc,
                "results": results or [_result()],
            }
        ],
    }


def _write_canonical(tmp_path: Path, controls: list[dict[str, Any]]) -> Path:
    p = tmp_path / "kube-bench.json"
    p.write_text(
        json.dumps(
            {
                "Controls": controls,
                "Totals": {"total_pass": 0, "total_fail": 1, "total_warn": 0, "total_info": 0},
            }
        )
    )
    return p


def _write_bare(tmp_path: Path, controls: list[dict[str, Any]]) -> Path:
    p = tmp_path / "kube-bench.json"
    p.write_text(json.dumps(controls))
    return p


# ---------------------------- happy path ---------------------------------


@pytest.mark.asyncio
async def test_read_canonical_shape(tmp_path: Path) -> None:
    path = _write_canonical(tmp_path, [_control()])

    out = await read_kube_bench(path=path)

    assert len(out) == 1
    f = out[0]
    assert f.control_id == "1.1.1"
    assert "API server" in f.control_text
    assert f.section_id == "1.1"
    assert f.section_desc == "Master Node Configuration Files"
    assert f.node_type == "master"
    assert f.status == "FAIL"
    assert f.audit == "stat -c %a /etc/kubernetes/manifests/kube-apiserver.yaml"
    assert f.actual_value == "777"
    assert f.scored is True
    assert f.severity_marker == ""  # no upstream override
    assert f.unmapped["test_info"] == ["info text"]
    assert f.unmapped["expected_result"].startswith("permissions are 644")


@pytest.mark.asyncio
async def test_read_bare_array_shape(tmp_path: Path) -> None:
    path = _write_bare(tmp_path, [_control()])
    out = await read_kube_bench(path=path)
    assert len(out) == 1


@pytest.mark.asyncio
async def test_multiple_controls_multiple_tests(tmp_path: Path) -> None:
    """Multiple Controls[] each with multiple tests[].results[] all flatten."""
    control_a = _control(
        node_type="master",
        section="1.1",
        results=[_result(test_number="1.1.1"), _result(test_number="1.1.2")],
    )
    control_b = _control(
        node_type="worker",
        section="4.1",
        section_desc="Worker Node Configuration Files",
        results=[_result(test_number="4.1.1")],
    )
    path = _write_canonical(tmp_path, [control_a, control_b])

    out = await read_kube_bench(path=path)
    assert len(out) == 3
    control_ids = sorted(f.control_id for f in out)
    assert control_ids == ["1.1.1", "1.1.2", "4.1.1"]
    node_types = {f.node_type for f in out}
    assert node_types == {"master", "worker"}


# ---------------------------- status filtering ---------------------------


@pytest.mark.parametrize("status", ["FAIL", "WARN"])
@pytest.mark.asyncio
async def test_fail_and_warn_become_findings(tmp_path: Path, status: str) -> None:
    path = _write_canonical(tmp_path, [_control(results=[_result(status=status)])])
    out = await read_kube_bench(path=path)
    assert len(out) == 1
    assert out[0].status == status


@pytest.mark.parametrize("status", ["PASS", "INFO", "pass", "info"])
@pytest.mark.asyncio
async def test_pass_and_info_dropped(tmp_path: Path, status: str) -> None:
    path = _write_canonical(tmp_path, [_control(results=[_result(status=status)])])
    out = await read_kube_bench(path=path)
    assert out == ()


@pytest.mark.asyncio
async def test_lowercase_status_normalised(tmp_path: Path) -> None:
    path = _write_canonical(tmp_path, [_control(results=[_result(status="fail")])])
    out = await read_kube_bench(path=path)
    assert len(out) == 1
    assert out[0].status == "FAIL"


@pytest.mark.asyncio
async def test_unknown_status_dropped(tmp_path: Path) -> None:
    path = _write_canonical(
        tmp_path,
        [_control(results=[_result(status="ERROR"), _result(test_number="1.1.2")])],
    )
    out = await read_kube_bench(path=path)
    assert len(out) == 1
    assert out[0].control_id == "1.1.2"


# ---------------------------- severity marker ----------------------------


@pytest.mark.asyncio
async def test_severity_marker_preserved(tmp_path: Path) -> None:
    """Upstream `severity: critical` flag on a control rides through to the finding."""
    path = _write_canonical(tmp_path, [_control(results=[_result(severity="critical")])])
    out = await read_kube_bench(path=path)
    assert len(out) == 1
    assert out[0].severity_marker == "critical"


# ---------------------------- forgiving on bad data ----------------------


@pytest.mark.asyncio
async def test_missing_test_number_dropped(tmp_path: Path) -> None:
    bad = _result()
    bad["test_number"] = ""
    good = _result(test_number="1.1.2")
    path = _write_canonical(tmp_path, [_control(results=[bad, good])])
    out = await read_kube_bench(path=path)
    assert len(out) == 1
    assert out[0].control_id == "1.1.2"


@pytest.mark.asyncio
async def test_missing_test_desc_dropped(tmp_path: Path) -> None:
    bad = _result()
    bad["test_desc"] = ""
    good = _result(test_number="1.1.2", test_desc="Good test")
    path = _write_canonical(tmp_path, [_control(results=[bad, good])])
    out = await read_kube_bench(path=path)
    assert len(out) == 1


@pytest.mark.asyncio
async def test_non_string_status_dropped(tmp_path: Path) -> None:
    bad = _result()
    bad["status"] = 123
    good = _result(test_number="1.1.2")
    path = _write_canonical(tmp_path, [_control(results=[bad, good])])
    out = await read_kube_bench(path=path)
    assert len(out) == 1


@pytest.mark.asyncio
async def test_control_without_tests_dropped(tmp_path: Path) -> None:
    no_tests = {"id": "x", "node_type": "master"}  # no `tests` key
    good_control = _control()
    path = _write_canonical(tmp_path, [no_tests, good_control])
    out = await read_kube_bench(path=path)
    assert len(out) == 1


@pytest.mark.asyncio
async def test_test_without_results_dropped(tmp_path: Path) -> None:
    no_results_control = {
        "id": "x",
        "node_type": "master",
        "tests": [{"section": "1.1", "desc": "x"}],  # no `results` key
    }
    good = _control()
    path = _write_canonical(tmp_path, [no_results_control, good])
    out = await read_kube_bench(path=path)
    assert len(out) == 1


# ---------------------------- file errors --------------------------------


@pytest.mark.asyncio
async def test_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(KubeBenchReaderError, match="not found"):
        await read_kube_bench(path=tmp_path / "missing.json")


@pytest.mark.asyncio
async def test_directory_path_raises(tmp_path: Path) -> None:
    with pytest.raises(KubeBenchReaderError, match="not a file"):
        await read_kube_bench(path=tmp_path)


@pytest.mark.asyncio
async def test_malformed_json_raises(tmp_path: Path) -> None:
    p = tmp_path / "bad.json"
    p.write_text("{not json")
    with pytest.raises(KubeBenchReaderError, match="malformed"):
        await read_kube_bench(path=p)


@pytest.mark.asyncio
async def test_empty_controls_returns_empty(tmp_path: Path) -> None:
    path = _write_canonical(tmp_path, [])
    out = await read_kube_bench(path=path)
    assert out == ()


@pytest.mark.asyncio
async def test_top_level_scalar_returns_empty(tmp_path: Path) -> None:
    p = tmp_path / "scalar.json"
    p.write_text("123")
    out = await read_kube_bench(path=p)
    assert out == ()
