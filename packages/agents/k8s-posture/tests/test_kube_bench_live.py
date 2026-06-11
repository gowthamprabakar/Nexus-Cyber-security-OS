"""D.6 v0.2 Task 2 — live kube-bench scan execution tests (injected runner)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from k8s_posture.tools.kube_bench_live import (
    KubeBenchLiveScanner,
    parse_kube_bench_blob,
)

_T = datetime(2026, 6, 11, 12, 0, 0, tzinfo=UTC)


def _blob(status: str = "FAIL") -> dict[str, Any]:
    return {
        "Controls": [
            {
                "node_type": "master",
                "tests": [
                    {
                        "section": "1.2",
                        "desc": "API Server",
                        "results": [
                            {
                                "test_number": "1.2.1",
                                "test_desc": "Ensure anonymous-auth is not enabled",
                                "status": status,
                                "severity": "HIGH",
                                "remediation": "set --anonymous-auth=false",
                                "scored": True,
                            }
                        ],
                    }
                ],
            }
        ]
    }


class _Runner:
    def __init__(self, blob: dict[str, Any]) -> None:
        self._blob = blob
        self.calls: list[tuple[str, str | None]] = []

    def run(self, *, kubeconfig: str, context: str | None = None) -> dict[str, Any]:
        self.calls.append((kubeconfig, context))
        return self._blob


def test_parse_blob_fail() -> None:
    findings = parse_kube_bench_blob(_blob("FAIL"), detected_at=_T)
    assert len(findings) == 1
    assert findings[0].control_id == "1.2.1" and findings[0].status == "FAIL"
    assert findings[0].detected_at == _T  # deterministic


def test_parse_blob_pass_skipped() -> None:
    # PASS results are not findings (only FAIL/WARN).
    assert parse_kube_bench_blob(_blob("PASS"), detected_at=_T) == ()


def test_scan_runs_and_parses() -> None:
    runner = _Runner(_blob("WARN"))
    findings = KubeBenchLiveScanner(runner).scan(
        kubeconfig="~/.kube/config", context="prod-eks", detected_at=_T
    )
    assert len(findings) == 1 and findings[0].status == "WARN"


def test_scan_passes_kubeconfig_and_context() -> None:
    runner = _Runner(_blob())
    KubeBenchLiveScanner(runner).scan(kubeconfig="cfg", context="ctx", detected_at=_T)
    assert runner.calls[0] == ("cfg", "ctx")


def test_empty_blob() -> None:
    assert parse_kube_bench_blob({}, detected_at=_T) == ()


def test_byte_identical_with_offline(tmp_path: Any) -> None:
    # The live blob-parse matches the offline reader's parse of the same JSON.
    import json

    from k8s_posture.tools.kube_bench import _read_sync

    p = tmp_path / "kb.json"
    p.write_text(json.dumps(_blob("FAIL")), encoding="utf-8")
    offline = _read_sync(p)
    live = parse_kube_bench_blob(_blob("FAIL"), detected_at=offline[0].detected_at)
    assert [f.control_id for f in live] == [f.control_id for f in offline]
    assert live[0].model_dump() == offline[0].model_dump()
