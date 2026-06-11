"""D.6 v0.2 Task 5 — live Polaris policy check execution tests (injected runner)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from k8s_posture.tools.polaris_live import PolarisLiveScanner, parse_polaris_blob

_T = datetime(2026, 6, 11, 12, 0, 0, tzinfo=UTC)


def _blob() -> dict[str, Any]:
    return {
        "Results": [
            {
                "Name": "web",
                "Namespace": "prod",
                "Kind": "Deployment",
                "PodResult": {
                    "ContainerResults": [
                        {
                            "Name": "app",
                            "Results": {
                                "runAsRootAllowed": {
                                    "ID": "runAsRootAllowed",
                                    "Success": False,
                                    "Severity": "danger",
                                    "Message": "Should not be allowed to run as root",
                                    "Category": "Security",
                                }
                            },
                        }
                    ]
                },
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


def test_parse_blob() -> None:
    findings = parse_polaris_blob(_blob(), detected_at=_T)
    assert len(findings) == 1 and findings[0].detected_at == _T


def test_scan_runs_and_parses() -> None:
    findings = PolarisLiveScanner(_Runner(_blob())).scan(
        kubeconfig="~/.kube/config", context="prod-aks", detected_at=_T
    )
    assert len(findings) == 1


def test_scan_passes_kubeconfig_and_context() -> None:
    runner = _Runner(_blob())
    PolarisLiveScanner(runner).scan(kubeconfig="cfg", context="ctx", detected_at=_T)
    assert runner.calls[0] == ("cfg", "ctx")


def test_empty_blob() -> None:
    assert parse_polaris_blob({}, detected_at=_T) == ()


def test_passing_checks_skipped() -> None:
    blob = _blob()
    blob["Results"][0]["PodResult"]["ContainerResults"][0]["Results"]["runAsRootAllowed"][
        "Success"
    ] = True
    assert parse_polaris_blob(blob, detected_at=_T) == ()  # only failing checks → findings


def test_byte_identical_with_offline(tmp_path: Any) -> None:
    import json

    from k8s_posture.tools.polaris import _read_sync

    p = tmp_path / "polaris.json"
    p.write_text(json.dumps(_blob()), encoding="utf-8")
    offline = _read_sync(p)
    live = parse_polaris_blob(_blob(), detected_at=offline[0].detected_at)
    assert live[0].model_dump() == offline[0].model_dump()
