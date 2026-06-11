"""D.6 v0.2 Task 8 — kubelet API client tests (injected transport; no live cluster)."""

from __future__ import annotations

from typing import Any

from k8s_posture.tools.kubelet_client import KubeletClient


class _Transport:
    def __init__(self, responses: dict[str, Any]) -> None:
        self._responses = responses
        self.paths: list[str] = []

    def get(self, path: str) -> dict[str, Any]:
        self.paths.append(path)
        if path not in self._responses:
            raise ConnectionError(f"no route: {path}")
        return self._responses[path]


def _pod(name: str) -> dict[str, Any]:
    return {"metadata": {"name": name, "namespace": "prod"}, "spec": {"containers": []}}


def test_pods_returns_items() -> None:
    t = _Transport({"/pods": {"items": [_pod("web"), _pod("db")]}})
    pods = KubeletClient(t).pods()
    assert [p["metadata"]["name"] for p in pods] == ["web", "db"]
    assert t.paths == ["/pods"]


def test_pods_drops_non_dicts() -> None:
    t = _Transport({"/pods": {"items": [_pod("web"), "bad", 42]}})
    assert len(KubeletClient(t).pods()) == 1


def test_pods_empty() -> None:
    assert KubeletClient(_Transport({"/pods": {}})).pods() == []


def test_stats_summary() -> None:
    t = _Transport({"/stats/summary": {"node": {"nodeName": "n1"}}})
    assert KubeletClient(t).stats_summary()["node"]["nodeName"] == "n1"


def test_healthz_true() -> None:
    assert KubeletClient(_Transport({"/healthz": {}})).healthz() is True


def test_healthz_false_when_unreachable() -> None:
    assert KubeletClient(_Transport({})).healthz() is False
