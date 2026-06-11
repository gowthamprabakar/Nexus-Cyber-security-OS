"""kubelet API client (D.6 v0.2 Task 8).

Queries the kubelet read-only/secure API (via the cluster kubeconfig + the API-server node
proxy in production) for **runtime** cluster state — the `/pods` and `/stats/summary`
endpoints. Runs over an **injectable transport** seam so it's unit-testable without a live
cluster. Per **Q3** a client targets a **single cluster**.
"""

from __future__ import annotations

from typing import Any, Protocol


class KubeletTransport(Protocol):
    """The HTTP seam a `KubeletClient` reads through (kubeconfig-authenticated in prod)."""

    def get(self, path: str) -> dict[str, Any]: ...


class KubeletClient:
    """A minimal read-only kubelet API client."""

    __slots__ = ("_t",)

    def __init__(self, transport: KubeletTransport) -> None:
        self._t = transport

    def pods(self) -> list[dict[str, Any]]:
        """The running pods (`/pods` → items). Malformed entries dropped."""
        resp = self._t.get("/pods")
        items = resp.get("items", [])
        return [p for p in items if isinstance(p, dict)]

    def stats_summary(self) -> dict[str, Any]:
        """Node + pod resource stats (`/stats/summary`)."""
        return self._t.get("/stats/summary")

    def healthz(self) -> bool:
        """`True` iff the kubelet `/healthz` endpoint is reachable."""
        try:
            self._t.get("/healthz")
            return True
        except Exception:
            return False
