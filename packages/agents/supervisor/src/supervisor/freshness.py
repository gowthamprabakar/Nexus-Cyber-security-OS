"""Freshness-signal API for continuous mode (Track D D-2).

An **activation prerequisite** (audit §11): v0.3 BUILDS the freshness surface;
v0.4 ACTIVATES it (the continuous loop calls :func:`record_run` on each
dispatch). In v0.3 this is an inert, **queryable** file-backed store —
``last_refreshed(...)`` answers "when was agent X last refreshed for tenant T",
returning ``None`` until something writes. Nothing here starts a loop or
registers a scheduler (pause trigger #25 stays clear).

Backing file: ``<workspace_root>/.supervisor/freshness/<customer_id>.json`` — a
flat ``{agent_id: iso8601_timestamp}`` map, mirroring the established
``.supervisor/<subdir>/<customer>`` convention used by ``scheduled_queue``. No
charter/shared change (the store is supervisor-local; substrate seal empty).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

_FRESHNESS_SUBDIR = Path(".supervisor") / "freshness"


class FreshnessStoreError(ValueError):
    """Raised when a freshness file exists but is malformed."""


def freshness_path(workspace_root: Path, customer_id: str) -> Path:
    """The per-tenant freshness file path (mirrors the scheduled_queue layout)."""
    return workspace_root / _FRESHNESS_SUBDIR / f"{customer_id}.json"


def _load(path: Path) -> dict[str, str]:
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise FreshnessStoreError(f"freshness store is malformed JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise FreshnessStoreError(f"freshness store {path} must be a JSON object")
    return {str(k): str(v) for k, v in data.items()}


def last_refreshed(workspace_root: Path, *, agent_id: str, customer_id: str) -> datetime | None:
    """When was ``agent_id`` last refreshed for ``customer_id``? ``None`` if never.

    The freshness signal every consumer can query (per the pipeline doc). A
    missing file or missing agent entry → ``None`` (not an error).
    """
    raw = _load(freshness_path(workspace_root, customer_id)).get(agent_id)
    if raw is None:
        return None
    try:
        return datetime.fromisoformat(raw)
    except ValueError as exc:
        raise FreshnessStoreError(f"freshness timestamp for {agent_id} is invalid: {raw}") from exc


def all_freshness(workspace_root: Path, *, customer_id: str) -> dict[str, datetime]:
    """All ``agent_id → last_refreshed`` entries for a tenant (empty if none)."""
    out: dict[str, datetime] = {}
    for agent_id, raw in _load(freshness_path(workspace_root, customer_id)).items():
        try:
            out[agent_id] = datetime.fromisoformat(raw)
        except ValueError as exc:
            raise FreshnessStoreError(
                f"freshness timestamp for {agent_id} is invalid: {raw}"
            ) from exc
    return out


def record_run(
    workspace_root: Path,
    *,
    agent_id: str,
    customer_id: str,
    at: datetime | None = None,
) -> None:
    """Stamp ``agent_id``'s last-refreshed time for ``customer_id``.

    The WRITE side of the freshness signal. **v0.3 does NOT call this from any
    loop** — it exists so the v0.4 continuous loop can stamp freshness on each
    dispatch (activation). Tested directly here. Idempotent upsert; creates the
    file + parent dir on first write.
    """
    when = at if at is not None else datetime.now(UTC)
    path = freshness_path(workspace_root, customer_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    current = _load(path)
    current[agent_id] = when.isoformat()
    path.write_text(json.dumps(current, indent=2, sort_keys=True), encoding="utf-8")
