"""Per-tenant continuous-mode cadence configuration (Track D D-2).

An **activation prerequisite**, per audit §11: v0.3 BUILDS the cadence surface;
v0.4 ACTIVATES it. This module only *loads and resolves* a per-tenant cadence
(``daily`` / ``weekly`` / ``monthly`` → ``interval_seconds``). It deliberately
does NOT register anything with a ``ContinuousDriver`` — feeding cadence into a
live driver is activation (pause trigger #25), reserved for v0.4. The resolved
cadence is an inert, queryable value the ``run`` CLI echoes in its decision
record.

Resolution order (first match wins):
1. ``NEXUS_CONTINUOUS_CADENCE`` env var (``daily``/``weekly``/``monthly``).
2. ``<workspace_root>/.supervisor/cadence/<customer_id>.yaml`` (key ``cadence``).
3. ``None`` — no cadence configured (the default; nothing to activate).

File-backed config mirrors the established ``.supervisor/<subdir>/<customer>``
convention used by ``scheduled_queue`` — no charter/shared change (substrate
seal stays empty; the cadence type is supervisor-local).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Literal, get_args

import yaml
from pydantic import BaseModel, ConfigDict

#: The supported human-facing cadences and their wall-clock interval in seconds.
#: ``monthly`` uses a 30-day convention (matching the claims-bus 30-day retention).
Cadence = Literal["daily", "weekly", "monthly"]
CADENCE_INTERVAL_SECONDS: dict[str, int] = {
    "daily": 86_400,
    "weekly": 604_800,
    "monthly": 2_592_000,
}

CADENCE_ENV = "NEXUS_CONTINUOUS_CADENCE"
_CADENCE_SUBDIR = Path(".supervisor") / "cadence"


class CadenceConfigError(ValueError):
    """Raised when a cadence config value is present but invalid."""


class TenantCadence(BaseModel):
    """A resolved per-tenant cadence — inert config, not a live schedule."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    tenant_id: str
    cadence: Cadence
    interval_seconds: int


def _validate_cadence(value: str) -> Cadence:
    if value not in get_args(Cadence):
        raise CadenceConfigError(f"cadence must be one of {list(get_args(Cadence))}, got {value!r}")
    return value  # type: ignore[return-value]


def cadence_config_path(workspace_root: Path, customer_id: str) -> Path:
    """The per-tenant cadence config path (mirrors the scheduled_queue layout)."""
    return workspace_root / _CADENCE_SUBDIR / f"{customer_id}.yaml"


def resolve_cadence(
    *, workspace_root: Path, customer_id: str, env: dict[str, str] | None = None
) -> TenantCadence | None:
    """Resolve the per-tenant cadence (env override → file → None).

    Returns ``None`` when no cadence is configured — the default; nothing is
    scheduled or activated. Raises :class:`CadenceConfigError` only when a
    value is *present but invalid* (loud failure, never silent).
    """
    environ = env if env is not None else dict(os.environ)

    env_value = environ.get(CADENCE_ENV)
    if env_value:
        cadence = _validate_cadence(env_value.strip().lower())
        return TenantCadence(
            tenant_id=customer_id,
            cadence=cadence,
            interval_seconds=CADENCE_INTERVAL_SECONDS[cadence],
        )

    path = cadence_config_path(workspace_root, customer_id)
    if not path.is_file():
        return None
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise CadenceConfigError(f"cadence config is malformed YAML: {exc}") from exc
    if not isinstance(data, dict) or "cadence" not in data:
        raise CadenceConfigError(f"cadence config {path} must be a mapping with a 'cadence' key")
    cadence = _validate_cadence(str(data["cadence"]).strip().lower())
    return TenantCadence(
        tenant_id=customer_id,
        cadence=cadence,
        interval_seconds=CADENCE_INTERVAL_SECONDS[cadence],
    )
