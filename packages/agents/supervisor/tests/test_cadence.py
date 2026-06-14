"""Tests — Track D D-2 per-tenant cadence config (inert; not activated)."""

from __future__ import annotations

from pathlib import Path

import pytest
from supervisor.cadence import (
    CADENCE_INTERVAL_SECONDS,
    CadenceConfigError,
    cadence_config_path,
    resolve_cadence,
)


def test_no_config_resolves_none(tmp_path: Path) -> None:
    """Default: no env, no file → None (nothing scheduled/activated)."""
    assert resolve_cadence(workspace_root=tmp_path, customer_id="acme", env={}) is None


def test_env_override_resolves(tmp_path: Path) -> None:
    cad = resolve_cadence(
        workspace_root=tmp_path,
        customer_id="acme",
        env={"NEXUS_CONTINUOUS_CADENCE": "weekly"},
    )
    assert cad is not None
    assert cad.tenant_id == "acme"
    assert cad.cadence == "weekly"
    assert cad.interval_seconds == CADENCE_INTERVAL_SECONDS["weekly"]


def test_env_override_is_case_insensitive(tmp_path: Path) -> None:
    cad = resolve_cadence(
        workspace_root=tmp_path, customer_id="acme", env={"NEXUS_CONTINUOUS_CADENCE": "Daily"}
    )
    assert cad is not None and cad.cadence == "daily"


def test_file_config_resolves(tmp_path: Path) -> None:
    path = cadence_config_path(tmp_path, "acme")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("cadence: monthly\n", encoding="utf-8")
    cad = resolve_cadence(workspace_root=tmp_path, customer_id="acme", env={})
    assert cad is not None
    assert cad.cadence == "monthly"
    assert cad.interval_seconds == 2_592_000


def test_env_takes_precedence_over_file(tmp_path: Path) -> None:
    path = cadence_config_path(tmp_path, "acme")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("cadence: monthly\n", encoding="utf-8")
    cad = resolve_cadence(
        workspace_root=tmp_path,
        customer_id="acme",
        env={"NEXUS_CONTINUOUS_CADENCE": "daily"},
    )
    assert cad is not None and cad.cadence == "daily"


def test_invalid_env_value_raises(tmp_path: Path) -> None:
    with pytest.raises(CadenceConfigError, match="cadence must be one of"):
        resolve_cadence(
            workspace_root=tmp_path,
            customer_id="acme",
            env={"NEXUS_CONTINUOUS_CADENCE": "hourly"},
        )


def test_file_without_cadence_key_raises(tmp_path: Path) -> None:
    path = cadence_config_path(tmp_path, "acme")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("interval: 99\n", encoding="utf-8")
    with pytest.raises(CadenceConfigError, match="must be a mapping with a 'cadence' key"):
        resolve_cadence(workspace_root=tmp_path, customer_id="acme", env={})


def test_all_three_cadences_have_intervals() -> None:
    assert set(CADENCE_INTERVAL_SECONDS) == {"daily", "weekly", "monthly"}
    assert CADENCE_INTERVAL_SECONDS["daily"] == 86_400
