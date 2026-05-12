"""Structural + end-to-end tests for the `0003_audit_events` migration (F.6 Task 3).

The migration chains from `0002_memory_rls`, creates the `audit_events`
table, declares the three production indexes, and (Postgres-only)
enables RLS + the `tenant_isolation` policy. Aiosqlite skips the RLS
block but materialises the table cleanly.

Assertions in this file fall in three groups (matching the pattern in
`test_memory_alembic.py` + `test_memory_rls_migration.py`):

1. File + revision metadata: file exists, chains from `0002_memory_rls`,
   `upgrade` + `downgrade` callable.
2. Body declares RLS + tenant_isolation policy + Postgres-only GIN index
   on payload, all gated by `dialect.name == 'postgresql'`.
3. End-to-end against aiosqlite: `upgrade head` lands the table + the
   three dialect-portable indexes; `downgrade base` drops everything;
   alembic head becomes `0003_audit_events`.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest
from alembic.config import Config
from alembic.script import ScriptDirectory

_CHARTER_ROOT = Path(__file__).resolve().parents[1]
_ALEMBIC_DIR = _CHARTER_ROOT / "alembic"
_VERSIONS_DIR = _ALEMBIC_DIR / "versions"
_MIGRATION = _VERSIONS_DIR / "0003_audit_events.py"
_INI = _CHARTER_ROOT / "alembic.ini"


def _load_module(path: Path):  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location(f"_{path.stem}", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _alembic_config_for(url: str) -> Config:
    cfg = Config(str(_INI))
    cfg.set_main_option("script_location", str(_ALEMBIC_DIR))
    cfg.set_main_option("sqlalchemy.url", url)
    return cfg


# ---------------------------- file + revision metadata ------------------


def test_audit_events_migration_file_exists() -> None:
    assert _MIGRATION.is_file(), f"missing migration at {_MIGRATION}"


def test_audit_events_migration_chains_from_rls() -> None:
    module = _load_module(_MIGRATION)
    assert module.revision == "0003_audit_events"
    assert module.down_revision == "0002_memory_rls"
    assert callable(module.upgrade)
    assert callable(module.downgrade)


def test_audit_events_migration_is_the_unique_head() -> None:
    cfg = Config(str(_INI))
    cfg.set_main_option("script_location", str(_ALEMBIC_DIR))
    script = ScriptDirectory.from_config(cfg)
    heads = script.get_heads()
    assert list(heads) == ["0003_audit_events"]


# ---------------------------- body declarations -------------------------


def test_migration_declares_audit_events_create_table() -> None:
    text = _MIGRATION.read_text()
    assert "create_table" in text and "audit_events" in text


def test_migration_declares_tenant_entry_hash_unique_constraint() -> None:
    text = _MIGRATION.read_text()
    assert "uq_audit_events_tenant_entry_hash" in text


def test_migration_declares_three_production_indexes() -> None:
    text = _MIGRATION.read_text()
    for ix in (
        "ix_audit_events_tenant_emitted",
        "ix_audit_events_tenant_action",
        "ix_audit_events_correlation",
    ):
        assert ix in text


def test_migration_declares_postgres_only_rls_block() -> None:
    """RLS DDL must be gated by `dialect.name == 'postgresql'` so the
    aiosqlite upgrade stays a clean no-op for the RLS portion.
    """
    text = _MIGRATION.read_text()
    assert "ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY" in text
    assert "CREATE POLICY" in text
    assert "current_setting('app.tenant_id', true)" in text
    assert "postgresql" in text.lower()


def test_migration_declares_payload_gin_index_postgres_only() -> None:
    """Production-grade JSONB query path needs a GIN index — Postgres-only,
    gated by dialect (mirrors the F.5 baseline pattern).
    """
    text = _MIGRATION.read_text()
    assert "ix_audit_events_payload_gin" in text
    assert "jsonb_path_ops" in text


# ---------------------------- end-to-end against aiosqlite --------------


@pytest.fixture
def sqlite_url(tmp_path: Path) -> str:
    return f"sqlite:///{tmp_path / 'memory.db'}"


def test_upgrade_head_creates_audit_events_table(sqlite_url: str) -> None:
    from alembic import command
    from sqlalchemy import create_engine, inspect

    command.upgrade(_alembic_config_for(sqlite_url), "head")

    engine = create_engine(sqlite_url)
    insp = inspect(engine)
    tables = set(insp.get_table_names())
    assert "audit_events" in tables


def test_upgrade_head_declares_dialect_portable_indexes(sqlite_url: str) -> None:
    from alembic import command
    from sqlalchemy import create_engine, inspect

    command.upgrade(_alembic_config_for(sqlite_url), "head")

    engine = create_engine(sqlite_url)
    insp = inspect(engine)
    index_names = {i["name"] for i in insp.get_indexes("audit_events")}
    assert {
        "ix_audit_events_tenant_emitted",
        "ix_audit_events_tenant_action",
        "ix_audit_events_correlation",
    } <= index_names


def test_downgrade_base_drops_audit_events_table(sqlite_url: str) -> None:
    from alembic import command
    from sqlalchemy import create_engine, inspect

    command.upgrade(_alembic_config_for(sqlite_url), "head")
    command.downgrade(_alembic_config_for(sqlite_url), "base")

    engine = create_engine(sqlite_url)
    insp = inspect(engine)
    tables = set(insp.get_table_names())
    assert "audit_events" not in tables
