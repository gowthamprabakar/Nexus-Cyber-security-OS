"""Structural tests for the `0002_memory_rls` migration (F.5 Task 7).

The real "off-tenant queries return empty" assertion is in Task 10's
live-Postgres integration test (RLS is a Postgres-only feature and
aiosqlite can't enforce it). What we *can* verify without Postgres:

1. The migration file exists with the right revision metadata and
   chains from `0001_memory_baseline`.
2. The migration's `upgrade()` body issues `ENABLE ROW LEVEL SECURITY`
   for every memory table and `CREATE POLICY ... USING (tenant_id =
   current_setting('app.tenant_id', true))` for every table.
3. The migration is gated by `dialect.name == 'postgresql'` so
   `upgrade head` against aiosqlite stays a no-op.
4. `downgrade()` cleanly reverses (DROP POLICY + DISABLE ROW LEVEL
   SECURITY for every table).
5. Alembic resolves exactly one head and that head is `0002_memory_rls`.
6. `upgrade head` + `downgrade base` against aiosqlite still work
   end-to-end (the RLS migration is a no-op on sqlite but must not
   raise).
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
_RLS = _VERSIONS_DIR / "0002_memory_rls.py"
_INI = _CHARTER_ROOT / "alembic.ini"

_TABLES = ("episodes", "playbooks", "entities", "relationships")


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


def test_rls_migration_file_exists() -> None:
    assert _RLS.is_file(), f"missing RLS migration at {_RLS}"


def test_rls_migration_chains_from_baseline() -> None:
    module = _load_module(_RLS)
    assert module.revision == "0002_memory_rls"
    assert module.down_revision == "0001_memory_baseline"
    assert callable(module.upgrade)
    assert callable(module.downgrade)


# ---------------------------- body declares policies --------------------


def test_rls_migration_enables_row_level_security_for_every_table() -> None:
    text = _RLS.read_text()
    for table in _TABLES:
        assert f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY" in text, (
            f"missing ENABLE ROW LEVEL SECURITY for {table}"
        )


def test_rls_migration_declares_tenant_isolation_policy_per_table() -> None:
    text = _RLS.read_text()
    for table in _TABLES:
        # We don't pin the policy name (callers may evolve naming), but
        # every table must reference the canonical session variable and
        # the tenant_id column inside a CREATE POLICY statement.
        assert "CREATE POLICY" in text
        assert f"ON {table}" in text, f"no policy targets {table}"
    assert "current_setting('app.tenant_id', true)" in text, (
        "RLS policy must read app.tenant_id with the missing_ok=true flag"
    )


def test_rls_migration_is_postgres_only() -> None:
    """`upgrade()` must be gated by `dialect.name == 'postgresql'` so
    aiosqlite unit tests don't trip the DDL.
    """
    text = _RLS.read_text()
    assert "postgresql" in text.lower()


def test_rls_migration_downgrade_drops_policies_and_disables_rls() -> None:
    text = _RLS.read_text()
    for table in _TABLES:
        assert "DISABLE ROW LEVEL SECURITY" in text
        assert "DROP POLICY" in text
        assert f"ON {table}" in text


# ---------------------------- alembic resolves the new head --------------


def test_rls_migration_is_the_unique_head() -> None:
    cfg = Config(str(_INI))
    cfg.set_main_option("script_location", str(_ALEMBIC_DIR))
    script = ScriptDirectory.from_config(cfg)
    heads = script.get_heads()
    assert list(heads) == ["0002_memory_rls"]


# ---------------------------- end-to-end against aiosqlite ---------------


@pytest.fixture
def sqlite_url(tmp_path: Path) -> str:
    return f"sqlite:///{tmp_path / 'memory.db'}"


def test_upgrade_head_against_aiosqlite_is_a_clean_noop_for_rls(
    sqlite_url: str,
) -> None:
    """The RLS DDL is gated by dialect — running upgrade head against
    sqlite must succeed and leave every memory table reachable.
    """
    from alembic import command
    from sqlalchemy import create_engine, inspect

    command.upgrade(_alembic_config_for(sqlite_url), "head")

    engine = create_engine(sqlite_url)
    insp = inspect(engine)
    tables = set(insp.get_table_names())
    for table in _TABLES:
        assert table in tables


def test_downgrade_head_against_aiosqlite_succeeds(sqlite_url: str) -> None:
    from alembic import command

    command.upgrade(_alembic_config_for(sqlite_url), "head")
    command.downgrade(_alembic_config_for(sqlite_url), "base")
