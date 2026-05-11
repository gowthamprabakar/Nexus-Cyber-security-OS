"""Alembic baseline migration tests for the charter.memory schema (F.5 Task 2).

Three kinds of assertion, all executed without a live Postgres:

1. **Configuration shape** — `alembic.ini` points at the migrations dir;
   `env.py` uses `version_table = "alembic_version_memory"` so this
   alembic head coexists with control-plane's `alembic_version` head
   on a shared Postgres instance.

2. **Migration structure** — the baseline file `0001_memory_baseline.py`
   exists, has `revision = "0001_memory_baseline"`, `down_revision is
   None`, and exposes callable `upgrade()` + `downgrade()`. Test the
   *script body* contains the production indexes (GIN on payload,
   ivfflat on embedding, GIST on path) that the Task-1 dialect-portable
   models can't declare — these must live in the migration.

3. **End-to-end materialization** — drive alembic's `command.upgrade`
   programmatically against an aiosqlite database, then introspect the
   resulting tables/indexes/FKs to prove `upgrade head` works in online
   mode. Postgres-only indexes are skipped by the migration when the
   dialect is sqlite (gated inside the migration body).
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, inspect

_CHARTER_ROOT = Path(__file__).resolve().parents[1]
_ALEMBIC_DIR = _CHARTER_ROOT / "alembic"
_VERSIONS_DIR = _ALEMBIC_DIR / "versions"
_BASELINE = _VERSIONS_DIR / "0001_memory_baseline.py"
_INI = _CHARTER_ROOT / "alembic.ini"


# ---------------------------- 1. Configuration shape ---------------------


def test_alembic_ini_exists_and_points_at_script_dir() -> None:
    text = _INI.read_text()
    assert "[alembic]" in text
    assert "script_location = alembic" in text


def test_env_uses_distinct_version_table() -> None:
    """Critical: must be `alembic_version_memory`, NOT the default
    `alembic_version`. Otherwise running this migration against the same
    Postgres as control-plane corrupts control-plane's alembic head.
    """
    env = _ALEMBIC_DIR / "env.py"
    text = env.read_text()
    assert (
        'version_table="alembic_version_memory"' in text
        or "version_table='alembic_version_memory'" in text
    )


def test_script_directory_resolves_one_head() -> None:
    """The script directory always has exactly one head. The baseline
    revision is reachable from it; subsequent migrations chain on top
    (the head currently points at the latest revision in the chain).
    """
    cfg = Config(str(_INI))
    cfg.set_main_option("script_location", str(_ALEMBIC_DIR))
    script = ScriptDirectory.from_config(cfg)
    heads = script.get_heads()
    assert len(heads) == 1, f"expected exactly one head, got {heads}"
    # The baseline must still be reachable as a base revision.
    bases = script.get_bases()
    assert "0001_memory_baseline" in bases


# ---------------------------- 2. Migration structure ---------------------


def test_baseline_migration_file_exists() -> None:
    assert _BASELINE.is_file(), f"missing baseline migration at {_BASELINE}"


def test_baseline_has_required_callbacks_and_revision_metadata() -> None:
    spec = importlib.util.spec_from_file_location("_baseline", _BASELINE)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    assert callable(module.upgrade)
    assert callable(module.downgrade)
    assert module.revision == "0001_memory_baseline"
    assert module.down_revision is None


def test_baseline_body_declares_postgres_only_indexes() -> None:
    """Postgres-only indexes (GIN, ivfflat, GIST) must appear in the
    migration body since the dialect-portable models can't declare them.
    They're behind a `dialect.name == 'postgresql'` guard so aiosqlite
    upgrades cleanly without them.
    """
    text = _BASELINE.read_text()
    assert "ix_episodes_payload_gin" in text
    assert "ix_episodes_embedding_ivf" in text
    assert "ix_playbooks_path_gist" in text
    assert "vector_cosine_ops" in text
    assert "jsonb_path_ops" in text
    # The dialect guard — these indexes must be conditional, not unconditional.
    assert "postgresql" in text.lower()


# ---------------------------- 3. End-to-end materialization --------------


@pytest.fixture
def sqlite_url(tmp_path: Path) -> str:
    return f"sqlite:///{tmp_path / 'memory.db'}"


def _alembic_config_for(url: str) -> Config:
    cfg = Config(str(_INI))
    cfg.set_main_option("script_location", str(_ALEMBIC_DIR))
    cfg.set_main_option("sqlalchemy.url", url)
    return cfg


def test_upgrade_head_against_aiosqlite_creates_all_four_tables(sqlite_url: str) -> None:
    from alembic import command

    command.upgrade(_alembic_config_for(sqlite_url), "head")

    engine = create_engine(sqlite_url)
    insp = inspect(engine)
    tables = set(insp.get_table_names())
    assert {"episodes", "playbooks", "entities", "relationships"} <= tables


def test_upgrade_head_creates_distinct_version_table(sqlite_url: str) -> None:
    """Alembic must write to `alembic_version_memory`, not `alembic_version`."""
    from alembic import command

    command.upgrade(_alembic_config_for(sqlite_url), "head")

    engine = create_engine(sqlite_url)
    insp = inspect(engine)
    tables = set(insp.get_table_names())
    assert "alembic_version_memory" in tables
    assert "alembic_version" not in tables


def test_upgrade_head_declares_dialect_portable_indexes(sqlite_url: str) -> None:
    """The dialect-portable indexes (declared on the SQLAlchemy models)
    must still materialize against sqlite.
    """
    from alembic import command

    command.upgrade(_alembic_config_for(sqlite_url), "head")

    engine = create_engine(sqlite_url)
    insp = inspect(engine)
    episodes_idx = {i["name"] for i in insp.get_indexes("episodes")}
    playbooks_idx = {i["name"] for i in insp.get_indexes("playbooks")}
    entities_idx = {i["name"] for i in insp.get_indexes("entities")}
    relationships_idx = {i["name"] for i in insp.get_indexes("relationships")}

    assert {"ix_episodes_tenant_emitted", "ix_episodes_correlation"} <= episodes_idx
    assert "ix_playbooks_tenant_path" in playbooks_idx
    assert "ix_entities_tenant_type" in entities_idx
    assert {
        "ix_relationships_src_type",
        "ix_relationships_dst_type",
        "ix_relationships_tenant",
    } <= relationships_idx


def test_upgrade_head_declares_foreign_keys_with_cascade(sqlite_url: str) -> None:
    from alembic import command

    command.upgrade(_alembic_config_for(sqlite_url), "head")

    engine = create_engine(sqlite_url)
    insp = inspect(engine)
    fks = insp.get_foreign_keys("relationships")
    # Both src_entity_id and dst_entity_id reference entities with ON DELETE CASCADE.
    assert len(fks) == 2
    for fk in fks:
        assert fk["referred_table"] == "entities"
        assert fk["options"].get("ondelete") == "CASCADE"
    columns = {fk["constrained_columns"][0] for fk in fks}
    assert columns == {"src_entity_id", "dst_entity_id"}


def test_downgrade_head_drops_all_tables(sqlite_url: str) -> None:
    from alembic import command

    command.upgrade(_alembic_config_for(sqlite_url), "head")
    command.downgrade(_alembic_config_for(sqlite_url), "base")

    engine = create_engine(sqlite_url)
    insp = inspect(engine)
    tables = set(insp.get_table_names())
    assert not ({"episodes", "playbooks", "entities", "relationships"} & tables)
