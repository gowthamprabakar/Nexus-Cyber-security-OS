"""Alembic environment for the charter.memory schema.

This alembic head is intentionally **separate** from
control-plane's alembic head: the two packages must be able to share a
single Postgres instance without their migrations stomping on each
other's `alembic_version` row. Solved by `version_table =
"alembic_version_memory"` (offline + online) — control-plane keeps
`alembic_version`, charter.memory keeps `alembic_version_memory`.

Reads `sqlalchemy.url` from `alembic.ini`; honors `NEXUS_DATABASE_URL`
as an environment-variable override so CI / Docker Compose can point
at a non-default Postgres without editing the ini.
"""

from __future__ import annotations

import os
from logging.config import fileConfig

from alembic import context
from charter.memory.models import Base
from sqlalchemy import engine_from_config, pool

config = context.config

db_url = os.environ.get("NEXUS_DATABASE_URL")
if db_url:
    config.set_main_option("sqlalchemy.url", db_url)

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        version_table="alembic_version_memory",
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            version_table="alembic_version_memory",
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
