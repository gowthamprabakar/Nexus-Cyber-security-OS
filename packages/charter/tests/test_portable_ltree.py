"""Mocked unit tests for `_PortableLtree` and its private `_LtreeColumn` emitter.

Task 3 of the F.5 LTREE substrate-fix plan
(`docs/superpowers/plans/2026-05-19-f5-ltree-substrate-fix.md`).

Two surfaces under test:

1. **`_LtreeColumn`** — the new private `UserDefinedType[str]` introduced
   by Task 2 (`acfc830`). Direct tests on the emitter itself: it returns
   `"LTREE"` as the SQL column type, and `cache_ok = True` is set (the
   latter is load-bearing for SQLAlchemy 2.x compiler caching — a missing
   or false `cache_ok` would force the compiler to bypass its statement
   cache for every query touching `playbooks.path`, a silent perf regression
   we want pinned).

2. **`_PortableLtree.load_dialect_impl`** — the dispatcher. Verifies the
   Postgres branch routes to `_LtreeColumn` (post-fix); the non-Postgres
   branch returns the unchanged `String(512)` fallback; and the class's
   pre-existing public attributes (`impl`, `cache_ok`) are untouched.

The mocked dialect is a minimal duck-typed stand-in: `name` is the only
attribute SQLAlchemy's `load_dialect_impl` contract reads, and
`type_descriptor` is the only method it calls. A passthrough
implementation is enough — we are not exercising SQLAlchemy's DDL
compiler here, just the routing logic in `_PortableLtree`. Live-Postgres
DDL emission is Task 5's job.

These tests catch regression at the unit-test layer in CI even without a
Postgres service container — closing the gap that allowed the original
LTREE bug to live latent: aiosqlite tests fell through to the `String(512)`
fallback and never touched the Postgres branch.
"""

from __future__ import annotations

from typing import Any

from charter.memory.models import _LtreeColumn, _PortableLtree
from sqlalchemy import String


class _FakeDialect:
    """Minimal duck-typed dialect for unit-testing `load_dialect_impl`.

    SQLAlchemy's `TypeDecorator.load_dialect_impl(dialect)` contract reads
    only `dialect.name` (to choose the branch) and calls
    `dialect.type_descriptor(t)` (to bind the chosen type to the dialect).
    Passthrough is sufficient for unit tests of the routing logic.
    """

    def __init__(self, name: str) -> None:
        self.name = name

    def type_descriptor(self, t: Any) -> Any:
        return t


# ----------------------------- _LtreeColumn ---------------------------------


def test_ltree_column_get_col_spec_returns_LTREE() -> None:
    """`_LtreeColumn().get_col_spec()` must return exactly `"LTREE"`.

    This is the core behaviour of the fix — the column-type emitter
    produces the same SQL type name `postgresql.LTREE()` would have
    produced if it existed. A regression here (e.g. `"Ltree"`, `"ltree"`,
    or omission) silently changes the DDL alembic emits for the
    `playbooks.path` column.
    """
    assert _LtreeColumn().get_col_spec() == "LTREE"


def test_ltree_column_cache_ok_is_true() -> None:
    """`cache_ok = True` keeps SQLAlchemy 2.x's compiler-caching path active.

    Per SQLAlchemy 2.0 docs: custom types that don't set `cache_ok`
    explicitly trigger compiler-cache bypass with a warning. A False or
    missing value would silently regress query-compilation performance
    for every statement touching `playbooks.path`. Pin it here so future
    refactors that drop the attribute fail CI.
    """
    assert _LtreeColumn.cache_ok is True


# ----------------------------- _PortableLtree.load_dialect_impl -------------


def test_portable_ltree_postgres_path_routes_to_ltree_column() -> None:
    """Postgres dialect path returns an `_LtreeColumn` whose DDL is `"LTREE"`.

    This is the load-bearing assertion of the substrate fix: against a
    dialect named `"postgresql"`, `_PortableLtree.load_dialect_impl`
    routes to the new emitter (rather than the previously-broken
    `postgresql.LTREE()` call). Confirms by both type and by the
    emitted column spec.
    """
    portable = _PortableLtree()
    result = portable.load_dialect_impl(_FakeDialect("postgresql"))

    assert isinstance(result, _LtreeColumn)
    assert result.get_col_spec() == "LTREE"


def test_portable_ltree_aiosqlite_path_returns_string_512_fallback() -> None:
    """Non-Postgres dialect path returns the unchanged `String(512)` fallback.

    This is the regression-guard for the path every existing aiosqlite
    unit test exercises. If a refactor accidentally changes the fallback
    column type (length, base type), every aiosqlite test of the
    `playbooks` table silently changes shape. Pin it here.
    """
    portable = _PortableLtree()
    result = portable.load_dialect_impl(_FakeDialect("sqlite"))

    assert isinstance(result, String)
    assert result.length == 512


def test_portable_ltree_unknown_dialect_also_falls_through_to_string_512() -> None:
    """Any dialect that is not `"postgresql"` hits the same `String(512)` fallback.

    Defensive: an unknown future dialect (e.g. `"mysql"`, `"oracle"`)
    must not crash; it must hit the fallback. The substrate's
    dialect-portability contract depends on this.
    """
    portable = _PortableLtree()
    result = portable.load_dialect_impl(_FakeDialect("mysql"))

    assert isinstance(result, String)
    assert result.length == 512


def test_portable_ltree_public_attributes_preserved() -> None:
    """`_PortableLtree`'s class-level `impl` + `cache_ok` survive the fix.

    Task 2 promised to leave `_PortableLtree`'s class shape untouched.
    Pin that promise so a future refactor cannot silently change the
    aiosqlite-fallback base type or drop the compiler-caching attribute.
    """
    assert _PortableLtree.impl is String
    assert _PortableLtree.cache_ok is True
