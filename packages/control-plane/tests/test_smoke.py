"""Smoke tests — package imports + ADR-002 charter dependency wired."""

from __future__ import annotations


def test_control_plane_imports() -> None:
    import control_plane

    assert control_plane.__version__ == "0.1.0"


def test_charter_dependency_resolves() -> None:
    """F.4 builds on F.1 — the charter audit primitive must be importable."""
    from charter.audit import AuditLog  # noqa: F401
    from charter.contract import ExecutionContract  # noqa: F401


def test_subpackages_exist() -> None:
    """The auth/tenants/api subpackages are scaffolded (filled in Tasks 2-10)."""
    import control_plane.api
    import control_plane.auth
    import control_plane.tenants  # noqa: F401
