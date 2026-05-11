"""Charter audit-chain adapter for control-plane events.

Wraps `charter.AuditLog` in an async-safe interface the FastAPI layer
can call from request handlers. Every auth/tenant/SCIM event lands as
a hash-chained `AuditEntry`; `charter.verifier.verify_audit_log` reads
the chain back and confirms integrity per ADR-002.

Canonical event names (dot-namespaced):

- `auth.login.initiated`        — `/auth/login` redirect emitted
- `auth.login.succeeded`        — verified-token returned from /auth/me
- `auth.login.failed`           — JWT verifier rejected the token
- `auth.callback.succeeded`     — Auth0 code -> token exchange ok
- `auth.callback.failed`        — Auth0 token exchange returned non-200
- `tenant.created`              — POST /tenants minted a tenant row
- `tenant.suspended`            — tenant flipped to suspended state
- `user.provisioned.scim`       — SCIM POST /Users created a row
- `user.deactivated.scim`       — SCIM PATCH active=false or DELETE
- `mfa.required.failure`        — MFA gate tripped on an admin action

Event names are stable wire identifiers — downstream consumers
(eval-framework, fabric layer) join on them.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

from charter.audit import AuditEntry, AuditLog

AuditEmit = Callable[[str, dict[str, Any]], Awaitable[None]]


class ControlPlaneAuditor:
    """Async-safe wrapper around `charter.AuditLog`.

    The control plane is a long-running service so we use a fixed
    `run_id` ("singleton") in v0.1; per-tenant logs land in Phase 1c
    when SOC2 evidence collection wants tenant-scoped chains.
    """

    def __init__(
        self,
        *,
        log_path: Path | str,
        agent: str = "control-plane",
        run_id: str = "singleton",
    ) -> None:
        self._log = AuditLog(Path(log_path), agent=agent, run_id=run_id)
        self._lock = asyncio.Lock()

    @property
    def path(self) -> Path:
        return self._log.path

    async def emit(self, event: str, payload: dict[str, Any]) -> AuditEntry:
        """Append an event to the audit chain. Serialized via internal lock."""
        async with self._lock:
            return await asyncio.to_thread(self._log.append, event, payload)


def make_audit_emit(auditor: ControlPlaneAuditor) -> AuditEmit:
    """Project the `ControlPlaneAuditor.emit` shape onto the FastAPI hook signature."""

    async def _emit(event: str, payload: dict[str, Any]) -> None:
        await auditor.emit(event, payload)

    return _emit


__all__ = [
    "AuditEmit",
    "ControlPlaneAuditor",
    "make_audit_emit",
]
