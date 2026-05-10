# `nexus-control-plane`

Nexus control plane — **auth (Auth0 SSO/SCIM/RBAC/MFA) + tenant manager**.

> **Status:** F.4 plan in flight. This README will be expanded as tasks land.

## What it does (Phase 1a goal)

The control plane hosts the auth layer: Auth0-backed SSO (SAML for enterprise customers, OIDC for self-serve), SCIM 2.0 for centrally-controlled user provisioning, role-based access control with three Phase-1 roles (admin / operator / auditor), and MFA enforcement on admin actions. Every auth event is recorded through the [runtime charter](../charter/)'s hash-chained audit log per [ADR-002](../../docs/_meta/decisions/ADR-002-charter-as-context-manager.md).

This package is the SaaS-side concern: **agents and edge plane consume `tenant_id` from this manager but don't host the IdP themselves.** Every agent already plumbs `tenant_id` through its `NexusEnvelope` per [ADR-004](../../docs/_meta/decisions/ADR-004-fabric-layer.md).

## Layout

```
src/control_plane/
├── auth/         — JWT verifier, tenant resolver, RBAC, MFA, Auth0 mgmt-API client
├── tenants/      — SQLAlchemy models, CRUD, SCIM 2.0
├── api/          — FastAPI surface (login / callback / me / tenants / scim)
└── audit.py      — bridges auth events into the charter audit chain
```

## License

BSL 1.1 — control-plane code per [ADR-001](../../docs/_meta/decisions/ADR-001-monorepo-bootstrap.md).

## See also

- [F.4 plan](../../docs/superpowers/plans/2026-05-11-f-4-auth-tenant-manager.md).
- [`nexus-charter`](../charter/) — F.4 audit-instruments through the charter primitives.
- ADRs: [001](../../docs/_meta/decisions/ADR-001-monorepo-bootstrap.md) · [002](../../docs/_meta/decisions/ADR-002-charter-as-context-manager.md) · [004](../../docs/_meta/decisions/ADR-004-fabric-layer.md) · [005](../../docs/_meta/decisions/ADR-005-async-tool-wrapper-convention.md).
