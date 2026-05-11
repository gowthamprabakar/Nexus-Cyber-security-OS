# F.4 — Auth + Tenant Manager Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Pause for review after each numbered task.

**Goal:** Ship the **Auth + Tenant Manager** — Phase 1a foundation. Auth0 SSO (SAML + OIDC), SCIM provisioning, RBAC, MFA enforcement. Lives at `packages/control-plane/` (the SaaS-side concern; agents and edge plane consume tenant identity but don't host the IdP). The eventual Phase 1c console (S.1 / S.2) and ChatOps (S.3) consume `tenant_id` from this manager; every agent already plumbs `tenant_id` through the `NexusEnvelope` per ADR-004.

**Strategic role.** Phase 1a's third foundation pillar after F.1 (charter) and F.2 (eval framework). F.3 + D.1 ship without it because v0.1 deterministic flows operate inside a single tenant (`cust_test` / `cust_eval`); F.4 is what lets a real customer onboard. **Lands the SOC 2 Type I starting condition** — without identity-and-access controls there's nothing to audit.

**Architecture:** The control plane hosts the auth layer; agents are auth-consumers, not auth-providers. The boundaries:

```
┌─────────────────────────────────────────────────────────────┐
│ Auth0 (managed IdP)                                         │
│   - SAML federation (enterprise customer IdPs)              │
│   - OIDC (Google / Microsoft / GitHub for self-serve)       │
│   - MFA enforcement (TOTP / WebAuthn)                       │
│   - Session management + JWT issuance                       │
└─────────────────────────────────────────────────────────────┘
        │  JWT (id_token + access_token)
        ▼
┌─────────────────────────────────────────────────────────────┐
│ control-plane.auth                                          │
│   - JWT verification (Auth0 JWKS public keys, cached)       │
│   - Tenant resolution (claim → tenant_id)                   │
│   - RBAC (role → permitted actions)                         │
│   - SCIM 2.0 endpoint (Auth0 provisions; we materialize)    │
└─────────────────────────────────────────────────────────────┘
        │  AuthContext(tenant_id, user_id, roles)
        ▼
┌─────────────────────────────────────────────────────────────┐
│ control-plane.tenants                                       │
│   - Tenant CRUD (create / suspend / delete)                 │
│   - Tenant-scoped resource isolation                        │
│   - User → tenant mapping                                   │
│   - Audit of tenant changes                                 │
└─────────────────────────────────────────────────────────────┘
        │
        ▼
   Agents + Console (consumers via FastAPI dependency injection)
```

**Tech stack:** Python 3.12 · BSL 1.1 · pydantic 2.9 · `nexus-charter` (workspace dep — for `Charter`, audit primitives) · `nexus-shared` (workspace dep — for `NexusEnvelope`'s `tenant_id` field) · **PyJWT** (JWT verification) · **httpx** (Auth0 management API + JWKS fetch) · **fastapi** (HTTP surface; reuses what S.4 will need) · **sqlalchemy + asyncpg** OR **pgvector-aware ORM** (tenant table; coordinated with F.5 memory engines). dev: pytest + respx (httpx mocking) + freezegun (JWT expiry).

**Depends on:**

- F.1 (charter) — auth events emit through the charter audit chain.
- F.5 in lockstep — the tenant table is the first F.5 schema. Either F.4 ships its own minimal Postgres setup OR F.4 + F.5 share the migration / engine config. **Decision in Task 1** (see Q1 below).

**Defers (Phase 2+):**

- Customer-managed encryption keys (CMKs / BYOK) for tenant data — Phase 2 enterprise tier.
- Multi-region failover for Auth0 — Phase 2 GA hardening.
- Just-in-time user provisioning (JIT/SAML) without SCIM — Phase 1c.
- Federated tenant graphs (parent / child organizations) — Phase 2 healthcare.
- API-key auth for service-to-service (separate from user JWTs) — S.4 (REST API + CLI) territory; wired in Phase 1b.

**Reference template:** No prior auth/tenant code in this repo — this is a from-scratch spec. The tasks below mirror F.1's discipline (TDD, async-by-default, charter-instrumented) without an agent-side template to copy.

---

## Execution status

```
1 → 2 → 3 → 4 → 5 → 6 → 7 → 8 → 9 → 10 → 11 → 12
```

| Task | Status     | Commit    | Notes                                                                                                                  |
| ---- | ---------- | --------- | ---------------------------------------------------------------------------------------------------------------------- |
| 1    | ✅ done    | `aa0f687` | Bootstrap `packages/control-plane/` (pyproject + auth/ + tenants/ + api/ + README); 3 smoke tests; F.5 boundary set    |
| 2    | ✅ done    | `9d4fbb5` | `Tenant` + `User` + `Role` pydantic + SQLAlchemy models; alembic baseline `0001_initial`; 19 tests                     |
| 3    | ✅ done    | `e54962c` | Auth0 management-API client (httpx + tenacity + token cache); 10 respx tests; retry on 429/5xx                         |
| 4    | ✅ done    | `52f709b` | JWT verifier (RS256 + JWKS cache); 11 respx tests; **Q2 resolved** (Auth0 namespaced custom claims)                    |
| 5    | ✅ done    | `c1f2b81` | Tenant resolver — first-login provisioning + suspended-tenant reject; 8 aiosqlite tests                                |
| 6    | ✅ done    | `90d176b` | RBAC table — 3 roles × 7 actions; 27 tests; **Q3 resolved** (hard-coded; DB-backed deferred to Phase 1c)               |
| 7    | ✅ done    | `46a3388` | SCIM 2.0 endpoint — POST/GET/PATCH/DELETE /Users; HMAC-signed; 14 tests via FastAPI TestClient + aiosqlite             |
| 8    | ✅ done    | `1120d1f` | FastAPI surface — login redirect, callback, /auth/me, /tenants/me, POST /tenants (admin); 15 tests + audit hook        |
| 9    | ✅ done    | `da6928c` | MFA enforcement gate — `amr` must contain `mfa` for all actions except READ_FINDINGS; 10 tests                         |
| 10   | ✅ done    | `c099c79` | Charter audit chain — `ControlPlaneAuditor` wraps `charter.AuditLog`; 9 tests; chain verifies via charter.verifier     |
| 11   | ⬜ pending | —         | Operator runbook — Auth0 tenant creation, SAML setup for an enterprise customer, SCIM webhook config                   |
| 12   | ⬜ pending | —         | Final verification (≥ 80% coverage; ruff/mypy clean; integration test against Auth0 sandbox; SOC 2 evidence checklist) |

ADR references: [ADR-001](../../_meta/decisions/ADR-001-monorepo-bootstrap.md) · [ADR-002](../../_meta/decisions/ADR-002-charter-as-context-manager.md) · [ADR-004](../../_meta/decisions/ADR-004-fabric-layer.md) · [ADR-005](../../_meta/decisions/ADR-005-async-tool-wrapper-convention.md).

---

## Key design questions (resolve in Tasks 1 + 2 + 4)

### Q1 — Database engine for the tenant table (F.4 / F.5 boundary)

F.5 (Memory engines) plans for TimescaleDB (episodic) + PostgreSQL (procedural) + Neo4j Aura (semantic). The tenant table is **procedural** state. Two options:

- **F.4 ships its own minimal Postgres setup** (alembic + asyncpg) and F.5 adopts it later. Risk: schema drift if F.5 reshuffles the engine config.
- **F.4 + F.5 land Postgres together as a joint sub-task** (`F.4.0 / F.5.0` shared migration baseline). Risk: F.4 blocks on F.5 design.

Per the [system-readiness recommendation](../../_meta/system-readiness-2026-05-11-eod.md) to "collapse to PostgreSQL + JSONB + pgvector for Phase 1a," F.4 ships its own minimal Postgres setup with alembic. F.5 inherits the migration baseline.

**Resolution:** F.4 owns Postgres. F.5 adopts the engine config when it lands.

### Q2 — Tenant-id JWT claim format

Auth0 `id_token` carries standard claims (`sub`, `iss`, `aud`, etc.) plus custom claims via Auth0 Rules / Actions. We need `tenant_id` and `roles` in the token. Two paths:

- **Custom Auth0 Action** that injects `https://nexus.app/tenant_id` and `https://nexus.app/roles` claims on login. Standard pattern; well-documented.
- **Lookup at verification time** — pull `tenant_id` from our own DB based on `sub`. Simpler claim, more DB load.

**Resolution (in Task 4):** custom Auth0 Action (claims namespaced under `https://nexus.app/`). Reduces DB lookups; standard practice.

### Q3 — RBAC model

Role-based vs attribute-based. Phase 1 should be simple:

- **Three roles:** `admin` (everything), `operator` (read + tier-2/3 remediation approvals), `auditor` (read-only).
- **No custom roles** in v0.1; deferred to Phase 1c.
- **Permission table** is hard-coded in Python (not DB-driven) for v0.1; DB-backed permissions land in Phase 1c when `auditor` and `operator` need finer-grained subdivisions per customer.

**Resolution (in Task 6):** three hard-coded roles + a `permission_for(role, action)` lookup function.

---

## File Structure

```
packages/control-plane/
├── pyproject.toml                              # name=nexus-control-plane, BSL 1.1
├── README.md
├── alembic.ini                                 # migration config
├── alembic/
│   └── versions/                               # migration history
├── runbooks/
│   └── auth0_tenant_setup.md                   # Task 11
├── src/control_plane/
│   ├── __init__.py
│   ├── py.typed
│   ├── auth/
│   │   ├── __init__.py
│   │   ├── jwt_verifier.py                     # Task 4
│   │   ├── tenant_resolver.py                  # Task 5
│   │   ├── rbac.py                             # Task 6
│   │   ├── mfa.py                              # Task 9
│   │   └── auth0_client.py                     # Task 3
│   ├── tenants/
│   │   ├── __init__.py
│   │   ├── models.py                           # Task 2 (SQLAlchemy)
│   │   ├── service.py                          # CRUD
│   │   └── scim.py                             # Task 7
│   ├── api/
│   │   ├── __init__.py
│   │   ├── auth_routes.py                      # Task 8
│   │   ├── tenant_routes.py
│   │   ├── scim_routes.py                      # Task 7
│   │   └── deps.py                             # FastAPI dependency injection
│   └── audit.py                                # Task 10 (charter-bridge)
└── tests/
    ├── test_smoke.py
    ├── test_auth0_client.py
    ├── test_jwt_verifier.py
    ├── test_tenant_resolver.py
    ├── test_rbac.py
    ├── test_mfa.py
    ├── test_models.py
    ├── test_scim.py
    ├── test_api_auth.py
    ├── test_api_scim.py
    ├── test_audit.py
    └── integration/
        └── test_auth0_sandbox.py               # opt-in via NEXUS_LIVE_AUTH0=1
```

---

## Tasks

### Task 1: Bootstrap + Postgres baseline

Create `packages/control-plane/` with the dir layout above. Resolve **Q1** (Postgres ownership).

- [ ] **Step 1: Write failing smoke test** — `from control_plane import __version__`.
- [ ] **Step 2: pyproject.toml** — name=nexus-control-plane, BSL 1.1, deps: nexus-charter, nexus-shared, fastapi, sqlalchemy, asyncpg, alembic, pyjwt, httpx, tenacity, structlog. Dev: pytest + respx + freezegun + pytest-asyncio + httpx-test-client + types-PyJWT.
- [ ] **Step 3: alembic init** — `packages/control-plane/alembic/` with empty migration baseline.
- [ ] **Step 4: Update root pyproject** — add `packages/control-plane` to `[tool.uv.workspace.members]` (already there as skeleton; verify) and `[tool.mypy.files]`.
- [ ] **Step 5: Commit** — `feat(control-plane): bootstrap auth + tenant package skeleton (F.4 task 1)`.

**Acceptance:** `uv sync` resolves; smoke test passes; alembic command available.

---

### Task 2: Tenant + User + Role models

Pydantic models for the API surface; SQLAlchemy models for persistence.

```python
class Tenant(BaseModel):
    tenant_id: str  # ULID
    name: str
    auth0_org_id: str | None  # nullable until SAML org is provisioned
    created_at: datetime
    suspended_at: datetime | None

class User(BaseModel):
    user_id: str  # ULID
    auth0_sub: str  # the JWT `sub` claim
    tenant_id: str
    email: EmailStr
    role: Role  # enum
    last_login_at: datetime | None

class Role(StrEnum):
    ADMIN = "admin"
    OPERATOR = "operator"
    AUDITOR = "auditor"
```

- [ ] **Step 1: Write failing tests** — pydantic validation, role round-trip, ULID format check.
- [ ] **Step 2: Implement** pydantic + SQLAlchemy models in parallel; alembic migration creates the tables.
- [ ] **Step 3: Tests pass** — ≥ 8 tests.
- [ ] **Step 4: Commit** — `feat(control-plane): tenant + user + role models with first migration (F.4 task 2)`.

---

### Task 3: Auth0 management-API client

Async httpx client per ADR-005 / ADR-007 v1.1's HTTP-wrapper convention. Wraps:

- `POST /api/v2/users` — invite a user.
- `GET /api/v2/users` — list (paginated).
- `POST /api/v2/organizations` — create a SAML org (for enterprise tenants).
- `POST /oauth/token` — fetch a management API access token (cached for ~24h).

- [x] **Step 1: Write failing tests** with respx — happy paths + 4xx error mapping + 5xx retry.
- [x] **Step 2: Implement**.
- [x] **Step 3: Tests pass** — 10/10 (token cache, invite, list, create-org, 5xx retry/exhaust, 429 retry, oauth 4xx).
- [x] **Step 4: Commit** — `e54962c feat(d2,f4): aws iam listing tool + auth0 management api client (D.2 + F.4 task 3)`. Bundled with D.2 Task 3.

---

### Task 4: JWT verifier

Resolve **Q2** (JWT claim format). The verifier:

- Fetches the Auth0 JWKS once and caches public keys for ~24h.
- Validates signature (RS256).
- Validates `iss` (must be the Auth0 tenant URL).
- Validates `aud` (must include our API audience).
- Validates `exp` and `nbf`.
- Extracts custom claims (`https://nexus.app/tenant_id`, `https://nexus.app/roles`).

```python
@dataclass(frozen=True, slots=True)
class VerifiedToken:
    sub: str
    tenant_id: str
    roles: tuple[str, ...]
    expires_at: datetime
    amr: tuple[str, ...]  # for MFA check (Task 9)
```

- [x] **Step 1: Write failing tests** — valid token, expired, bad signature, wrong iss/aud, missing custom claim, unknown kid, JWKS caching, JWKS 5xx.
- [x] **Step 2: Implement** with PyJWT.
- [x] **Step 3: Tests pass** — 11/11 (one-shot RSA keypair + respx-mocked JWKS endpoint).
- [x] **Step 4: Commit** — `52f709b feat(d2,f4): iam policy simulator + auth0 jwt verifier (D.2 + F.4 task 4)`. Bundled with D.2 Task 4. **Q2 resolved**: tenant/roles via Auth0 namespaced custom claims (`https://nexus.app/...`).

---

### Task 5: Tenant resolver

Maps `VerifiedToken → (tenant_id, user_id)`. First-login auto-provisions a `User` row tied to the JWT's `sub` and the token's `tenant_id` claim.

- [x] **Step 1: Write failing tests** — first-login provisions, repeat-login resolves, last_login updates, role-from-token, unknown-role fallback, unknown-tenant reject, suspended-tenant reject.
- [x] **Step 2: Implement**.
- [x] **Step 3: Tests pass** — 8/8 (in-memory aiosqlite; greenlet added to dev deps).
- [x] **Step 4: Commit** — `c1f2b81 feat(d2,f4): access analyzer wrapper + tenant resolver (D.2 + F.4 task 5)`. Bundled with D.2 Task 5.

---

### Task 6: RBAC

Resolve **Q3** (RBAC model). Hard-coded permission table:

```python
class Action(StrEnum):
    READ_FINDINGS = "read_findings"
    APPROVE_TIER_2 = "approve_tier_2"
    EXECUTE_TIER_1 = "execute_tier_1"  # Phase 1c
    MANAGE_USERS = "manage_users"
    MANAGE_TENANT = "manage_tenant"
    # ... grow as agents land

_PERMISSIONS: dict[Role, frozenset[Action]] = {
    Role.ADMIN: frozenset(Action),
    Role.OPERATOR: frozenset({Action.READ_FINDINGS, Action.APPROVE_TIER_2}),
    Role.AUDITOR: frozenset({Action.READ_FINDINGS}),
}

def permission_for(role: Role, action: Action) -> bool:
    return action in _PERMISSIONS[role]
```

- [x] **Step 1: Write failing tests** — full role × action matrix parametrized.
- [x] **Step 2: Implement** with hard-coded `_PERMISSIONS` table (Phase 1 — DB-backed deferred to 1c).
- [x] **Step 3: Tests pass** — 27/27 (21 matrix entries + 6 invariants).
- [x] **Step 4: Commit** — `90d176b feat(d2,f4): permission-path resolver + rbac table (D.2 + F.4 task 6)`. Bundled with D.2 Task 6.

**Q3 resolved**: hard-coded RBAC for Phase 1; DB-backed roles deferred to Phase 1c. The migration is a one-shot dump of the dict, so we lose nothing by deferring.

---

### Task 7: SCIM 2.0 endpoint

Auth0 provisions users via SCIM webhooks; we materialize them in our `users` table. Endpoints:

- `POST /scim/v2/Users` — create user.
- `PATCH /scim/v2/Users/{id}` — update (most commonly: deactivate).
- `DELETE /scim/v2/Users/{id}` — hard delete (rare; usually replaced by `active: false` patch).
- `GET /scim/v2/Users/{id}` — read (Auth0 needs this for syncs).

HMAC-signed; secret rotated quarterly.

- [x] **Step 1: Write failing tests** — POST/GET/PATCH/DELETE happy paths + 401 (bad HMAC) + 400 (malformed) + 404 (unknown tenant/user) + 409 (duplicate).
- [x] **Step 2: Implement**.
- [x] **Step 3: Tests pass** — 14/14 (FastAPI TestClient + aiosqlite). PATCH only honors `replace active=false` in v0.1; broader PATCH-path support deferred.
- [x] **Step 4: Commit** — `46a3388 feat(d2,f4): findings normalizer + scim 2.0 endpoint (D.2 + F.4 task 7)`. Bundled with D.2 Task 7.

---

### Task 8: FastAPI surface

Wire the auth + tenant flow:

- `GET /auth/login` — redirects to Auth0 hosted login.
- `GET /auth/callback` — receives Auth0 code, exchanges for tokens, sets session cookie.
- `GET /auth/me` — returns the current `VerifiedToken`'s claims.
- `GET /tenants/me` — returns the current user's `Tenant`.
- `POST /tenants` — admin-only; create a new tenant (calls Auth0 mgmt API to create the org).

Charter-instrumented — every route emits an audit entry through `Charter`.

- [x] **Step 1: Write failing tests** with FastAPI TestClient — login redirect, callback exchange + sad paths, /auth/me + 401 + cookie-read, /tenants/me + 404, POST /tenants admin gate + 403/401/422, audit-hook invocation.
- [x] **Step 2: Implement** with factory-injected `verify_token` / `auth0_client` / `audit_emit` so the JWT-crypto, Auth0-mgmt-API, and audit-chain surfaces stay decoupled.
- [x] **Step 3: Tests pass** — 15/15.
- [x] **Step 4: Commit** — `1120d1f feat(d2,f4): identity markdown summarizer + fastapi auth surface (D.2 + F.4 task 8)`. Bundled with D.2 Task 8. `audit_emit` is a noop hook today; Task 10 wires it through the charter audit chain.

---

### Task 9: MFA enforcement gate

Verify the Auth0 `amr` (Authentication Methods References) claim contains `mfa`. Reject any token without MFA on admin-scoped actions (every action except `READ_FINDINGS`).

```python
def require_mfa(token: VerifiedToken) -> None:
    if "mfa" not in token.amr:
        raise PermissionDenied("MFA required for this action")
```

- [x] **Step 1: Write failing tests** — predicate, require_mfa raise/pass, requires_mfa_for matrix, integration test (POST /tenants 403 without MFA).
- [x] **Step 2: Implement** in `control_plane.auth.mfa`; wire `require_mfa` into POST /tenants.
- [x] **Step 3: Tests pass** — 10/10 (9 unit + 1 integration); failure emits `mfa_required_failure` via existing audit hook.
- [x] **Step 4: Commit** — `da6928c feat(d2,f4): identity nlah bundle + mfa enforcement (D.2 + F.4 task 9)`. Bundled with D.2 Task 9.

---

### Task 10: Audit instrumentation

Per ADR-002, every auth event emits a hash-chained audit entry. Events:

- `auth_login_succeeded` — payload: `sub`, `tenant_id`, `amr`.
- `auth_login_failed` — payload: `error_code`, `attempted_email` (no PII beyond email).
- `tenant_created` — payload: `tenant_id`, `auth0_org_id`, `creator_sub`.
- `user_provisioned_via_scim` — payload: `user_id`, `tenant_id`, `source: "scim"`.
- `mfa_required_failure` — payload: `sub`, `action`.
- `tenant_suspended` — payload: `tenant_id`, `reason`.

These bridge into the charter audit chain via a small adapter.

- [x] **Step 1: Write failing tests** — chain integrity, charter.verifier round-trip, concurrent emits serialized, payload/agent/run_id fidelity, action-name preservation.
- [x] **Step 2: Implement** `ControlPlaneAuditor` (async lock + `to_thread` around `charter.AuditLog.append`) + `make_audit_emit` adapter for the FastAPI hook.
- [x] **Step 3: Tests pass** — 9/9.
- [x] **Step 4: Commit** — `c099c79 feat(d2,f4): consume charter.llm_adapter + charter audit chain (D.2 + F.4 task 10)`. Bundled with D.2 Task 10. The auth_routes / scim handlers continue to call their existing `audit_emit` hook — Task 11 (or the operator runbook) wires `ControlPlaneAuditor` as the default in production.

---

### Task 11: Operator runbook

`runbooks/auth0_tenant_setup.md`. Walks an operator through:

1. Auth0 tenant creation (one-time per environment: dev / staging / prod).
2. Creating an Auth0 Application (`name = nexus-control-plane`, type = Regular Web Application).
3. Configuring callback URLs.
4. Creating a custom Action that injects `https://nexus.app/tenant_id` + `https://nexus.app/roles`.
5. SAML connection setup for an enterprise customer (with their IdP metadata XML).
6. SCIM endpoint configuration in Auth0 (URL, secret rotation).
7. MFA policy enforcement at the Auth0 tenant level.
8. Verifying the integration via the Auth0 sandbox + our integration test.

- [ ] **Step 1: Write the runbook**.
- [ ] **Step 2: Commit** — `docs(control-plane): auth0 tenant setup runbook (F.4 task 11)`.

---

### Task 12: Final verification

Mirror F.3 / F.2 / D.1's gate set:

1. `uv run pytest packages/control-plane/ --cov=control_plane --cov-fail-under=80` — ≥ 80%.
2. `uv run ruff check + format --check + mypy strict` — all clean.
3. `uv run pytest packages/control-plane/tests/integration/test_auth0_sandbox.py` (with `NEXUS_LIVE_AUTH0=1` against an Auth0 dev tenant) — full login flow + tenant create + SCIM provision succeed.
4. **SOC 2 Type I evidence checklist** — append to F.4's verification record:
   - [ ] User provisioning is centrally controlled (SCIM) ✓
   - [ ] Strong authentication is enforced (MFA on admin) ✓
   - [ ] Authentication events are logged immutably (hash-chained audit) ✓
   - [ ] Tenant boundaries are enforced (resolver + RBAC) ✓
   - [ ] Failed login attempts are recorded (`auth_login_failed`) ✓
5. Re-issue [system-readiness](../../_meta/system-readiness.md) with F.4 done; weighted Wiz coverage unchanged (auth doesn't add detection capability) but **Phase 1a foundation track moves from 50% → 67%**.

Capture `docs/_meta/f4-verification-<date>.md`.

- [ ] **Step 1: Run all gates.**
- [ ] **Step 2: Write verification record** including the SOC 2 evidence checklist.
- [ ] **Step 3: Re-issue system-readiness**.
- [ ] **Step 4: Commit** — `docs(f4): final verification + soc2 evidence checklist + readiness re-issue`.

**Acceptance:** Auth + tenant manager runs end-to-end against a real Auth0 tenant. SOC 2 Type I scoping has its starting evidence. Customer onboarding flow is unblocked (the missing piece for "sell to a paying customer" gate).

---

## Self-Review

**Spec coverage** (build-roadmap entry "Auth0 SSO (SAML + OIDC), SCIM provisioning, RBAC, MFA enforcement"):

- ✓ Auth0 SSO (SAML + OIDC) — Tasks 3, 4, 8.
- ✓ SCIM provisioning — Task 7.
- ✓ RBAC — Task 6.
- ✓ MFA enforcement — Task 9.

**Defers (Phase 2+):**

- BYOK / customer-managed keys.
- Multi-region Auth0 failover.
- JIT/SAML without SCIM.
- Federated tenant graphs.
- Service-to-service API keys (S.4 territory).
- Custom roles beyond admin/operator/auditor.
- DB-backed permissions table.

**SOC 2 evidence**: ✓ User provisioning, ✓ Strong auth, ✓ Audit logging, ✓ Tenant boundaries, ✓ Failed-login records. The five Common Criteria CC6 controls have starter evidence by Task 12; full Type I audit happens at M9 per the [build roadmap](2026-05-08-build-roadmap.md) Phase 1c exit gate.

**Type / name consistency:**

- Package import name: `control_plane`.
- FastAPI app: `nexus-control-plane`.
- Auth0 application name: `nexus-control-plane`.
- Custom JWT claim namespace: `https://nexus.app/`.

**Acceptance for F.4 as a whole:** Auth + tenant manager ships end-to-end against a real Auth0 tenant; SOC 2 Type I evidence checklist filled out; customer-onboarding flow demo-able to a design partner.

---

## References

- [F.1 plan](2026-05-08-f-1-runtime-charter-v0.1.md) — charter primitives F.4 audit-instruments through.
- [Build roadmap](2026-05-08-build-roadmap.md) — F.4 entry.
- [System readiness 2026-05-11 EOD](../../_meta/system-readiness-2026-05-11-eod.md) — Phase 1a foundation track at 50% before F.4.
- [Platform architecture](../../architecture/platform_architecture.md) — auth section.
- ADRs: [ADR-001](../../_meta/decisions/ADR-001-monorepo-bootstrap.md) · [ADR-002](../../_meta/decisions/ADR-002-charter-as-context-manager.md) · [ADR-004](../../_meta/decisions/ADR-004-fabric-layer.md) · [ADR-005](../../_meta/decisions/ADR-005-async-tool-wrapper-convention.md).
- Auth0 docs: [Custom Actions](https://auth0.com/docs/customize/actions) · [SCIM 2.0](https://auth0.com/docs/manage-users/user-migration/configure-automatic-migration-from-auth0) · [Management API](https://auth0.com/docs/api/management/v2).
