# D.2 + F.4 verification record — 2026-05-11

Joint final-verification gate for two Phase-1a tracks shipped in parallel:

- **D.2 — Identity Agent (CIEM).** Agent #3 of 18. **Second consumer of ADR-007 v1.1** (post-amendment canon).
- **F.4 — Auth + Tenant Manager.** Phase-1a foundation pillar (after F.1 charter + F.2 eval framework). Lands the SOC 2 Type I starting condition.

All sixteen D.2 tasks and all twelve F.4 tasks are committed; every paired commit's hash is pinned in the corresponding plan.

---

## Gate results

### D.2 — Identity Agent

| Gate                                                   | Threshold                                                     | Result                         |
| ------------------------------------------------------ | ------------------------------------------------------------- | ------------------------------ |
| `pytest --cov=identity --cov-fail-under=80`            | ≥ 80%                                                         | **97.46%** (142 tests passing) |
| `ruff check`                                           | clean                                                         | ✅                             |
| `ruff format --check`                                  | clean                                                         | ✅                             |
| `mypy --strict`                                        | clean (12 source files)                                       | ✅                             |
| `identity-agent eval`                                  | 10/10                                                         | ✅                             |
| `eval-framework run --runner identity`                 | 10/10 (100.0%)                                                | ✅                             |
| `eval-framework gate suite --config min_pass_rate=1.0` | exit 0                                                        | ✅                             |
| **ADR-007 v1.1 conformance**                           | no `identity/llm.py`; `charter.llm_adapter` consumed directly | ✅                             |

### F.4 — Auth + Tenant Manager

| Gate                                                                        | Threshold                                  | Result                         |
| --------------------------------------------------------------------------- | ------------------------------------------ | ------------------------------ |
| `pytest --cov=control_plane --cov-fail-under=80`                            | ≥ 80%                                      | **90.67%** (130 tests passing) |
| `ruff check`                                                                | clean                                      | ✅                             |
| `ruff format --check`                                                       | clean                                      | ✅                             |
| `mypy --strict`                                                             | clean (13 source files)                    | ✅                             |
| Charter audit chain verifies via `charter.verifier`                         | `result.valid is True`                     | ✅ (test_audit.py)             |
| Operator runbook at `packages/control-plane/runbooks/auth0_tenant_setup.md` | exists; 8 sections + common-failures table | ✅                             |

### Repo-wide sanity check

`uv run pytest -q` → **730 passed, 5 skipped** (skips are opt-in integration tests requiring LocalStack / Ollama).

---

## D.2 — ADR-007 v1.1 conformance review

D.2 is the second agent built to the reference template. Each of the ten canon patterns reviewed:

| Pattern                                                | Verdict                             | Notes                                                                                                                                         |
| ------------------------------------------------------ | ----------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| Schema-as-typing-layer (OCSF wire format)              | ✅ generalizes                      | `class_uid 2004` Detection Finding; five-bucket FindingType enum                                                                              |
| Async-by-default tool wrappers (boto3 → `to_thread`)   | ✅ generalizes                      | aws_iam_list_identities, aws_iam_simulate_principal_policy, aws_access_analyzer_findings                                                      |
| HTTP-wrapper convention                                | n/a                                 | Identity is boto3-only                                                                                                                        |
| Concurrent `asyncio.TaskGroup` enrichment              | ✅ generalizes                      | IAM listing + Access Analyzer fetch run in parallel                                                                                           |
| Markdown summarizer (top-down severity)                | ✅ generalizes                      | one delta: "High-risk principals" section pinned above per-severity                                                                           |
| NLAH layout (README + tools.md + examples/)            | ✅ generalizes; **HOIST CANDIDATE** | nlah_loader is now materially identical across cloud-posture / vulnerability / identity. Flagged in `identity.nlah_loader`'s module docstring |
| LLM adapter via `charter.llm_adapter` (post-amendment) | ✅ **twice-validated**              | Anti-pattern guard test added (`test_no_per_agent_llm_module`) — `importlib.util.find_spec("identity.llm")` must be `None`                    |
| Charter context + `agent.run` signature shape          | ✅ generalizes                      | Signature: `run(contract, *, llm_provider=None, ...)`                                                                                         |
| Eval-runner via entry-point group                      | ✅ generalizes                      | `nexus_eval_runners`: `identity → identity.eval_runner:IdentityEvalRunner`; 10/10 via the framework CLI                                       |
| CLI subcommand pattern (`eval` + `run`)                | ✅ generalizes                      | Click group; same shape as D.1                                                                                                                |

**Twice-validated:** ADR-007 v1.1's hoist of `llm.py` into `charter.llm_adapter` works end-to-end across both consumers. **No new amendment required from D.2.**

**One follow-up flagged for the v1.2 candidate:** the NLAH loader is now identical across three agents. Hoisting it into `charter.nlah_loader` would let every future agent `from charter.nlah_loader import load_system_prompt` instead of copying. We don't land that here — three data points justify the hoist; per ADR-007 v1.1's "amend on the third duplicate" discipline, we propose v1.2 amendment **before D.3** ships.

---

## F.4 — Phase-1a foundation review

F.4 ships from scratch (no agent-side reference template). All twelve tasks closed; per-task surface:

| Surface                                             | Module                                                              | Tests                      |
| --------------------------------------------------- | ------------------------------------------------------------------- | -------------------------- |
| Tenant + User + Role models (pydantic + SQLAlchemy) | `control_plane/tenants/models.py`                                   | 19                         |
| Alembic baseline                                    | `control_plane/alembic/versions/0001_initial_tenant_user_tables.py` | 4                          |
| Auth0 management-API client                         | `control_plane/auth/auth0_client.py`                                | 10                         |
| JWT verifier (RS256 + JWKS cache)                   | `control_plane/auth/jwt_verifier.py`                                | 11                         |
| Tenant resolver (first-login provisioning)          | `control_plane/tenants/resolver.py`                                 | 8                          |
| RBAC (3 roles × 7 actions, hard-coded)              | `control_plane/auth/rbac.py`                                        | 27                         |
| SCIM 2.0 endpoint (HMAC-signed)                     | `control_plane/api/scim.py`                                         | 14                         |
| FastAPI surface (login/callback/me/tenants)         | `control_plane/api/auth_routes.py`                                  | 15                         |
| MFA enforcement gate                                | `control_plane/auth/mfa.py`                                         | 10                         |
| Charter audit-chain adapter                         | `control_plane/auth/audit.py`                                       | 9                          |
| Operator runbook                                    | `runbooks/auth0_tenant_setup.md`                                    | n/a (8 sections + cleanup) |

**Q-decisions resolved in code:**

- **Q1 (DB engine for the tenant table).** F.4 owns Postgres with alembic; F.5 inherits the engine config when it lands.
- **Q2 (JWT claim format).** Auth0 namespaced custom claims (`https://nexus.app/tenant_id`, `https://nexus.app/roles`), compatible with Auth0 Rules / Actions and any upstream IdP that injects claims.
- **Q3 (RBAC model).** Hard-coded in code for Phase 1. DB-backed roles deferred to Phase 1c with a one-shot migration when custom roles become a real signal.

---

## Wiz weighted coverage delta

Coverage is computed as a sum of (Wiz product weight × Nexus capability coverage). Per the [system-readiness recommendation](system-readiness-2026-05-11-eod.md):

| Product family                      | Wiz weight       | D.1 baseline | D.2 + F.4 contribution                | New estimate |
| ----------------------------------- | ---------------- | ------------ | ------------------------------------- | ------------ |
| CSPM (F.3 + D.1 contributors)       | 0.40             | 8%           | –                                     | 8%           |
| Vulnerability (D.1)                 | 0.15             | 3%           | –                                     | 3%           |
| **CIEM (D.2)**                      | **0.10**         | 0%           | +3pp (~30% template parity × 0.10)    | **3pp**      |
| **Identity + tenant manager (F.4)** | n/a (foundation) | 0pp          | +0pp (substrate, not direct coverage) | –            |
| Other Wiz products                  | 0.35             | 0.8%         | –                                     | 0.8%         |
| **Total**                           | **1.00**         | **11.8%**    | **+3pp from D.2**                     | **~14.8%**   |

F.4 doesn't directly move weighted coverage — it's foundation, not a security capability. Its leverage shows up in Phase 1c when the SaaS-side admin console (S.1 / S.2) consumes tenants + RBAC + MFA from this manager.

---

## Sub-plan completion delta

Closed in this run:

- D.2 Identity Agent (16/16) — +1 agent (#3 of 18).
- F.4 Auth + Tenant Manager (12/12) — Phase-1a foundation pillar #3.

**Phase-1a foundation status:** F.1 charter ✅ · F.2 eval framework ✅ · F.3 cloud-posture ✅ · F.4 auth + tenant ✅ · F.5 memory engines ⬜ (next).
**Track-D agent status:** D.1 vulnerability ✅ · D.2 identity ✅ · D.3+ pending.

Three agents now ship to the reference template. Pattern fitness across three consumers: ten of ten canon items either generalize cleanly or call out one named follow-up (NLAH loader hoist) for v1.2.

---

## Carried-forward risks (not blockers for ship)

1. **NLAH loader is duplicated** across three agents. Hoist to `charter.nlah_loader` before D.3 lands (would be ADR-007 v1.2 amendment).
2. **IAM `Condition` evaluation + SCPs deferred** in the resolver. v0.1 driver synthesizes admin grants from `attached_policy_arns` rather than invoking the simulator per principal — Phase 2 turns on the per-action path.
3. **MFA signal is operator-supplied** to the agent. Phase 1c wires it from cloud-posture's IAM credential-report helpers.
4. **SCIM PATCH only honors `replace active=false`** in v0.1. Broader PATCH paths land when a real customer asks.
5. **Husky deprecation warnings** continue to surface on every commit hook. Cosmetic in v9; will fail in v10. Migration when convenient.

---

## Sign-off

D.2 Identity Agent + F.4 Auth + Tenant Manager are **production-ready for v0.1 deterministic flows**. Phase 1c work (customer console, Tier-2 remediation, charter-instrumented audit wiring at the route layer) is sequenced from here.

— recorded 2026-05-11
