# Charter tenant-RLS fix — Brainstorm (SET LOCAL `$1` bug) — 2026-06-07

> **Parallel SAFETY-CRITICAL substrate cycle** authorized under γ sequencing (one parallel substrate cycle alongside the detection serial). Fixes the `SET LOCAL app.tenant_id = $1` tenant-RLS bug at [`charter/memory/service.py:96`](../../../packages/charter/src/charter/memory/service.py). Investigation + Q-lock surfacing stage.

- **Status:** brainstorm — **NO code yet.** Awaiting operator Q-locks before the plan doc.
- **Branch:** `feat/charter-tenant-rls-fix`
- **Scope:** the single charter substrate fix + its cross-agent regression proof + doc-drift cleanup. **No** v2.0 graph design, **no** detection-agent work, **no** other charter fixes, **no** Wazuh.
- **Why now / why SAFETY-CRITICAL:** blocks multi-tenant RLS on real Postgres; gates the **v2.0 security-graph substrate** — the single largest residual Wiz gap (~14–19 weighted pts, [PR #245 benchmark §7](../../_meta/competitive-benchmark-2026-06-08.md)). A single-line charter change that unblocks ~half the Wiz-comparison story.
- **Method:** 4 parallel read-only investigation agents (fix mechanism · caller inventory · cross-agent regression scope · doc drift), spot-checked against live code + the real-Postgres test suite.
- **Sources:** [`service.py`](../../../packages/charter/src/charter/memory/service.py) · [`0002_memory_rls.py`](../../../packages/charter/alembic/versions/) · [`0003_audit_events.py`](../../../packages/charter/alembic/versions/) · [`test_memory_live_postgres.py`](../../../packages/charter/tests/integration/test_memory_live_postgres.py) · [ADR-009 memory](../../_meta/decisions/ADR-009-memory-architecture.md) · the F.5 LTREE substrate-fix precedent · project memory `project_f5_set_local_tenant_rls_bug`.

---

## §0. Executive summary — the fix is trivial; the _scope_ is the decision

**The fix itself is settled and low-risk:** one line at `service.py:96`, `SET LOCAL app.tenant_id = :tid` → **`SELECT set_config('app.tenant_id', :tid, true)`** — the canonical, parameter-safe, transaction-scoped Postgres GUC pattern, behaviorally identical to `SET LOCAL` (third arg `true` = `is_local`). No edge-case surprises (§1). A **real-Postgres CI keystone already exists** — [`test_memory_live_postgres.py`](../../../packages/charter/tests/integration/test_memory_live_postgres.py) has 6 gated tests, **1 passing / 5 failing today**; the fix turns them green. That green suite _is_ the proof.

**The real decisions are about scope**, because the investigation found the blast radius is **narrower than the directive assumed**:

- The tenant-scoped `MemoryService.session(tenant_id=…)` seam is **called only from tests today** — agents call the store methods directly or default `semantic_store=None` (§2).
- Of the five agents the directive names (F.6 / A.4 / Compliance / Supervisor / D.12), **only F.6 Audit owns an RLS table** (`audit_events`) — and even F.6's read path currently **bypasses the seam** (its own session + app-side `WHERE tenant_id` filter), so RLS isn't actually _enforced_ for F.6 today. A.4 + Compliance default `semantic_store=None` (wiring them is **agent v0.2 work**, not substrate); Supervisor + D.12 are stateless / write-only and touch no RLS (§3).
- Doc drift is **78 references**, but only ~45 are live docs to update; ~33 are **dated point-in-time records** (verification records, plans, the merged benchmark) that must **not** be retroactively edited (§4).

So the genuine cross-agent regression surface is **charter's own RLS tables + F.6's `audit_events` policy** — not five agent test suites. The fix _unblocks_ all five agents; _wiring_ the None-defaulted ones is each agent's own cycle. **Folding agent-wiring into this substrate cycle is the scope-creep risk to guard against.** Q-locks in §5.

---

## §1. Axis 1 — fix mechanism ✅ (verified, no surprises)

**Buggy code** ([`service.py:82-99`](../../../packages/charter/src/charter/memory/service.py), the `session()` async ctx mgr):

```python
async with self._session_factory.begin() as session:        # inside a transaction
    dialect = session.bind.dialect.name if session.bind else ""
    if dialect == "postgresql":
        await session.execute(
            text("SET LOCAL app.tenant_id = :tid").bindparams(tid=tenant_id)   # ← line 96: Postgres rejects $1 on SET LOCAL
        )
    yield session
```

**Fix:** `await session.execute(text("SELECT set_config('app.tenant_id', :tid, true)").bindparams(tid=tenant_id))`.

- `set_config(name, value, is_local=true)` is the **parameter-safe** equivalent of `SET LOCAL`; `true` scopes it to the transaction (reverts on COMMIT/ROLLBACK) — **behaviorally identical**.
- **5 RLS policies** read `current_setting('app.tenant_id', true)` and resolve correctly once the GUC is set: `episodes` / `playbooks` / `entities` / `relationships` ([`0002_memory_rls.py:52-72`](../../../packages/charter/alembic/versions/)) + `audit_events` ([`0003_audit_events.py:95-99`](../../../packages/charter/alembic/versions/)).
- **Edge cases** (all safe, identical to `SET LOCAL`): transaction rollback clears it; savepoint rollback restores prior; **txn-mode** connection pooling is safe (cleared on commit before return-to-pool); **statement-mode** pooling breaks the same way `SET LOCAL` does and is already documented must-not-use; nested `session()` contexts each set their own value.
- **Single-file fix** — `grep` found no other `SET LOCAL` sites; consumers already read via `current_setting(...)` correctly.

**Keystone proof:** [`test_memory_live_postgres.py`](../../../packages/charter/tests/integration/test_memory_live_postgres.py), gated `NEXUS_LIVE_POSTGRES=1`, against real Postgres 16 + pgvector (the F.5 LTREE lane — `charter-f5-live.yml`). Currently **1 PASS** (alembic upgrade) / **5 FAIL** (CRUD, pgvector ANN, 3× RLS isolation). **Fix → 6 PASS** is the acceptance bar. (Note: only 3 of the 4 memory tables have an RLS isolation test — `relationships` is missing; add it — and there is no `audit_events` RLS test yet.)

---

## §2. Axis 2 — caller inventory (blast radius is small)

- **The tenant-scoped `session()` seam is invoked only by tests today** (6 live-Postgres tests + 1 unit test). No agent calls it directly; agents use the store methods.
- **Agent dependency on tenant-scoped memory:**
  - **D.7 Investigation** — the only agent with a **required** (non-None) `semantic_store` (graph walk). Genuinely blocked on real Postgres today.
  - **A.4 Meta-Harness · Compliance · D.13 Synthesis · D.8 Threat-Intel · F.3 Cloud-Posture** — `semantic_store=None` **by default**; KG writes are no-op-with-INFO-log guards. The fix _unblocks_ wiring, but wiring is each agent's own work.
  - **F.6 Audit** — has an `audit_events` RLS table, **but its read path** (`episode_audit_read` / `AuditStore.query`) constructs its **own** session and relies on app-side `WHERE tenant_id` filtering — it **bypasses** the `session()` seam, so RLS is not enforced for F.6 reads today.
  - **Supervisor · D.12 Curiosity** — stateless / fabric-write-only; **no** tenant-scoped reads.
- **Existing workarounds** the fix makes removable (eventually): the `semantic_store=None` no-op-with-log guards in ~5 agents' `kg_writer.py`. **Recommendation: keep them** — they remain correct defensive scaffolding until each agent is wired to multi-tenant (Q4).

## §3. Axis 3 — cross-agent regression scope (honest, narrower than the directive)

| Agent (directive list)                                                    | Genuinely uses tenant-scoped RLS today?                         | New RLS test needed this cycle?                                                                                     |
| ------------------------------------------------------------------------- | --------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| **Charter memory tables** (episodes/playbooks/entities/**relationships**) | **Yes** — the substrate itself                                  | **Yes** — fix the 5 live tests + add the missing `relationships` isolation test                                     |
| **F.6 Audit** (`audit_events`)                                            | Policy exists, but read path **bypasses** the seam (app-filter) | **Yes at charter/Postgres level** (prove the `audit_events` policy). F.6 read-path _rewire_ to enforce RLS = **Q2** |
| **A.4 Meta-Harness**                                                      | No — `semantic_store=None` default                              | No — fix _unblocks_; wiring is A.4's own v0.2 work                                                                  |
| **Compliance**                                                            | No — `semantic_store=None` default                              | No — same                                                                                                           |
| **Supervisor**                                                            | No — stateless router                                           | No                                                                                                                  |
| **D.12 Curiosity**                                                        | No — fabric write-only                                          | No                                                                                                                  |

**The honest regression surface = charter's RLS tables (5 live tests, +`relationships`) + the `audit_events` policy.** The directive's five-agent sweep over-counts: three of the five don't exercise RLS today, and wiring them in would be agent work, not substrate work (the scope-creep guard). This is **Q1**.

## §4. Axis 4 — documentation drift (78 refs; edit the live, preserve the dated)

| Bucket                                                           |  Count | Action                                                                                                                                                                                                                                                                           |
| ---------------------------------------------------------------- | -----: | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Live cross-cutting docs**                                      |    few | **Update this cycle:** [`agent-version-roadmaps` sketch](../sketches/2026-05-20-agent-version-roadmaps.md) (the master "blocked-agent" map), [ADR-006](../../_meta/decisions/ADR-006-openai-compatible-provider.md) ("blocked on SET LOCAL" clause), the `service.py` docstring. |
| **Agent READMEs** (user-facing "multi-tenant blocked")           |     ~8 | **Update on merge** (batched doc task) — remove the blocker caveat.                                                                                                                                                                                                              |
| **Agent source docstrings / NLAH READMEs / `None`-guards**       |    ~20 | **Leave** — still-correct defensive scaffolding until each agent wires multi-tenant (Q3/Q4).                                                                                                                                                                                     |
| **Dated records** (verification records, plan docs, brainstorms) | ~13+18 | **Do NOT edit** — historical point-in-time truth.                                                                                                                                                                                                                                |
| **Merged benchmark** (PR #245)                                   |      1 | **Footnote at most**, never retro-edit the body ("compiled while the bug was open; fixed in [PR#]").                                                                                                                                                                             |

**Principle (locked):** point-in-time records stay as written; only living docs lose the caveat. This is **Q3**.

---

## §5. Proposed Q-locks (operator decides) 🔒

|      # | Question                                 | Options                                                                                                                                                                                            | **Recommendation**                                                                                                                                                    |
| -----: | ---------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Q1** | **Cross-agent regression scope**         | (a) **Honest-minimal**: charter RLS tables (5 live tests + new `relationships` test) + `audit_events` policy test · (b) Full 5-agent sweep (requires wiring `semantic_store` into A.4/Compliance)  | **(a).** The fix _unblocks_ all five; wiring None-defaulted agents is each agent's own v0.2 cycle. Folding it in = scope creep.                                       |
| **Q2** | **F.6 Audit read path**                  | (a) Add the `audit_events` RLS test at charter/Postgres level; leave F.6's read path (app-filter) as a fast-follow · (b) Rewire F.6 reads through the GUC this cycle (true RLS enforcement)        | **(a).** Prove the policy now; F.6 read-path rewire is a small _agent_ change, fast-follow — keeps this a single-file substrate cycle.                                |
| **Q3** | **Doc-update scope**                     | (a) Update live cross-cutting docs (roadmap sketch + ADR-006 + `service.py` docstring) + the ~8 agent README caveats; leave dated records · (b) Sweep all 45 live refs incl. source docstrings now | **(a).** Update the living docs; never touch dated records (footnote the benchmark only). Source-docstring/`None`-guard cleanup rides with each agent's wiring cycle. |
| **Q4** | **`semantic_store=None` no-op guards**   | Keep (defensive) · Remove now                                                                                                                                                                      | **Keep.** Still-correct scaffolding; the fix unblocks but does not auto-wire agents. Removing = agent work.                                                           |
| **Q5** | **Add missing `relationships` RLS test** | Yes · No                                                                                                                                                                                           | **Yes** — closes the 3-of-4-tables gap so all four memory tables have isolation proof.                                                                                |

---

## §6. Proposed task breakdown (plan + 4 tasks)

|    # | Risk                | Title                                        | Description                                                                                                                                                                                                                                                                    |
| ---: | ------------------- | -------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Plan | LOW-RISK            | Plan doc                                     | Decomposition of this brainstorm under the Q-locks.                                                                                                                                                                                                                            |
|    1 | **SAFETY-CRITICAL** | Apply the fix at `service.py:96`             | `SET LOCAL` → `set_config('app.tenant_id', :tid, true)`; update the docstring (lines 86-90). **Charter substrate touch** — no auto-merge; verify against merged-branch HEAD; the substrate-seal guard tripping _is the seal working_.                                          |
|    2 | LOW-RISK            | Charter RLS regression proof (real Postgres) | Turn the 5 live-Postgres tests green; **add** the `relationships` isolation test + an `audit_events` isolation test (Q5, Q2-a). Keystone: `NEXUS_LIVE_POSTGRES=1` → all green.                                                                                                 |
|    3 | LOW-RISK            | Doc updates (live only)                      | Roadmap sketch + ADR-006 + `service.py` docstring + the ~8 agent README "multi-tenant blocked" caveats → unblocked (Q3-a). **No** dated-record edits; footnote the benchmark.                                                                                                  |
|    4 | LOW-RISK            | Verification record + closure                | Fix proven **end-to-end against real Postgres** (not a SQLAlchemy mock); multi-tenant trust restored for charter + F.6; **v2.0 security-graph substrate dependency unblocked**; deferred handoff: per-agent `semantic_store` wiring (A.4/Compliance/D.7) to each agent's v0.2. |

**Calendar:** ~1–2 weeks (the directive's estimate); the fix is hours, the cross-agent proof + docs + verification carry the rest.

## §7. Risk profile + verification

- **Task 1 SAFETY-CRITICAL** (charter substrate): full review, verify-against-HEAD, operator approval gate, expect the substrate-seal guard. **Tasks 2-4 LOW-RISK.**
- **The verification bar is end-to-end against actual Postgres** — the gated `test_memory_live_postgres.py` suite going from 1/6 → 6/6 (+2 new tests) is the proof, not unit mocks. Reuse the F.5 LTREE real-Postgres CI lane.
- **Rollback safety:** single-line change; if the live suite regresses, revert is one line.

## §8. Guardrails (restated)

❌ No code yet (plan after Q-locks) · ❌ No v2.0 graph design (Track 3, after this lands) · ❌ No detection-agent work · ❌ No other charter fixes · ❌ No Wazuh · ❌ No retro-editing dated records · ❌ No folding agent `semantic_store` wiring into this cycle · ✅ Single substrate fix + honest cross-agent RLS proof · ✅ SAFETY-CRITICAL discipline on Task 1 · ✅ Real-Postgres verification.

---

## §9. Next step

**Operator: lock Q1–Q5 (or amend).** On lock, the plan doc (`docs/superpowers/plans/2026-06-XX-charter-tenant-rls-fix.md`) decomposes §6 into per-task PRs (Task 1 SAFETY-CRITICAL, Tasks 2-4 LOW-RISK). No code until the plan is locked.

— drafted 2026-06-07 (charter tenant-RLS fix brainstorm; parallel substrate cycle under γ sequencing).
