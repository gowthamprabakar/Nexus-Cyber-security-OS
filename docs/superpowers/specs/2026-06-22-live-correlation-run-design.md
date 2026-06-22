# Live Correlation Run on a Persistent Graph — Design Spec

**Date:** 2026-06-22
**Branch:** `slice-live-correlation-run`
**Predecessors:** the two toxic-combination slices (detection + opt-in OCSF emit, both merged; detection now ON by default). Those run against an in-memory graph in tests. This slice makes the graph **persistent (real Postgres)** and **populated by real agent runs**, so D.7 finds a toxic combination on a graph the agents actually built — not a hand-seeded test graph.

## Goal

A `correlation_run(store, tenant)` that, in one process: runs data-security then identity (both writing to ONE shared persistent `SemanticStore`), then runs investigation (D.7) against that graph + the agents' findings, producing a **persisted** OCSF 2005 toxic-combination finding. Proven against **real Postgres** (gated) and in-memory (CI). Cloud data is injected as fixtures; the gate is persistence (`NEXUS_LIVE_POSTGRES`), not live AWS.

## Scope decision & the one refinement (from due-diligence)

Chosen scope = the full real win (not plumbing-only, not fake grants). Due-diligence refined exactly one thing: **`HAS_ACCESS_TO` is derived offline as "over-permissioned (admin-grade) principal → every tenant `CLOUD_RESOURCE` node".** This is real and a true positive (an admin genuinely can reach the public PII bucket), driving identity's existing-but-dormant `_synthesize_admin_grants`. Fine-grained non-admin access is **deferred** (it needs a concrete per-statement `Resource` extractor that does not exist, and the live `SimulatePrincipalPolicy` simulator needs live AWS and doesn't return concrete ARNs anyway).

## Components

### 1. `build_semantic_store(dsn)` — production store factory (NEW)

Location: `packages/charter/src/charter/memory/` (next to `MemoryService`).
A near-verbatim lift of the proven live-Postgres test pattern: `create_async_engine(dsn)` → run `alembic upgrade head` (sync `+psycopg2` URL) → `async_sessionmaker(engine, expire_on_commit=False)` → `SemanticStore(session_factory)`. Today the only store factory in the repo is the in-memory test one (`fleet_testkit.in_memory_semantic_store`); this is the missing production counterpart.

- Signature: `async def build_semantic_store(dsn: str, *, run_migrations: bool = False) -> SemanticStore`.
- RLS: tenant scoping is the **working** `set_config('app.tenant_id', :tid, true)` path (commit 5b8cefc) inside `SemanticStore`/`MemoryService.session`. Confirmed by 6/6 live RLS tests.

### 2. Identity writes real `HAS_ACCESS_TO` (drive dormant code + small expander)

File: `packages/agents/identity/src/identity/agent.py` (run() KG-write block) + `kg_writer.py` (already has `record_access`, currently uncalled).
When `semantic_store` is present, after `record_listing(listing)`:

- compute admin grants via the existing offline `_synthesize_admin_grants(listing)` → `EffectiveGrant(principal_arn, resource_pattern="*", is_admin=True)`;
- fetch tenant resources via `semantic_store.list_entities_by_type(tenant_id=customer_id, entity_type=NodeCategory.CLOUD_RESOURCE.value)` (the resource nodes data-security wrote, keyed by ARN);
- write edges: `record_access([(grant.principal_arn, resource.external_id) for grant in admin_grants for resource in resources])`.
  This is the only NEW logic (~15 lines): expand `*` against concrete tenant resources. `record_access` upserts idempotently → edges land on the existing resource nodes.
  **Ordering requirement:** data-security must run BEFORE identity so the resource nodes exist when identity lists them. (Identity run alone with an empty resource set writes no `HAS_ACCESS_TO` — graceful.)
  **Honest bound (documented, not faked):** admin-grade only; non-admin fine-grained access + live simulator deferred. Coarseness is O(admins × resources) edges — acceptable for v1; noted.

### 3. `correlation_run` orchestrator (NEW, the right shape)

Location: `packages/runtime/src/nexus_runtime/` (new module). NOT the supervisor's parallel dispatch — correlation is inherently ordered (writers before reader), so a sequenced orchestrator is correct.
Responsibilities: build/receive the shared store; construct 3 `ExecutionContract`s (one per agent, each with its own workspace — cheap, pattern proven in each agent's tests); run data-security (fixture S3 feeds) → identity (fixture `IdentityListing`) → D.7 with `sibling_workspaces=(ds_workspace, identity_workspace)` and `detect_toxic_combinations=True` (default). D.7 reads identity's `findings.json` (the OVERPRIVILEGE 2004 findings) to seed the detector, and the shared graph for the edges.
The supervisor's `del semantic_store # v0.1 placeholder` is real scaffold debt — flagged as a **noted follow-up** (cleaning it means threading the store through the parallel invoker protocol, a separate concern), not silently left as "done".

## Data flow

fixture S3 inventory → data-security writes `CLOUD_RESOURCE`(ARN)+`is_public`+`EXPOSES_DATA` to the shared store → fixture `IdentityListing` → identity writes `IDENTITY` + `HAS_ACCESS_TO`(over-perm principal → each tenant resource) + emits OVERPRIVILEGE 2004 findings.json → D.7 reads the findings (seed) + the graph → `find_public_data_exposure` → `TOXIC_COMBINATION` node + OCSF 2005, all persisted (Postgres) / in the store (CI).

## Testing

1. **CI orchestration test** (ungated, in-memory store + fixture cloud data): the full `correlation_run` produces one persisted toxic combination; the identity `HAS_ACCESS_TO`-expansion logic is exercised with a real fixture `IdentityListing` (an admin-equivalent principal) + a fixture public-PII bucket. Proves orchestration + the IAM-derived edge + correlation + persistence-logic — without a live DB.
2. **Gated Postgres integration test** (`NEXUS_LIVE_POSTGRES=1`, real Postgres + fixture cloud data): the SAME flow against a freshly-migrated Postgres DB; asserts the `TOXIC_COMBINATION` node + 2005 finding are persisted and readable, and (via the existing RLS machinery) tenant-scoped.
3. **Negative/inertness:** with no over-permissioned principal (or a private bucket) → no toxic combination, no crash.

**CI-vs-Postgres honesty (stated, not hidden):** the in-memory CI store (SQLite) does NOT enforce RLS — it proves _logical_ tenant isolation via WHERE clauses; DB-level RLS is proven only by the gated Postgres test (and the prior slice's 40 adversarial tenant tests cover the detector's isolation).

## Cloud-input honesty

Cloud data (`IdentityListing`, S3 inventory) is injected as **fixtures**, via the agents' charter-tool registry (mock the `aws_iam_list_identities` / inventory tools — standard practice, e.g. D.1 vulnerability tests). The `HAS_ACCESS_TO` and all graph writes are produced by **real agent code** from that input — not supplied. Live cloud _reading_ is an orthogonal, already-gated axis (`NEXUS_LIVE_*` per agent), out of scope here.

## Honest scope / deferred

- **HAS_ACCESS_TO is admin-grade only** (over-perm → all tenant resources). Fine-grained non-admin access + the live `SimulatePrincipalPolicy` simulator → a later depth slice.
- **Auto-driven continuous loop** (cron/heartbeat) — still operator-initiated; the orchestrator is invoked, not scheduled.
- **Supervisor `del semantic_store` placeholder cleanup** — noted follow-up.
- **Agents beyond data-security/identity/D.7** in this orchestration; **live cloud reads**; **cloud-posture's `is_public` stamp** (detector keys off `EXPOSES_DATA`, so not needed).

## Constraints (carried)

- Additive where possible; identity's `HAS_ACCESS_TO` write is gated on `semantic_store is not None` (consistent with `record_listing`) → offline default unchanged.
- Typed vocabulary (`NodeCategory`/`EdgeType`); tenant-scoped (`customer_id`); read/write separation (`kg_query` read-only).
- Real code only — no supplied grants, no parallel fake path.
