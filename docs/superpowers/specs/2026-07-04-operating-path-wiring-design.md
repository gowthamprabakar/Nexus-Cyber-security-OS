# Operating-Path Wiring — Design

**Date:** 2026-07-04
**Branch:** `feat/operating-path-wiring`
**Status:** approved (operator: all 4 phases; in-memory + real-Postgres proof)

## The problem (grounded by audit)

An evidence-traced audit found: **0 of ~26 attack-path detectors fire in a running system today.** The detector _logic_ is sound — CI drives it hard and ~11 detectors are correct end-to-end against planted graphs — but nothing joins the halves into a pipeline:

1. **No process runs an agent `run()` with a _persistent_ store.** Every spine-writer is gated `if semantic_store is not None`; the default is `None`, and CLIs pass `None` or an ephemeral in-memory store destroyed at exit. The one orchestrator that threads a shared store (`nexus_runtime/correlation.py::correlation_run`) has zero non-test callers, runs only 3 of the ~10 spine agents, and **stops before the ranker**.
2. **The detector surface has no production trigger.** `AttackPathRanker.find_all()` is reachable only from a manual `nexus attack-paths` CLI.
3. **The continuous loop and supervisor dispatch are inert** (empty scheduler registry; the supervisor's invoker logs-and-no-ops).
4. **~12 spine-writers are fully dormant** (no `run()` caller at all): cloud-posture's entire ECS/EC2 topology, k8s-posture privileged/reachability, identity `OWNS`, vulnerability SBOM, threat-intel IOC nodes, the multi-cloud KMS/SQL/VM trio.

The two halves already exist and were never connected:

- `nexus_runtime/correlation.py::correlation_run` runs 3 agents into **one shared store** (but stops before the ranker).
- `meta_harness/scan.py::analyze(store, tenant)` runs `correlate_all` + `AttackPathRanker.find_all` + candidates on **any populated store**.

**Goal:** one pipeline (and then one loop) that runs the fleet's spine-writing agents into a single persistent graph, correlates, ranks, and emits the top-N attack paths — so the detectors fire in a real pipeline, not only in CI.

## The honest ceiling (no lipstick)

"Everything wired" means: **every detector whose data source is available fires in the real pipeline**, proven end-to-end against fixture feeds **and a real Postgres substrate** ("Done = watched it work"). It does **not** mean all 26 fire against a live cloud account on day one:

- **Live cloud stays `NEXUS_LIVE_*`-gated.** The pipeline proves against fixture feeds + real Postgres; pointing it at a live account is the operator's gated step. Every agent's `run()` already takes both a feed/injectable source (offline) and live params (gated) — the pipeline is source-agnostic.
- **The multi-cloud KMS/SQL/VM trio stays dark.** `find_exposed_kms_key` / `find_exposed_database` / `find_kms_key_access` on Azure/GCP have no honest source — the multi-cloud-posture CIS rule engine is dead code (Track B's deferred fork). These are explicitly listed as blocked, not silently skipped.
- **Security constraints hold.** Readers/classifiers return label/hashed only, never plaintext — the sole plaintext exception is the AWS access key ID (`AKIA`/`ASIA`); non-AWS credential convergence uses `secret_fingerprint` (`secretfp:` sha256). The stored-secret env extraction (below) honors this: it detects `AKIA`/`ASIA` in cleartext and fingerprints everything else.

The cycle ends with an explicit per-detector table: **LIVE-in-pipeline** vs **still-blocked-by-source**.

## Architecture

```
feeds / live-gated sources
        │
        ▼
   scan_run(session_factory, tenant, sources)          ← nexus_runtime/scan_pipeline.py (NEW)
        │   run each spine agent's run(…, semantic_store=store) in dependency order,
        │   each feeder wrapped try/except → per-feeder outcome (failure degrades coverage, never aborts)
        ▼
   ONE shared SemanticStore(session_factory)            ← persistent (Postgres) or in-memory
        │
        ▼
   scan.analyze(store, tenant)                          ← EXISTING: correlate_all + AttackPathRanker.find_all + candidates
        │
        ▼
   ScanResult(confirmed, candidates) + per-feeder outcomes
        │
        ├──▶ nexus scan CLI                             ← renders the ranked report card
        └──▶ ContinuousDriver tick                      ← scheduled cadence calls scan_run
```

**Feeder dependency order** (load-bearing — later feeders read earlier writes; `correlate_all` bridges need both endpoints):
data-security → cloud-posture → identity → vulnerability → k8s-posture → network-threat → threat-intel → runtime-threat → aispm → appsec → `analyze`.

## Components

### 1. `scan_run` — the pipeline (NEW `nexus_runtime/scan_pipeline.py`)

**Responsibility:** run every spine agent's `run()` into one shared store, then `analyze`.
**Interface:** `async def scan_run(*, session_factory, tenant, sources: ScanSources, workspace_root) -> ScanRunResult` where `ScanRunResult` carries `confirmed`, `candidates`, and `feeders: list[FeederOutcome]` (agent, ok/failed, error). `ScanSources` is a per-agent bundle of feed paths / injectable readers / live params — fixtures in tests, live-gated in production. Each feeder is wrapped in try/except: a failure is recorded and logged; the run proceeds to `analyze` on the partial graph (a missing feeder degrades coverage, surfaced in the output — never a silent gap, never an aborted scan).
`correlation_run` stays as-is (its D.7-specific tests use it); `scan_run` is the general superset.

### 2. `nexus scan` CLI (`meta_harness/cli.py`)

**Responsibility:** the real entry point. `@main.command("scan")` sibling to `attack-paths` (cli.py:507): `--customer-id`, `--dsn` (envvar `NEXUS_MEMORY_DSN`), feed options, `--json`. Builds `session_factory` via `build_session_factory(dsn)`, calls `scan_run`, renders the ranked report card (`render_report`/`render_candidates`) plus a one-line-per-feeder coverage summary (which feeders ran, which failed).

### 3. Dormant-writer wiring (per-agent `run()` calls)

Each closes a gap the audit named; the source is already read by `run()` unless noted:

- **vulnerability** (`vulnerability/agent.py:243` block): add `record_sbom_packages(image_ref, [(PkgName, VulnerabilityID, Severity) …])` from `trivy_results.raw_findings`. → lights `find_sbom_vulnerable_workload` + `CONTAINS_PACKAGE`.
- **identity** (`identity/agent.py:234` block): add `record_credential_ownership(_credential_grants(listing))` — `listing` in scope, helper already defined at :550. → lights `OWNS`/`OWNED_BY` (leaked-cred detector + `link_ip_ownership` is unaffected; this feeds `find_leaked_credential_to_data`).
- **threat-intel** (`_persist_to_semantic_store`, agent.py:379): iterate the IOC index (built :220) → `upsert_ioc(entity)`. → lights IOC nodes for `link_threat_indicators`.
- **k8s-posture** (`agent.py:190`): **relax the write guard** — currently `if semantic_store is not None and (kubeconfig is not None or in_cluster)` writes nothing on offline feeds. Extend so feed-driven inventory also writes; add `record_privileged_workloads` + `record_pod_reachability` after `record_inventory` (:198). → lights `USES_SERVICE_ACCOUNT`, `privileged`, `POD_CAN_REACH`.
- **cloud-posture** (`agent.py` — the big one): call `read_ec2_workloads` + `read_ecs_workloads` in `run()` and write `record_ec2_workloads` / `record_workloads` (EC2/ECS topology: `is_public`, `RUNS_IMAGE`, `role_arn`, `private_ips`, `iac_artifact`). → lights the internet-exposed-vulnerable-workload detectors **and both `correlate_all` bridges** (`link_ip_ownership` needs EC2 `private_ips`; `link_deployed_via` needs EC2 `iac_artifact`).
- **cloud-posture stored-secret** (reader extension): extend the ECS task-def reader to surface `containerDefinitions[].environment[].value` on `EcsWorkload`, pass to `stored_secret_grants` (detects `AKIA`/`ASIA`, fingerprints the rest), write `record_stored_secrets`. → lights `find_stored_secret_to_data` (the C-1 detector).

### 4. Continuous loop (`nexus_runtime/continuous.py` + supervisor)

**Responsibility:** run `scan_run` on a cadence instead of only on a manual command.

- A `ScanScheduler` implementing `SchedulerProtocol` (`due(now)` → tenants due by cadence; `mark_ran(tenant, at)`).
- `driver.register("scan", ScanScheduler(...))` so `due_runs()` is non-empty.
- A real invoker (replacing `make_logging_invoker` for the scan path): given `(agent_id="scan", tenant)`, build the contract and call `scan_run`. The existing `tick(now, dispatch=…)` → `dispatch_parallel` bridge carries it.
- `ContinuousMetrics` (`ticks`, `due_runs_dispatched`) increments once the tick fires real work.

## Data flow

Feeds (or live-gated sources) → each agent `run()` writes its spine nodes/edges into the shared store → `correlate_all` adds the four bridge edges (`OWNED_BY`, `MATCHES_INDICATOR`, `RUNS_IMAGE`-runtime, `DEPLOYED_VIA`) → `AttackPathRanker.find_all` produces confirmed named paths → `find_candidate_paths` produces the generic tier → expected-loss ranking → report card.

## Error handling

- **Feeder failure:** try/except per feeder; log + record in `FeederOutcome`; proceed to `analyze` on the partial graph. Coverage degradation is surfaced in the CLI/loop output — never silent, never a hard abort. `ponytail:` no retry/circuit-breaker until a real failure rate demands it.
- **Empty graph / no paths:** `analyze` returns empty tiers; the CLI prints "no attack paths found (feeders that ran: …)" so an empty result is distinguishable from a broken run.
- **Store/migration failure (Postgres):** surfaces from `build_session_factory`; the CLI reports it plainly (no partial-write masking).

## Testing

- **Per-writer unit tests:** each dormant-writer wiring (Components 3) gets a test that drives the agent's `run()` with a fixture feed and asserts the new nodes/edges land (k8s: asserts the relaxed guard now writes on feeds).
- **In-memory e2e (every PR):** fixtures for ≥3 domains → `scan_run` → assert a ranked top-N attack path comes out of **real agent `run()`s** (not planted nodes), spanning a cross-domain bridge (e.g. runtime→image or endpoint→IOC) to prove `correlate_all` fired in-pipeline.
- **Real-Postgres gate (`NEXUS_LIVE_POSTGRES=1`):** the same e2e against real Postgres via `build_session_factory(dsn, migrate=True)`, reusing the `test_correlation_live_postgres.py` skip-gate + DB-recreate fixture. The honest substrate proof.
- **Continuous e2e:** register `ScanScheduler`, advance the tick, assert `scan_run` fired for a due tenant and `ContinuousMetrics.due_runs_dispatched` incremented.

## Phases / task groups

1. **Keystone:** `scan_run` + `nexus scan` CLI + in-memory e2e + real-Postgres gate.
2. **Dormant writers:** vulnerability SBOM, identity OWNS, threat-intel IOC, k8s guard+privileged/reachability, cloud-posture EC2/ECS topology, cloud-posture stored-secret reader extension — each with its unit test; extend the e2e assertions as each detector lights up.
3. **Continuous:** `ScanScheduler` + real invoker + registration + continuous e2e.
4. **Honest close:** the per-detector LIVE-vs-blocked table; whole-branch adversarial review.

## Out of scope (explicit)

- Reviving the multi-cloud KMS/SQL/VM source (dead rule engine — Track B fork; operator decision).
- Live-cloud emission (stays `NEXUS_LIVE_*`-gated; operator's step).
- OCSF emission of the ranked paths (separate deferred slice).
- Any new datastore (reuses the existing SemanticStore/Postgres substrate).
