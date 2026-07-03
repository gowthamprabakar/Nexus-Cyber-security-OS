# Operating-Path Wiring Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Join the two existing halves — the spine-writing agent `run()`s and the `analyze` ranker — into one pipeline (`scan_run`) with a CLI entry point and a continuous loop, so the attack-path detectors fire against a real persistent graph, not only in CI.

**Architecture:** A new `scan_run` in `nexus_runtime/scan_pipeline.py` runs each spine agent's `run(…, semantic_store=store)` into ONE shared `SemanticStore(session_factory)` in dependency order (each feeder try/except → a `FeederOutcome`, failure degrades coverage but never aborts), then calls the existing `meta_harness.scan.analyze` (`correlate_all` + `AttackPathRanker.find_all` + candidates). A `nexus scan` CLI command and a `ScanScheduler`-driven `ContinuousDriver` tick both call `scan_run`. Six dormant writers get wired into their agents' `run()` so their detectors light up.

**Tech Stack:** Python 3.12, asyncio, click (CLI), SQLAlchemy async + Alembic (SemanticStore over Postgres/aiosqlite), pytest + pytest-asyncio, `charter.memory` (SemanticStore, `build_session_factory`), `fleet_testkit` (`in_memory_semantic_store`, `drive_*` helpers).

## Global Constraints

- **Security — evidence discipline:** readers/classifiers return label/hashed only, never plaintext. The SOLE plaintext exception is the AWS access key ID (`AKIA`/`ASIA`). Non-AWS credential convergence uses `secret_fingerprint` = `secretfp:` + sha256. The stored-secret env extraction (Task 10) detects `AKIA`/`ASIA` in clear and fingerprints everything else — never store other env values in plaintext.
- **Live cloud stays gated:** the pipeline is source-agnostic; offline it runs on feeds/injectable readers, live only under `NEXUS_LIVE_*` env gating (operator step). No task points at a live account.
- **No new datastore:** reuse the existing `SemanticStore` / Postgres substrate.
- **Multi-cloud KMS/SQL/VM stays blocked** (dead rule engine, Track B fork) — out of scope; list it in the Task 15 table, do not wire it.
- **Feeder failure degrades coverage, never aborts:** every feeder call in `scan_run` is wrapped try/except → `FeederOutcome(agent, ok, error)`; `analyze` always runs on the partial graph.
- **Husky clean:** never `--no-verify`. Commit subjects lowercase, ≤100 chars; body lines ≤100 chars. `ruff check` + `ruff format` + whole-repo `mypy` run in pre-commit when Python is staged.
- **Feeder dependency order (load-bearing):** data-security → cloud-posture → identity → vulnerability → k8s-posture → network-threat → threat-intel → runtime-threat → aispm → appsec → `analyze`.

---

## File Structure

- **Create** `packages/runtime/src/nexus_runtime/scan_pipeline.py` — `scan_run`, `ScanSources`, `ScanRunResult`, `FeederOutcome`. The full-fleet pipeline (superset of `correlation_run`, which stays as-is).
- **Create** `packages/runtime/src/nexus_runtime/scan_scheduler.py` — `ScanScheduler` (SchedulerProtocol) + `run_due_scans` continuous runner.
- **Modify** `packages/agents/meta-harness/src/meta_harness/cli.py` — add `@main.command("scan")`.
- **Modify** `packages/agents/vulnerability/src/vulnerability/agent.py` — `record_sbom_packages` call.
- **Modify** `packages/agents/identity/src/identity/agent.py` — `record_credential_ownership` call.
- **Modify** `packages/agents/threat-intel/src/threat_intel/agent.py` — `upsert_ioc` in `_persist_to_semantic_store`.
- **Modify** `packages/agents/k8s-posture/src/k8s_posture/agent.py` — relax write guard + `record_privileged_workloads`/`record_pod_reachability`.
- **Modify** `packages/agents/cloud-posture/src/cloud_posture/agent.py` — injectable workload seam + `record_ec2_workloads`/`record_workloads`.
- **Modify** `packages/agents/cloud-posture/src/cloud_posture/tools/aws_ecs.py` — `EcsWorkload.env_values` + task-def env extraction.
- **Modify** `packages/agents/supervisor/src/supervisor/cli.py` — register `ScanScheduler` in the continuous source.
- **Create** `packages/runtime/tests/test_scan_pipeline.py`, `packages/runtime/tests/integration/test_scan_pipeline_e2e.py`, `packages/runtime/tests/integration/test_scan_pipeline_live_postgres.py`, `packages/runtime/tests/test_scan_scheduler.py` — pipeline + e2e + scheduler tests. Per-agent writer tests go in each agent's existing `tests/` dir.
- **Create** `docs/strategy/operating-path-detector-coverage.md` — the honest LIVE-vs-blocked table (Task 15).

---

## Task 1: `scan_run` pipeline + result types

**Files:**

- Create: `packages/runtime/src/nexus_runtime/scan_pipeline.py`
- Test: `packages/runtime/tests/test_scan_pipeline.py`
- Reference (model to follow): `packages/runtime/src/nexus_runtime/correlation.py` (contract-building + shared-store pattern), `packages/agents/meta-harness/src/meta_harness/scan.py` (`analyze`).

**Interfaces:**

- Consumes: `meta_harness.scan.analyze(store, tenant) -> ScanResult(confirmed, candidates)`; `charter.memory.SemanticStore(session_factory)`; each agent's `run(...)` (signatures in the reference table below).
- Produces:
  - `ScanSources` — frozen dataclass, all fields default `None`: `ds_inventory_feed: Path | None`, `ds_objects_feed: Path | None`, `identity_listing: object | None`, `vuln_image_refs: tuple[str, ...] | None`, `k8s_kube_bench_feed: Path | None`, `k8s_polaris_feed: Path | None`, `k8s_manifest_dir: Path | None`, `network_vpc_flow_feed: Path | None`, `threat_nvd_snapshot: Path | None`, `threat_kev_snapshot: Path | None`, `runtime_falco_feed: Path | None`, `appsec_scm_connector: object | None`, `cloud_ec2_workloads: tuple | None`, `cloud_ecs_workloads: tuple | None`.
  - `FeederOutcome(agent: str, ok: bool, error: str | None = None)` — frozen dataclass.
  - `ScanRunResult(confirmed: list, candidates: list, feeders: list[FeederOutcome])` — frozen dataclass.
  - `async def scan_run(*, session_factory, tenant: str, sources: ScanSources, workspace_root: Path) -> ScanRunResult`.

**Per-agent `run()` reference (for the feeders):**
| Feeder | import | offline call (kwargs beyond `contract`, `semantic_store=store`) |
|---|---|---|
| data-security | `from data_security.agent import run as data_security_run` | `s3_inventory_feed=sources.ds_inventory_feed, s3_objects_feed=sources.ds_objects_feed` |
| identity | `from identity.agent import run as identity_run` | `iam_listing=sources.identity_listing` |
| vulnerability | `from vulnerability.agent import run as vulnerability_run` | `image_refs=list(sources.vuln_image_refs or ()), enrich=False` |
| k8s-posture | `from k8s_posture.agent import run as k8s_run` | `kube_bench_feed=…, polaris_feed=…, manifest_dir=sources.k8s_manifest_dir` |
| network-threat | `from network_threat.agent import run as network_run` | `vpc_flow_feed=sources.network_vpc_flow_feed` |
| threat-intel | `from threat_intel.agent import run as threat_run` | `nvd_snapshot=…, kev_snapshot=…` |
| runtime-threat | `from runtime_threat.agent import run as runtime_run` | `falco_feed=sources.runtime_falco_feed` |
| appsec | `from appsec.agent import run as appsec_run` | `scm_connector=sources.appsec_scm_connector` |
| cloud-posture | `from cloud_posture.agent import run as cloud_run` | injectable workload params (Task 9): `ec2_workloads=…, ecs_workloads=…` |

A feeder is SKIPPED (no `FeederOutcome`) when its required source field(s) are all `None`. aispm needs injectable readers; omit from the first cut (add later if a fixture reader is available) — do not fabricate.

- [ ] **Step 1: Write the failing test** (`packages/runtime/tests/test_scan_pipeline.py`)

```python
"""scan_run runs the feeders whose sources are present, records per-feeder outcomes,
and always calls analyze on the shared store."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from charter.memory.provisioning import build_session_factory
from nexus_runtime.scan_pipeline import FeederOutcome, ScanRunResult, ScanSources, scan_run

_TENANT = "tenant-scan-pipeline"


@pytest.mark.asyncio
async def test_scan_run_records_feeder_outcomes_and_analyzes(tmp_path: Path) -> None:
    # A minimal data-security inventory feed with one public bucket + a PII object.
    inv = tmp_path / "inv.json"
    inv.write_text(json.dumps([{"name": "b1", "is_public": True, "region": "us-east-1",
                                "account_uid": "111122223333"}]))
    objs = tmp_path / "objs.json"
    objs.write_text(json.dumps({"b1": [{"key": "e.csv", "body_b64": "c3NuOiAxMjMtNDUtNjc4OQo="}]}))

    factory = await build_session_factory("sqlite+aiosqlite:///:memory:")
    sources = ScanSources(ds_inventory_feed=inv, ds_objects_feed=objs)
    result = await scan_run(session_factory=factory, tenant=_TENANT, sources=sources,
                            workspace_root=tmp_path / "ws")

    assert isinstance(result, ScanRunResult)
    ds = next(f for f in result.feeders if f.agent == "data-security")
    assert ds == FeederOutcome(agent="data-security", ok=True, error=None)
    # analyze ran (confirmed/candidates are lists, possibly empty on this minimal graph)
    assert isinstance(result.confirmed, list) and isinstance(result.candidates, list)
```

- [ ] **Step 2: Run to verify it fails** — `pytest packages/runtime/tests/test_scan_pipeline.py -v` → FAIL (`No module named nexus_runtime.scan_pipeline`). Confirm the exact feed-field names data-security's `run` expects by reading `packages/agents/data-security/src/data_security/agent.py:127` before implementing; adjust the fixture JSON shape to match its reader (the shapes above are illustrative).

- [ ] **Step 3: Implement `scan_pipeline.py`.** Model the contract builder on `correlation.py::_contract`. Structure:

```python
from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path
from charter.memory import SemanticStore
from meta_harness.scan import analyze
# ... per-agent run imports (reference table) ...

@dataclass(frozen=True, slots=True)
class ScanSources:
    ds_inventory_feed: Path | None = None
    # ... all fields from the Interfaces block, default None ...

@dataclass(frozen=True, slots=True)
class FeederOutcome:
    agent: str
    ok: bool
    error: str | None = None

@dataclass(frozen=True, slots=True)
class ScanRunResult:
    confirmed: list
    candidates: list
    feeders: list[FeederOutcome]

async def scan_run(*, session_factory, tenant, sources, workspace_root):
    store = SemanticStore(session_factory)
    feeders: list[FeederOutcome] = []
    async def _feed(name, needed, coro_factory):
        if not needed:
            return
        try:
            await coro_factory()
            feeders.append(FeederOutcome(name, True))
        except Exception as exc:  # noqa: BLE001 — a bad feeder degrades coverage, never aborts
            feeders.append(FeederOutcome(name, False, f"{type(exc).__name__}: {exc}"))
    # dependency order (Global Constraints). Example — data-security:
    await _feed("data-security", sources.ds_inventory_feed is not None,
                lambda: data_security_run(_contract(tenant, "data_security", _DS_TOOLS,
                    workspace_root / "data_security", ["findings.json", "report.md"]),
                    s3_inventory_feed=sources.ds_inventory_feed,
                    s3_objects_feed=sources.ds_objects_feed, semantic_store=store))
    # ... one _feed(...) per agent in the reference table, in dependency order ...
    result = await analyze(store, tenant)
    return ScanRunResult(confirmed=result.confirmed, candidates=result.candidates, feeders=feeders)
```

Copy `_contract` + the `_*_TOOLS` permitted-tool lists from `correlation.py` (extend with per-agent tool lists mirroring each agent's test contract helper — grep `permitted_tools` in each agent's `tests/`). Keep aispm out of the first cut.

- [ ] **Step 4: Run to verify it passes** — `pytest packages/runtime/tests/test_scan_pipeline.py -v` → PASS.

- [ ] **Step 5: Commit** — `git add packages/runtime/src/nexus_runtime/scan_pipeline.py packages/runtime/tests/test_scan_pipeline.py && git commit -m "feat(runtime): scan_run — run spine agents into one store, then analyze"`

---

## Task 2: `nexus scan` CLI command

**Files:**

- Modify: `packages/agents/meta-harness/src/meta_harness/cli.py` (add after `attack_paths_cmd`, ~line 555)
- Test: `packages/agents/meta-harness/tests/test_cli_scan.py`

**Interfaces:**

- Consumes: `nexus_runtime.scan_pipeline.scan_run`, `ScanSources`, `ScanRunResult` (Task 1); `meta_harness.attack_path_report.render_report`, `render_candidates`.
- Produces: a `scan` click command (no importable symbol other than the command).

- [ ] **Step 1: Write the failing test** — CliRunner smoke that the command exists and renders `scan_run`'s result. Monkeypatch `scan_run` to a stub so the test needs no DB.

```python
from click.testing import CliRunner
from meta_harness import cli as cli_mod
from nexus_runtime.scan_pipeline import FeederOutcome, ScanRunResult


def test_scan_command_renders_result(monkeypatch, tmp_path):
    async def _fake_scan_run(**kwargs):
        return ScanRunResult(confirmed=[], candidates=[],
                             feeders=[FeederOutcome("data-security", True)])
    monkeypatch.setattr(cli_mod, "_scan_run_impl", _fake_scan_run, raising=False)
    # The command imports scan_run lazily inside _run(); patch at its source too:
    import nexus_runtime.scan_pipeline as sp
    monkeypatch.setattr(sp, "scan_run", _fake_scan_run)

    result = CliRunner().invoke(cli_mod.main, [
        "scan", "--customer-id", "t1",
        "--dsn", "sqlite+aiosqlite:///:memory:",
        "--ds-inventory-feed", str(tmp_path / "inv.json"),
    ])
    assert result.exit_code == 0, result.output
    assert "data-security" in result.output  # feeder coverage line rendered
```

- [ ] **Step 2: Run to verify it fails** — `pytest packages/agents/meta-harness/tests/test_cli_scan.py -v` → FAIL (no `scan` command).

- [ ] **Step 3: Implement the command** — mirror `attack_paths_cmd` (cli.py:507). Add feed options mapping to `ScanSources` fields; build the factory; call `scan_run`; render:

```python
@main.command("scan")
@click.option("--customer-id", required=True, help="Tenant identifier")
@click.option("--dsn", envvar="NEXUS_MEMORY_DSN", required=True,
              help="Postgres/SQLite DSN for the fleet graph (or set NEXUS_MEMORY_DSN)")
@click.option("--ds-inventory-feed", type=click.Path(), default=None)
@click.option("--ds-objects-feed", type=click.Path(), default=None)
# ... one option per ScanSources feed field you support from the CLI ...
@click.option("--limit", default=10, show_default=True)
@click.option("--json", "as_json", is_flag=True)
def scan_cmd(customer_id, dsn, ds_inventory_feed, ds_objects_feed, limit, as_json):
    """Run the fleet's spine agents into the graph, then rank the top attack paths."""
    import asyncio as _asyncio
    from pathlib import Path as _Path
    from charter.memory.provisioning import build_session_factory
    from nexus_runtime.scan_pipeline import ScanSources, scan_run
    from meta_harness.attack_path_report import render_candidates, render_report

    async def _run():
        factory = await build_session_factory(dsn)
        sources = ScanSources(
            ds_inventory_feed=_Path(ds_inventory_feed) if ds_inventory_feed else None,
            ds_objects_feed=_Path(ds_objects_feed) if ds_objects_feed else None,
        )
        res = await scan_run(session_factory=factory, tenant=customer_id, sources=sources,
                             workspace_root=_Path(".nexus-scan"))
        for f in res.feeders:
            click.echo(f"feeder {f.agent}: {'ok' if f.ok else 'FAILED ' + (f.error or '')}")
        click.echo()
        click.echo(render_report(res.confirmed, tenant_id=customer_id, limit=limit))
        click.echo()
        click.echo(render_candidates(res.candidates, tenant_id=customer_id))

    _asyncio.run(_run())
```

Drop the `_scan_run_impl` monkeypatch line from the test if you import `scan_run` directly inside `_run` (patching `nexus_runtime.scan_pipeline.scan_run` is what takes effect). Keep the test green.

- [ ] **Step 4: Run to verify it passes** — `pytest packages/agents/meta-harness/tests/test_cli_scan.py -v` → PASS.

- [ ] **Step 5: Commit** — `git commit -am "feat(cli): nexus scan — run the pipeline and print ranked attack paths"`

---

## Task 3: In-memory operating-path e2e (Phase-1 proof)

**Files:**

- Create: `packages/runtime/tests/integration/test_scan_pipeline_e2e.py`
- Reference: `packages/integration/src/fleet_testkit/tests/test_mixed_cloud_ranking_e2e.py` (fixture-feed + assert-ranked pattern).

**Interfaces:** Consumes `scan_run`, `ScanSources` (Task 1); `fleet_testkit` feed builders.

**Purpose:** prove the operating path end-to-end — real agent `run()`s → shared store → `correlate_all` → ranker → a ranked path. Assert only what the Phase-1 (already-wired) feeders produce: a public-data exposure path (data-security + identity). This is the keystone regression guard; Task 11 extends it once the dormant writers land.

- [ ] **Step 1: Write the failing test**

```python
"""End-to-end: scan_run over real agent run()s yields a ranked public-data attack path."""
from __future__ import annotations
import json
from pathlib import Path
import pytest
from charter.memory.provisioning import build_session_factory
from nexus_runtime.scan_pipeline import ScanSources, scan_run

_TENANT = "tenant-op-e2e"

@pytest.mark.asyncio
async def test_scan_run_yields_ranked_public_data_path(tmp_path: Path) -> None:
    inv = tmp_path / "inv.json"; objs = tmp_path / "objs.json"
    # public bucket + PII object → data-security writes is_public + EXPOSES_DATA;
    # identity's default listing links HAS_ACCESS_TO. (Match the readers' feed shapes.)
    inv.write_text(json.dumps([{"name": "crown", "is_public": True, "region": "us-east-1",
                                "account_uid": "111122223333"}]))
    objs.write_text(json.dumps({"crown": [{"key": "ssn.csv",
                                           "body_b64": "c3NuOiAxMjMtNDUtNjc4OQo="}]}))
    factory = await build_session_factory("sqlite+aiosqlite:///:memory:")
    sources = ScanSources(ds_inventory_feed=inv, ds_objects_feed=objs)
    res = await scan_run(session_factory=factory, tenant=_TENANT, sources=sources,
                         workspace_root=tmp_path / "ws")
    assert all(f.ok for f in res.feeders), [f for f in res.feeders if not f.ok]
    assert res.confirmed, "expected at least one confirmed attack path from real run()s"
    # ranking invariant: expected_loss non-increasing
    losses = [p.expected_loss for p in res.confirmed]
    assert losses == sorted(losses, reverse=True)
```

- [ ] **Step 2: Run to verify it fails** — first from missing feed shapes; read `data_security/agent.py` + `identity/agent.py` to match the exact feed/listing the readers parse. Iterate the fixture until data-security writes `EXPOSES_DATA` and identity links `HAS_ACCESS_TO`. Expected eventual: PASS.

- [ ] **Step 3: Make it pass** — adjust the fixture shapes (no product code change; if a Phase-1 feeder needs a param `scan_run` does not yet pass, add it to `ScanSources` + the feeder). If identity needs an explicit `iam_listing` to link `HAS_ACCESS_TO` to the bucket, construct a minimal `IdentityListing` fixture and pass via `sources.identity_listing`.

- [ ] **Step 4: Run to verify it passes** — `pytest packages/runtime/tests/integration/test_scan_pipeline_e2e.py -v` → PASS.

- [ ] **Step 5: Commit** — `git commit -am "test(runtime): operating-path e2e — scan_run yields a ranked path from real run()s"`

---

## Task 4: Real-Postgres gate

**Files:**

- Create: `packages/runtime/tests/integration/test_scan_pipeline_live_postgres.py`
- Reference (copy skip-gate + DB-recreate fixture verbatim): `packages/runtime/tests/integration/test_correlation_live_postgres.py`.

**Interfaces:** Consumes `scan_run`, `ScanSources`; `charter.memory.provisioning.build_session_factory(dsn, migrate=True)`.

- [ ] **Step 1: Write the test** — copy the `_LIVE`/`pytestmark`/`postgres_dsn` fixture from `test_correlation_live_postgres.py`; run the SAME scenario as Task 3 but against real Postgres:

```python
import os
import pytest
# copy from test_correlation_live_postgres.py:
_LIVE = os.environ.get("NEXUS_LIVE_POSTGRES") == "1"
pytestmark = pytest.mark.skipif(not _LIVE, reason="set NEXUS_LIVE_POSTGRES=1 + reachable Postgres")
# ... copy the postgres_dsn fixture (drops+recreates the DB) ...

@pytest.mark.asyncio
async def test_scan_run_e2e_on_real_postgres(postgres_dsn, tmp_path):
    from charter.memory.provisioning import build_session_factory
    from nexus_runtime.scan_pipeline import ScanSources, scan_run
    factory = await build_session_factory(postgres_dsn, migrate=True)
    # same fixture feeds as Task 3
    # ... build inv/objs ...
    res = await scan_run(session_factory=factory, tenant="tenant-pg-e2e",
                         sources=ScanSources(ds_inventory_feed=inv, ds_objects_feed=objs),
                         workspace_root=tmp_path / "ws")
    assert res.confirmed, "operating path must produce a ranked path on real Postgres"
```

- [ ] **Step 2: Run skipped** — `pytest packages/runtime/tests/integration/test_scan_pipeline_live_postgres.py -v` → SKIPPED (no `NEXUS_LIVE_POSTGRES`). That is the expected CI state.

- [ ] **Step 3: Run live (if Postgres reachable)** — `NEXUS_LIVE_POSTGRES=1 pytest …/test_scan_pipeline_live_postgres.py -v` → PASS. If Postgres is not available in this environment, leave it skip-verified and note in the report that the operator runs the live gate (same posture as the existing live-Postgres tests).

- [ ] **Step 4: Commit** — `git commit -am "test(runtime): real-Postgres gate for the operating-path e2e (NEXUS_LIVE_POSTGRES)"`

---

## Task 5: vulnerability — wire `record_sbom_packages`

**Files:**

- Modify: `packages/agents/vulnerability/src/vulnerability/agent.py` (the `if semantic_store is not None:` block, ~line 243, after `record_scan_results`)
- Test: `packages/agents/vulnerability/tests/test_agent_sbom_kg.py`

**Interfaces:** Consumes `KnowledgeGraphWriter.record_sbom_packages(image_ref: str, packages: Iterable[tuple[str, str, str]])` (already defined, `vulnerability/kg_writer.py:79`). Produces: `CONTAINS_PACKAGE` + `SBOM_PACKAGE` nodes in the graph after a `run()` with `semantic_store`.

- [ ] **Step 1: Write the failing test** — drive `run()` with an image + a fake trivy result carrying `raw_findings`, assert `SBOM_PACKAGE`/`CONTAINS_PACKAGE` land. Read `vulnerability/tests/` for the existing `run()` test harness + the trivy-result fixture shape; reuse it. The assertion queries the store for the `CONTAINS_PACKAGE` edge (use `store` query helpers as the existing kg tests do).

- [ ] **Step 2: Run to verify it fails** — the edge is absent (writer not called). FAIL.

- [ ] **Step 3: Implement** — in the `if semantic_store is not None:` block, after `kg.record_scan_results(trivy_results)`:

```python
for result in trivy_results:
    packages = [(f["PkgName"], f["VulnerabilityID"], f["Severity"]) for f in result.raw_findings]
    if packages:
        await kg.record_sbom_packages(result.image_ref, packages)
```

Read the exact `trivy_results` element attribute names (`image_ref`, `raw_findings`, and the finding keys) at agent.py:243 before writing — match them exactly.

- [ ] **Step 4: Run to verify it passes** — `pytest packages/agents/vulnerability/tests/test_agent_sbom_kg.py -v` → PASS. Then `pytest packages/agents/vulnerability -q` (no regressions).

- [ ] **Step 5: Commit** — `git commit -am "feat(vulnerability): write SBOM CONTAINS_PACKAGE edges in run()"`

---

## Task 6: identity — wire `record_credential_ownership` (OWNS)

**Files:**

- Modify: `packages/agents/identity/src/identity/agent.py` (the `if semantic_store is not None:` block, after ~line 234; `_credential_grants` helper exists at ~:550)
- Test: `packages/agents/identity/tests/test_agent_owns_kg.py`

**Interfaces:** Consumes `KnowledgeGraphWriter.record_credential_ownership(grants: Sequence[tuple[str, str]])` (identity/kg_writer.py:136) and `_credential_grants(listing) -> list[tuple[str, str]]` (agent.py:550). Produces: `OWNS`/`OWNED_BY` edges after `run()` with a listing containing access keys.

- [ ] **Step 1: Write the failing test** — drive `run()` with an `iam_listing` whose user has `access_key_ids`; assert the `IDENTITY --OWNS--> SECRET` edge lands. Reuse the identity `run()` + `IdentityListing` fixture from `identity/tests/test_agent_unit.py`.

- [ ] **Step 2: Run to verify it fails** — edge absent. FAIL.

- [ ] **Step 3: Implement** — in the `if semantic_store is not None:` block:

```python
cred_grants = _credential_grants(listing)
if cred_grants:
    await kg.record_credential_ownership(cred_grants)
```

(`listing` and `kg` are already in scope at that point — verify variable names at agent.py:234.)

- [ ] **Step 4: Run to verify it passes** — `pytest packages/agents/identity/tests/test_agent_owns_kg.py -v` → PASS; then `pytest packages/agents/identity -q`.

- [ ] **Step 5: Commit** — `git commit -am "feat(identity): write credential OWNS/OWNED_BY edges in run()"`

---

## Task 7: threat-intel — persist IOC nodes (`upsert_ioc`)

**Files:**

- Modify: `packages/agents/threat-intel/src/threat_intel/agent.py` (`_persist_to_semantic_store`, ~:379-407; IOC index built ~:220)
- Test: `packages/agents/threat-intel/tests/test_agent_ioc_kg.py`

**Interfaces:** Consumes `KnowledgeGraphWriter.upsert_ioc(ioc: IocEntity)` (threat_intel/kg_writer.py:49). Produces: `ioc` nodes (`external_id = "{type}:{value}"`) after `run()`.

- [ ] **Step 1: Write the failing test** — drive `run()` with `nvd_snapshot`/`kev_snapshot` feeds that yield at least one IP/domain IOC; assert an `ioc` node exists. Reference `drive_threat_intel_iocs` (`fleet_testkit/network_intel.py:51`) for the `IocEntity` shape.

- [ ] **Step 2: Run to verify it fails** — no `ioc` node (only CVE/TTP persisted). FAIL.

- [ ] **Step 3: Implement** — pass the IOC index (built ~:220) into `_persist_to_semantic_store` (or read it there) and loop:

```python
for entity in ioc_index:            # IocEntity objects; confirm the index is iterable of entities
    await writer.upsert_ioc(entity)
```

Read `_persist_to_semantic_store`'s signature + how `ioc_index`/`build_ioc_index` is shaped at :220 — thread the entities in without changing the correlator behavior.

- [ ] **Step 4: Run to verify it passes** — `pytest packages/agents/threat-intel/tests/test_agent_ioc_kg.py -v` → PASS; then `pytest packages/agents/threat-intel -q`.

- [ ] **Step 5: Commit** — `git commit -am "feat(threat-intel): persist IOC nodes in run() for cross-agent correlation"`

---

## Task 8: k8s-posture — feed-driven writes + privileged/reachability

**Files:**

- Modify: `packages/agents/k8s-posture/src/k8s_posture/agent.py` (write guard ~:190; after `record_inventory` ~:198)
- Test: `packages/agents/k8s-posture/tests/test_agent_offline_kg.py`

**Interfaces:** Consumes `KnowledgeGraphWriter.record_inventory(...)`, `record_privileged_workloads(cluster_id, workloads)`, `record_pod_reachability(grants)` (k8s_posture/kg_writer.py:137/178). Produces: `IRSA_MAPPING`/`BINDS`, `privileged`/`USES_SERVICE_ACCOUNT`, `POD_CAN_REACH` after an OFFLINE feed-driven `run()`.

- [ ] **Step 1: Write the failing test** — drive `run()` with `manifest_dir` (or `kube_bench_feed`+`polaris_feed`) containing a privileged pod, `semantic_store=store`, NO `kubeconfig`/`in_cluster`; assert the inventory node AND the `privileged` node land. Today both are absent (guard blocks offline).

- [ ] **Step 2: Run to verify it fails** — FAIL (guard writes nothing offline).

- [ ] **Step 3: Implement** — (a) relax the guard at :190 so offline feeds also write:

```python
if semantic_store is not None:      # was: and (kubeconfig is not None or in_cluster)
    ...
    await kg.record_inventory(inventory)
    privileged = _privileged_workloads(inventory)       # derive from parsed inventory/manifests
    if privileged:
        await kg.record_privileged_workloads(cluster_id, privileged)
    reach = _pod_reachability(inventory)                 # derive reachable pairs
    if reach:
        await kg.record_pod_reachability(reach)
```

Read what `inventory` (from the offline parse) contains — derive `privileged` (pods with `securityContext.privileged`) and reachability from it. If reachability cannot be derived from the offline feed, wire `record_privileged_workloads` only and note `POD_CAN_REACH` stays live-cluster-only (surface honestly, do not fabricate).

- [ ] **Step 4: Run to verify it passes** — `pytest packages/agents/k8s-posture/tests/test_agent_offline_kg.py -v` → PASS; then `pytest packages/agents/k8s-posture -q`.

- [ ] **Step 5: Commit** — `git commit -am "feat(k8s-posture): populate graph from offline feeds + write privileged workloads"`

---

## Task 9: cloud-posture — EC2/ECS topology into `run()`

**Files:**

- Modify: `packages/agents/cloud-posture/src/cloud_posture/agent.py` (`run()` signature + after `_upsert_findings_to_kg`, ~:457)
- Test: `packages/agents/cloud-posture/tests/test_agent_topology_kg.py`

**Interfaces:** Consumes `read_ec2_workloads`/`read_ecs_workloads` (tools/aws_ec2.py:96, aws_ecs.py:78), `KnowledgeGraphWriter.record_ec2_workloads`/`record_workloads` (tools/kg_writer.py:224/101). Produces: `CLOUD_RESOURCE{is_public, private_ips, iac_artifact}` + `RUNS_IMAGE` — the source for `link_ip_ownership` + `link_deployed_via` bridges. **Design: mirror identity's `iam_listing` injectable seam (NEX-004a).** Add optional injectable params `ec2_workloads: Sequence[Ec2Workload] | None = None`, `ecs_workloads: Sequence[EcsWorkload] | None = None` to `run()`; when provided (offline/pipeline), write them directly (bypass live readers); when `None` + live clients present, call the readers.

- [ ] **Step 1: Write the failing test** — call `run()` with `ec2_workloads=[Ec2Workload(...is_public=True, private_ips=[...], iac_artifact=...)]`, `semantic_store=store`; assert the EC2 `CLOUD_RESOURCE` node with `is_public` + `private_ips` lands.

- [ ] **Step 2: Run to verify it fails** — FAIL (`run()` has no such param / writer never called).

- [ ] **Step 3: Implement** — add the injectable params; in the `semantic_store is not None` path:

```python
ec2 = ec2_workloads if ec2_workloads is not None else (read_ec2_workloads(...) if <live clients> else [])
if ec2:
    await kg.record_ec2_workloads(ec2)
ecs = ecs_workloads if ecs_workloads is not None else (read_ecs_workloads(...) if <live clients> else [])
if ecs:
    await kg.record_workloads(ecs)
```

Read `cloud_posture/agent.py::run` to find the KG-writer handle and the live-client availability check; follow the identity injectable-seam pattern exactly. Then wire `scan_run`'s cloud-posture feeder (Task 1 reference row) to pass `sources.cloud_ec2_workloads`/`cloud_ecs_workloads`.

- [ ] **Step 4: Run to verify it passes** — `pytest packages/agents/cloud-posture/tests/test_agent_topology_kg.py -v` → PASS; then `pytest packages/agents/cloud-posture -q`.

- [ ] **Step 5: Commit** — `git commit -am "feat(cloud-posture): write EC2/ECS topology in run() via injectable workload seam"`

---

## Task 10: cloud-posture — stored-secret env extraction

**Files:**

- Modify: `packages/agents/cloud-posture/src/cloud_posture/tools/aws_ecs.py` (`EcsWorkload` + the task-def reader `_task_def_image_and_role`)
- Modify: `packages/agents/cloud-posture/src/cloud_posture/agent.py` (call `stored_secret_grants` → `record_stored_secrets` in the `semantic_store` path)
- Test: `packages/agents/cloud-posture/tests/test_stored_secret_kg.py`

**Interfaces:** Consumes `stored_secret_grants(workloads: Sequence[tuple[str, Sequence[str]]])` (tools/stored_secrets.py:27), `record_stored_secrets` (tools/kg_writer.py:247). Produces: `CLOUD_RESOURCE --STORES_SECRET--> SECRET` after `run()` when an ECS workload's env carries an `AKIA`/`ASIA` key. **Security (Global Constraints): only `AKIA`/`ASIA` are handled in cleartext; `stored_secret_grants` already fingerprints the rest — do not persist other env values as plaintext.**

- [ ] **Step 1: Write the failing test** — an `EcsWorkload` fixture with `env_values=["AKIAIOSFODNN7EXAMPLE"]`; call `run()` with it injected; assert the `STORES_SECRET` edge lands.

- [ ] **Step 2: Run to verify it fails** — FAIL (`EcsWorkload` has no `env_values`; nothing calls `stored_secret_grants`).

- [ ] **Step 3: Implement** — add `env_values: tuple[str, ...] = ()` to `EcsWorkload`; extend the task-def reader to pull `containerDefinitions[].environment[].value` into it. In `run()` (Task 9's ecs path):

```python
grants = stored_secret_grants([(w.service_arn, w.env_values) for w in ecs if w.env_values])
if grants:
    await kg.record_stored_secrets(grants)
```

- [ ] **Step 4: Run to verify it passes** — `pytest packages/agents/cloud-posture/tests/test_stored_secret_kg.py -v` → PASS; then `pytest packages/agents/cloud-posture -q`.

- [ ] **Step 5: Commit** — `git commit -am "feat(cloud-posture): extract ECS env + write STORES_SECRET (AKIA/ASIA clear, rest fingerprinted)"`

---

## Task 11: Full-fleet e2e — dormant-writer detectors fire through `scan_run`

**Files:**

- Modify: `packages/runtime/tests/integration/test_scan_pipeline_e2e.py` (add a second test)

**Interfaces:** Consumes `scan_run`, `ScanSources` (now carrying vuln/cloud/threat sources).

- [ ] **Step 1: Write the failing test** — feed a scenario that exercises a NEWLY-wired detector end-to-end via `scan_run`: e.g. a stored-secret path (cloud-posture ECS workload with an `AKIA` env + identity + data-security) → assert `find_stored_secret_to_data` appears in `res.confirmed` (check `path_type`). Also assert a cross-domain bridge fired (e.g. `link_runtime_images` or `link_ip_ownership`) by feeding both endpoints.

- [ ] **Step 2: Run to verify it fails** — before Tasks 5-10 land it would fail; now (all wired) confirm the detector appears. If a required source is not yet supported by `scan_run`, add it to `ScanSources` + the feeder.

- [ ] **Step 3: Make it pass** — wire the remaining `ScanSources` fields/feeders needed; no detector logic changes.

- [ ] **Step 4: Run to verify it passes** — `pytest packages/runtime/tests/integration/test_scan_pipeline_e2e.py -v` → PASS.

- [ ] **Step 5: Commit** — `git commit -am "test(runtime): full-fleet e2e — dormant-writer detectors fire through scan_run"`

---

## Task 12: `ScanScheduler`

**Files:**

- Create: `packages/runtime/src/nexus_runtime/scan_scheduler.py`
- Test: `packages/runtime/tests/test_scan_scheduler.py`
- Reference: `packages/runtime/src/nexus_runtime/continuous.py` (`SchedulerProtocol`, `due_runs`, `tick`).

**Interfaces:** Produces `ScanScheduler` implementing `SchedulerProtocol`: `due(now) -> list[tenant_id]` (tenants whose last-run + cadence ≤ now), `mark_ran(tenant_id, at)`. Constructor takes `tenants: Sequence[str]`, `cadence: timedelta`.

- [ ] **Step 1: Write the failing test** — read `SchedulerProtocol`'s exact method names in `continuous.py` and match them. Test: a scheduler with cadence 1h and one tenant returns it due at t0, not due at t0+30m after `mark_ran`, due again at t0+61m.

- [ ] **Step 2: Run to verify it fails** — FAIL (no module).

- [ ] **Step 3: Implement** — stdlib only; hold `dict[tenant, last_ran]`. `ponytail:` in-memory last-ran map, swap for a persisted store when multi-process scheduling matters.

- [ ] **Step 4: Run to verify it passes** — `pytest packages/runtime/tests/test_scan_scheduler.py -v` → PASS.

- [ ] **Step 5: Commit** — `git commit -am "feat(runtime): ScanScheduler — cadence-based due tenants for the scan loop"`

---

## Task 13: Continuous runner — tick calls `scan_run`

**Files:**

- Modify: `packages/runtime/src/nexus_runtime/scan_scheduler.py` (add `run_due_scans`)
- Test: `packages/runtime/tests/test_scan_scheduler.py` (add a test)
- Reference: `continuous.py::ContinuousDriver.register`/`tick(now, *, dispatch)`.

**Interfaces:** Produces `async def run_due_scans(*, driver, now, session_factory, sources_for, workspace_root) -> list[FeederOutcome-bearing results]` where `sources_for: Callable[[str], ScanSources]` maps a tenant → its sources. It builds a `dispatch(agent_id, tenant)` that calls `scan_run` and passes it to `driver.tick(now, dispatch=dispatch)`.

- [ ] **Step 1: Write the failing test** — register a `ScanScheduler` with one due tenant on a `ContinuousDriver`; call `run_due_scans`; assert `scan_run` ran for that tenant (spy via a `sources_for` that records the call, or assert the graph got written). Assert the driver marked it ran (next `due` excludes it).

- [ ] **Step 2: Run to verify it fails** — FAIL (`run_due_scans` missing).

- [ ] **Step 3: Implement** — the `dispatch` closure calls `scan_run(session_factory=…, tenant=tenant, sources=sources_for(tenant), workspace_root=…)`; rely on `tick` marking ran on success (read `tick`'s contract).

- [ ] **Step 4: Run to verify it passes** — `pytest packages/runtime/tests/test_scan_scheduler.py -v` → PASS.

- [ ] **Step 5: Commit** — `git commit -am "feat(runtime): run_due_scans — continuous tick drives scan_run per due tenant"`

---

## Task 14: Supervisor activation — register `ScanScheduler`

**Files:**

- Modify: `packages/agents/supervisor/src/supervisor/cli.py` (~:242-259, `_resolve_continuous_source` / where `ContinuousDriver()` is constructed)
- Test: `packages/agents/supervisor/tests/test_cli_continuous_scan.py`
- Reference: the existing `ContinuousTriggerSource(ContinuousDriver())` wiring + `continuous_metrics.py`.

**Interfaces:** Consumes `ScanScheduler`, `run_due_scans` (Tasks 12-13). Registers a `ScanScheduler` on the driver so `due_runs()` is non-empty when scan is enabled (behind an explicit opt-in flag/env so it stays OFF by default — mirror the existing "wire + OFF" posture).

- [ ] **Step 1: Write the failing test** — with the scan opt-in enabled, assert the driver the supervisor builds has a registered `"scan"` scheduler and a tick produces a due run + increments `ContinuousMetrics.due_runs_dispatched`. Read the existing continuous test for the harness.

- [ ] **Step 2: Run to verify it fails** — FAIL (empty driver).

- [ ] **Step 3: Implement** — register `ScanScheduler` (tenants + cadence from config/env) when the opt-in is set; default OFF (empty driver, unchanged behavior). Keep the log-and-no-op default path for non-scan agents.

- [ ] **Step 4: Run to verify it passes** — `pytest packages/agents/supervisor/tests/test_cli_continuous_scan.py -v` → PASS; then `pytest packages/agents/supervisor -q`.

- [ ] **Step 5: Commit** — `git commit -am "feat(supervisor): register ScanScheduler in the continuous source (opt-in, default OFF)"`

---

## Task 15: Honest detector-coverage table

**Files:**

- Create: `docs/strategy/operating-path-detector-coverage.md`

**Interfaces:** none (documentation, verified against the wired writers).

- [ ] **Step 1: Enumerate** — from `AttackPathRanker.find_all` (`attack_paths.py`), list every `find_*` detector. For each, mark **LIVE-in-pipeline** (all its spine legs are now written by a feeder in `scan_run`), **live-cloud-gated** (fires on feeds; live source is `NEXUS_LIVE_*`), or **BLOCKED** (no honest source — the multi-cloud KMS/SQL/VM trio) with the blocking leg named.

- [ ] **Step 2: Write the table** — one row per detector: detector | verdict | spine legs | which feeder writes each | blocker if any. State the bottom line: N LIVE-in-pipeline / M live-gated / 3 blocked.

- [ ] **Step 3: Cross-check** — grep each detector's required edge types against the Task 5-10 writers to confirm the verdict. No detector claimed LIVE without a feeder writing every leg.

- [ ] **Step 4: Commit** — `git commit -am "docs(operating-path): honest per-detector LIVE-vs-blocked coverage table"`

---

## Self-Review (against the spec)

**Spec coverage:** scan_run (T1), CLI (T2), in-memory + Postgres proof (T3/T4), all six dormant writers — vuln SBOM (T5), identity OWNS (T6), threat-intel IOC (T7), k8s guard+privileged (T8), cloud-posture topology (T9), stored-secret (T10) — full-fleet e2e (T11), continuous loop scheduler+runner+activation (T12/13/14), honest ceiling table (T15). Every spec section maps to a task. ✓

**Placeholder scan:** the bigger tasks (T1, T9, T13, T14) instruct the implementer to read the exact seam file before writing — deliberate (the mapping gives file:lines; exact variable names must be read at the seam), not a "TODO." All test code is concrete. No "handle edge cases" hand-waves.

**Type consistency:** `ScanSources`/`FeederOutcome`/`ScanRunResult`/`scan_run` names identical across T1, T2, T3, T4, T11, T13. `record_sbom_packages`/`record_credential_ownership`/`upsert_ioc`/`record_privileged_workloads`/`record_ec2_workloads`/`record_workloads`/`record_stored_secrets`/`stored_secret_grants` match the mapping's kg_writer signatures. `EcsWorkload.env_values` defined in T10, consumed in T10. ✓

**Known soft spots the implementer must resolve at the seam (flagged, not hidden):** exact feed JSON shapes (T1/T3 — read each reader), cloud-posture live-client availability check (T9), k8s reachability derivability from offline feeds (T8 — wire privileged only if reachability can't be derived, surface honestly), supervisor continuous wiring exact seam (T14).
