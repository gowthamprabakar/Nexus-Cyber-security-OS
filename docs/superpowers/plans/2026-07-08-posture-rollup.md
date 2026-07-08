# Posture Rollup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a read-only "posture rollup" producer that aggregates post-scan graph data (ranked attack paths + node-category counts) into board data — a highlighted coverage metric, severity distribution, per-domain scorecards (= heatmap), path-type counts, an exposure funnel, inventory counts, and cross-scan trend snapshots — emitted as `posture.json` + a CLI markdown section.

**Architecture:** One new module `meta_harness/posture.py` (pure `compute` + render + persistence helpers), hooked non-fatally into `scan_run` after `analyze()`, plus a thin CLI render. No new collection, no OCSF, no graph node; trends use the existing episodic-memory table. Everything reads via `SemanticStore.list_entities_by_type` + the already-ranked `AttackPath`s.

**Tech Stack:** Python 3.12, dataclasses, SQLAlchemy async (aiosqlite in tests), `uv`, pytest, mypy. Packages: `meta-harness` (new module + tests), `runtime` (scan hook + integration test), `charter.memory` (read-only use of `SemanticStore` / `EpisodicStore`).

## Global Constraints

- **Read-only & pure compute.** `PostureRollup.compute` performs no writes; persistence (`posture.json`, snapshot) is separate and explicit.
- **Never fail the scan.** The scan-pipeline hook is best-effort: any rollup exception is logged and swallowed; the scan's authoritative paths/OCSF output is unchanged.
- **Tenant-scoped by construction.** `PostureRollup(store, tenant)` pins the tenant once (mirrors `KgQuery`); no per-call tenant.
- **Categorical / counts only — no plaintext.** `posture.json` and snapshots contain counts, ids, path_types, and percentages only. Never resource contents, secrets, or PII.
- **Coverage rendered first.** `render_posture_summary` prints the coverage line above severity/domains/funnel.
- **Divide-by-zero guarded.** Every percentage returns `0` when its denominator is `0`.
- **CI parity:** `uv run mypy` (NO path args) and `uv run pytest` must pass. Husky stays clean — never `--no-verify`. Commit subjects lowercase, ≤100 chars; body lines ≤100.
- **No new dependencies. No OCSF export, no graph POSTURE node (v1).**

---

## File Structure

- **Create** `packages/agents/meta-harness/src/meta_harness/posture.py` — the whole producer: models, constants, `bucket_of`, pure aggregations, `PostureRollup.compute`, `write_posture_json`, `render_posture_summary`, `emit_posture_snapshot`, `posture_trend`.
- **Create** `packages/agents/meta-harness/tests/test_posture.py` — all unit tests.
- **Modify** `packages/runtime/src/nexus_runtime/scan_pipeline.py` — add `ScanRunResult.posture`; best-effort hook after `analyze()`.
- **Create** `packages/runtime/tests/test_posture_pipeline.py` — integration: `posture.json` written, `res.posture` populated, non-fatal on failure.
- **Modify** `packages/agents/meta-harness/src/meta_harness/cli.py` — render `res.posture` in the `scan` subcommand (text + json branches).

## Verified interfaces (code against these exactly)

```python
# meta_harness/attack_paths.py:76 — construct directly in tests
@dataclass(frozen=True, slots=True)
class AttackPath:
    path_type: str; severity: int; title: str; entities: tuple[str, ...]
    evidence: tuple[str, ...] = (); count: int = 1; sink_id: str = ""
    kev: bool = False; epss: float | None = None
# meta_harness/attack_paths.py — AttackPathRanker(kg: KgQuery); async find_all() -> list[AttackPath] (ranked worst-first)
# meta_harness/kg_query.py — KgQuery(semantic_store, customer_id)
# meta_harness/attack_paths.py — module dict _SEVERITY: dict[str, int]  (29 path_type -> severity)

# charter/memory/semantic.py:389
async def list_entities_by_type(self, *, tenant_id: str, entity_type: str) -> list[EntityRow]
# EntityRow: .entity_id .entity_type .external_id .properties(dict) .tenant_id .created_at
# SemanticStore(session_factory); test-insert: await store.upsert_entity(tenant_id=, entity_type=, external_id=, properties={})

# charter/memory/episodic.py — EpisodicStore(session_factory)
async def append_event(self, *, tenant_id, correlation_id, agent_id, action, payload, embedding=None) -> int
async def query_recent(self, *, tenant_id, limit=100) -> list[EpisodeRow]   # DESC emit order
# EpisodeRow: .action .payload(dict) .emitted_at .correlation_id .agent_id

# nexus_runtime/scan_pipeline.py:335 — async def scan_run(*, session_factory, tenant, sources, workspace_root) -> ScanRunResult
#   ScanRunResult(confirmed, candidates, feeders: list[FeederOutcome], ocsf_findings)
#   FeederOutcome(agent: str, ok: bool, error: str | None)
#   hook site line ~655: store, tenant, workspace_root, feeders in scope
# meta_harness/scan.py:45 — async def analyze(store, tenant_id, *, persist, now) -> ScanResult(confirmed, candidates, ocsf_findings)

# test fixture: from fleet_testkit import in_memory_semantic_store  (async ctx mgr yielding SemanticStore)
```

Run a single test file: `uv run pytest packages/agents/meta-harness/tests/test_posture.py`
Typecheck: `uv run mypy` (no path args)

---

### Task 1: Models, constants, severity bucketing

**Files:**

- Create: `packages/agents/meta-harness/src/meta_harness/posture.py`
- Test: `packages/agents/meta-harness/tests/test_posture.py`

**Interfaces:**

- Produces: the dataclasses `DomainCount, PathTypeCount, ExposureFunnel, Coverage, PostureSummary, TrendPoint`; `bucket_of(severity:int)->str`; constants `DOMAINS, PATH_DOMAIN, DOMAIN_CATEGORIES, FINDING_CATEGORIES, INVENTORY_CATEGORIES, EXPOSURE_PATH_TYPES, EPSS_EXPLOITABLE`.

- [ ] **Step 1: Write the failing tests**

```python
# packages/agents/meta-harness/tests/test_posture.py
from meta_harness.attack_paths import _SEVERITY
from meta_harness import posture as P


def test_bucket_of_boundaries():
    assert P.bucket_of(100) == "critical"
    assert P.bucket_of(90) == "critical"
    assert P.bucket_of(89) == "high"
    assert P.bucket_of(75) == "high"
    assert P.bucket_of(74) == "medium"
    assert P.bucket_of(50) == "medium"
    assert P.bucket_of(49) == "low"
    assert P.bucket_of(0) == "low"


def test_path_domain_is_complete_and_valid():
    # Every live path_type must map to a real domain — no silent "other".
    for path_type in _SEVERITY:
        assert path_type in P.PATH_DOMAIN, f"unmapped path_type: {path_type}"
        assert P.PATH_DOMAIN[path_type] in P.DOMAINS, f"bad domain for {path_type}"


def test_domain_categories_cover_all_domains():
    assert set(P.DOMAIN_CATEGORIES) == set(P.DOMAINS)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest packages/agents/meta-harness/tests/test_posture.py -q`
Expected: FAIL — `ModuleNotFoundError` / `AttributeError: module 'meta_harness.posture' has no attribute 'bucket_of'`.

- [ ] **Step 3: Write the module (models + constants + bucket_of)**

```python
# packages/agents/meta-harness/src/meta_harness/posture.py
"""Posture rollup — read-only aggregation of post-scan graph data into board data.

Pure `compute` + explicit persistence. No writes in compute; no OCSF; no graph node.
See docs/superpowers/specs/2026-07-08-posture-rollup-design.md.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from charter.memory.graph_types import NodeCategory as NC

# ---- severity bucketing (attack-path severity is an int 0-100) -------------
def bucket_of(severity: int) -> str:
    if severity >= 90:
        return "critical"
    if severity >= 75:
        return "high"
    if severity >= 50:
        return "medium"
    return "low"


# ---- domain vocabulary -----------------------------------------------------
DOMAINS: frozenset[str] = frozenset(
    {"vulnerability", "cloud", "identity", "data", "container", "appsec", "threat", "ai", "network"}
)

# path_type -> product domain (completeness enforced by test against _SEVERITY)
PATH_DOMAIN: dict[str, str] = {
    "crown_jewel": "data",
    "leaked_credential": "identity",
    "public_secret": "identity",
    "runtime_exploit_vulnerable": "threat",
    "malicious_destination": "threat",
    "exposed_database": "data",
    "lateral_movement": "network",
    "supply_chain_sbom": "appsec",
    "internet_exposed_vulnerable": "vulnerability",
    "internet_exposed_host_vulnerable": "vulnerability",
    "lateral_reachable": "network",
    "privileged_vulnerable": "vulnerability",
    "rbac_privilege_escalation": "container",
    "public_unencrypted": "data",
    "kms_key_access": "data",
    "escalation_method_to_data": "identity",
    "exposed_kms_key_over_data": "data",
    "exposed_kms_key": "data",
    "external_trust": "identity",
    "exposed_ai_sensitive_data": "ai",
    "privilege_escalation": "identity",
    "resource_based_data": "data",
    "fine_grained_data": "data",
    "iac_misconfig_deployed": "appsec",
    "cicd_compromise": "appsec",
    "stored_secret_to_data": "identity",
    "rbac_escalation_to_cloud_data": "container",
    "serverless_lambda_exposure": "cloud",
    "imds_credential_theft": "identity",
}

# domain -> representative node categories, for coverage ("did this domain produce data?")
DOMAIN_CATEGORIES: dict[str, tuple[str, ...]] = {
    "vulnerability": (NC.CVE_FINDING.value, NC.SBOM_PACKAGE.value, NC.EXPLOIT_AVAILABILITY.value),
    "cloud": (NC.CLOUD_RESOURCE.value, NC.CLOUD_ACCOUNT.value, NC.MISCONFIGURATION_FINDING.value),
    "identity": (NC.IDENTITY.value, NC.POLICY.value, NC.SECRET.value, NC.SECRET_FINDING.value),
    "data": (NC.DATA_CLASSIFICATION.value, NC.KMS_KEY.value),
    "container": (NC.K8S_CLUSTER.value, NC.K8S_OBJECT.value, NC.CONTAINER_IMAGE.value),
    "appsec": (NC.CODE_REPOSITORY.value, NC.SAST_FINDING.value, NC.IAC_ARTIFACT.value, NC.BUILD.value),
    "threat": (NC.THREAT_INDICATOR.value, NC.THREAT_ACTOR.value, NC.PROCESS_EVENT.value),
    "ai": (NC.AI_SERVICE.value, NC.AI_MODEL.value),
    "network": (NC.NETWORK_PATH.value, NC.NETWORK_FLOW_EVENT.value),
}

FINDING_CATEGORIES: tuple[str, ...] = (
    NC.CVE_FINDING.value, NC.MISCONFIGURATION_FINDING.value, NC.SECRET_FINDING.value, NC.SAST_FINDING.value,
)
INVENTORY_CATEGORIES: tuple[str, ...] = (
    NC.CLOUD_RESOURCE.value, NC.IDENTITY.value, NC.DATA_CLASSIFICATION.value, NC.CONTAINER_IMAGE.value,
    NC.K8S_OBJECT.value, NC.CODE_REPOSITORY.value, NC.SBOM_PACKAGE.value, NC.AI_MODEL.value, NC.SAAS_TENANT.value,
)
EXPOSURE_PATH_TYPES: frozenset[str] = frozenset(
    {"internet_exposed_vulnerable", "internet_exposed_host_vulnerable", "supply_chain_sbom"}
)
EPSS_EXPLOITABLE = 0.5


# ---- data model ------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class DomainCount:
    domain: str
    critical: int
    high: int
    medium: int
    low: int
    total: int


@dataclass(frozen=True, slots=True)
class PathTypeCount:
    path_type: str
    count: int
    max_severity: int


@dataclass(frozen=True, slots=True)
class ExposureFunnel:
    exposed: int
    vulnerable: int
    kev: int
    exploitable: int


@dataclass(frozen=True, slots=True)
class Coverage:
    domains_covered: int
    domains_total: int
    domain_pct: int
    collectors_ok: int | None
    collectors_run: int | None
    collector_pct: int | None
    surfaced_findings: int
    total_findings: int
    surfaced_pct: int


@dataclass(frozen=True, slots=True)
class PostureSummary:
    tenant: str
    scan_at: str
    coverage: Coverage
    totals: dict[str, int]
    severity_distribution: dict[str, int]
    by_domain: tuple[DomainCount, ...]
    by_path_type: tuple[PathTypeCount, ...]
    exposure_funnel: ExposureFunnel
    inventory_counts: dict[str, int]
    top_paths: tuple[dict[str, Any], ...]


@dataclass(frozen=True, slots=True)
class TrendPoint:
    at: str
    attack_paths: int
    critical: int
    high: int
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest packages/agents/meta-harness/tests/test_posture.py -q`
Expected: PASS (3 tests). If `test_path_domain_is_complete_and_valid` fails, it names the unmapped `path_type` — add it to `PATH_DOMAIN` with the correct domain.

- [ ] **Step 5: Commit**

```bash
git add packages/agents/meta-harness/src/meta_harness/posture.py packages/agents/meta-harness/tests/test_posture.py
git commit -m "feat(posture): rollup models, domain maps, severity bucketing"
```

---

### Task 2: Path-derived aggregations (pure functions over `list[AttackPath]`)

**Files:**

- Modify: `packages/agents/meta-harness/src/meta_harness/posture.py`
- Test: `packages/agents/meta-harness/tests/test_posture.py`

**Interfaces:**

- Consumes: `AttackPath` (construct directly); Task 1 constants + `DomainCount/PathTypeCount/ExposureFunnel`.
- Produces: `severity_distribution(paths)->dict[str,int]`, `by_path_type(paths)->tuple[PathTypeCount,...]`, `by_domain(paths)->tuple[DomainCount,...]`, `exposure_funnel(paths)->ExposureFunnel`.

- [ ] **Step 1: Write the failing tests**

```python
# append to test_posture.py
from meta_harness.attack_paths import AttackPath


def _p(path_type, severity, *, kev=False, epss=None, entities=("e",)):
    return AttackPath(path_type=path_type, severity=severity, title="t", entities=entities, kev=kev, epss=epss)


def test_severity_distribution_counts_by_bucket():
    paths = [_p("crown_jewel", 95), _p("public_secret", 90), _p("lateral_movement", 82), _p("fine_grained_data", 60)]
    assert P.severity_distribution(paths) == {"critical": 2, "high": 1, "medium": 1, "low": 0}


def test_by_path_type_counts_and_max_severity():
    paths = [_p("crown_jewel", 95), _p("crown_jewel", 80), _p("public_secret", 90)]
    got = {c.path_type: (c.count, c.max_severity) for c in P.by_path_type(paths)}
    assert got == {"crown_jewel": (2, 95), "public_secret": (1, 90)}


def test_by_domain_groups_paths_into_domains():
    paths = [_p("crown_jewel", 95), _p("exposed_database", 84), _p("public_secret", 90)]  # data, data, identity
    rows = {d.domain: d for d in P.by_domain(paths)}
    assert rows["data"].total == 2 and rows["data"].critical == 1 and rows["data"].high == 1
    assert rows["identity"].total == 1 and rows["identity"].critical == 1
    assert "network" not in rows  # domains with no paths are omitted


def test_exposure_funnel():
    paths = [
        _p("internet_exposed_vulnerable", 80, kev=True, epss=0.9),
        _p("internet_exposed_vulnerable", 80, kev=False, epss=0.2),
        _p("internet_exposed_host_vulnerable", 79, kev=False, epss=None),
        _p("crown_jewel", 95),  # not an exposure path — excluded
    ]
    f = P.exposure_funnel(paths)
    assert (f.exposed, f.vulnerable, f.kev, f.exploitable) == (3, 3, 1, 1)
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest packages/agents/meta-harness/tests/test_posture.py -q`
Expected: FAIL — `AttributeError: module 'meta_harness.posture' has no attribute 'severity_distribution'`.

- [ ] **Step 3: Implement the pure aggregations**

```python
# add to posture.py (import AttackPath for typing)
from collections import defaultdict

from meta_harness.attack_paths import AttackPath


def severity_distribution(paths: list[AttackPath]) -> dict[str, int]:
    out = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for p in paths:
        out[bucket_of(p.severity)] += 1
    return out


def by_path_type(paths: list[AttackPath]) -> tuple[PathTypeCount, ...]:
    count: dict[str, int] = defaultdict(int)
    maxsev: dict[str, int] = defaultdict(int)
    for p in paths:
        count[p.path_type] += 1
        maxsev[p.path_type] = max(maxsev[p.path_type], p.severity)
    rows = [PathTypeCount(pt, count[pt], maxsev[pt]) for pt in count]
    return tuple(sorted(rows, key=lambda r: (-r.max_severity, r.path_type)))


def by_domain(paths: list[AttackPath]) -> tuple[DomainCount, ...]:
    buckets: dict[str, dict[str, int]] = defaultdict(lambda: {"critical": 0, "high": 0, "medium": 0, "low": 0})
    for p in paths:
        domain = PATH_DOMAIN.get(p.path_type, "other")
        buckets[domain][bucket_of(p.severity)] += 1
    rows = [
        DomainCount(d, b["critical"], b["high"], b["medium"], b["low"],
                    b["critical"] + b["high"] + b["medium"] + b["low"])
        for d, b in buckets.items()
    ]
    return tuple(sorted(rows, key=lambda r: (-r.total, r.domain)))


def exposure_funnel(paths: list[AttackPath]) -> ExposureFunnel:
    exposure = [p for p in paths if p.path_type in EXPOSURE_PATH_TYPES]
    exposed = len(exposure)
    vulnerable = sum(1 for p in exposure if p.count >= 1)
    kev = sum(1 for p in exposure if p.kev)
    exploitable = sum(1 for p in exposure if p.epss is not None and p.epss > EPSS_EXPLOITABLE)
    return ExposureFunnel(exposed=exposed, vulnerable=vulnerable, kev=kev, exploitable=exploitable)
```

- [ ] **Step 4: Run to verify they pass**

Run: `uv run pytest packages/agents/meta-harness/tests/test_posture.py -q`
Expected: PASS (7 tests total).

- [ ] **Step 5: Commit**

```bash
git add packages/agents/meta-harness/src/meta_harness/posture.py packages/agents/meta-harness/tests/test_posture.py
git commit -m "feat(posture): pure path aggregations (severity, by-type, by-domain, funnel)"
```

---

### Task 3: Store-derived counts + coverage (async, fixture graph)

**Files:**

- Modify: `packages/agents/meta-harness/src/meta_harness/posture.py`
- Test: `packages/agents/meta-harness/tests/test_posture.py`

**Interfaces:**

- Consumes: `SemanticStore.list_entities_by_type`; Task 1 constants + `Coverage`; `FeederOutcome`-like objects (anything with `.ok: bool`).
- Produces: `async count_categories(store, tenant, categories)->dict[str,int]`; `async compute_coverage(store, tenant, paths, feeders, *, category_counts)->Coverage`. (`feeders` typed `Sequence[object] | None` — list is invariant, so `Sequence` accepts `list[FeederOutcome]`; only `.ok` is read.)

- [ ] **Step 1: Write the failing tests**

```python
# append to test_posture.py
import pytest
from charter.memory.graph_types import NodeCategory as NC
from fleet_testkit import in_memory_semantic_store


class _Feeder:
    def __init__(self, ok: bool) -> None:
        self.ok = ok


@pytest.mark.asyncio
async def test_count_categories_counts_per_type():
    async with in_memory_semantic_store() as store:
        await store.upsert_entity(tenant_id="t", entity_type=NC.CVE_FINDING.value, external_id="cve-1", properties={})
        await store.upsert_entity(tenant_id="t", entity_type=NC.CVE_FINDING.value, external_id="cve-2", properties={})
        await store.upsert_entity(tenant_id="t", entity_type=NC.IDENTITY.value, external_id="id-1", properties={})
        counts = await P.count_categories(store, "t", (NC.CVE_FINDING.value, NC.IDENTITY.value, NC.SECRET_FINDING.value))
        assert counts == {NC.CVE_FINDING.value: 2, NC.IDENTITY.value: 1, NC.SECRET_FINDING.value: 0}


@pytest.mark.asyncio
async def test_compute_coverage_domain_collector_surfaced():
    async with in_memory_semantic_store() as store:
        # 1 finding entity that IS on a path (surfaced), 1 that is NOT
        f1 = await store.upsert_entity(tenant_id="t", entity_type=NC.CVE_FINDING.value, external_id="cve-1", properties={})
        await store.upsert_entity(tenant_id="t", entity_type=NC.CVE_FINDING.value, external_id="cve-2", properties={})
        await store.upsert_entity(tenant_id="t", entity_type=NC.IDENTITY.value, external_id="id-1", properties={})
        counts = await P.count_categories(store, "t", P._all_counted())
        paths = [_p("internet_exposed_vulnerable", 80, entities=(f1,))]
        feeders = [_Feeder(True), _Feeder(True), _Feeder(False)]
        cov = await P.compute_coverage(store, "t", paths, feeders, category_counts=counts)
        # domains covered: vulnerability (CVE) + identity (IDENTITY) = 2 of 9
        assert cov.domains_covered == 2 and cov.domains_total == 9 and cov.domain_pct == 22
        assert cov.collectors_ok == 2 and cov.collectors_run == 3 and cov.collector_pct == 67
        assert cov.surfaced_findings == 1 and cov.total_findings == 2 and cov.surfaced_pct == 50


@pytest.mark.asyncio
async def test_compute_coverage_no_feeders_is_none_and_guards_zero():
    async with in_memory_semantic_store() as store:
        counts = await P.count_categories(store, "t", P._all_counted())
        cov = await P.compute_coverage(store, "t", [], None, category_counts=counts)
        assert cov.collectors_ok is None and cov.collector_pct is None
        assert cov.total_findings == 0 and cov.surfaced_pct == 0 and cov.domain_pct == 0
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest packages/agents/meta-harness/tests/test_posture.py -q`
Expected: FAIL — `AttributeError: ... has no attribute 'count_categories'`.

- [ ] **Step 3: Implement the store-derived helpers**

```python
# add to posture.py
from collections.abc import Sequence

from charter.memory.semantic import SemanticStore


def _pct(num: int, den: int) -> int:
    return round(num / den * 100) if den else 0


def _all_counted() -> tuple[str, ...]:
    seen: dict[str, None] = {}
    for c in (*INVENTORY_CATEGORIES, *FINDING_CATEGORIES):
        seen[c] = None
    for cats in DOMAIN_CATEGORIES.values():
        for c in cats:
            seen[c] = None
    return tuple(seen)


async def count_categories(store: SemanticStore, tenant: str, categories: tuple[str, ...]) -> dict[str, int]:
    out: dict[str, int] = {}
    for cat in categories:
        rows = await store.list_entities_by_type(tenant_id=tenant, entity_type=cat)
        out[cat] = len(rows)
    return out


async def compute_coverage(
    store: SemanticStore,
    tenant: str,
    paths: list[AttackPath],
    feeders: Sequence[object] | None,
    *,
    category_counts: dict[str, int],
) -> Coverage:
    # domain coverage — a domain is "covered" if any of its categories has >=1 node
    domains_covered = sum(
        1 for cats in DOMAIN_CATEGORIES.values() if any(category_counts.get(c, 0) > 0 for c in cats)
    )
    domains_total = len(DOMAIN_CATEGORIES)

    # collector coverage — from FeederOutcome.ok (None when no feeder context)
    collectors_ok: int | None = None
    collectors_run: int | None = None
    collector_pct: int | None = None
    if feeders is not None:
        collectors_run = len(feeders)
        collectors_ok = sum(1 for f in feeders if getattr(f, "ok", False))
        collector_pct = _pct(collectors_ok, collectors_run)

    # surfaced ratio — distinct finding entity ids that appear on any path
    total_findings = sum(category_counts.get(c, 0) for c in FINDING_CATEGORIES)
    finding_ids: set[str] = set()
    for cat in FINDING_CATEGORIES:
        for row in await store.list_entities_by_type(tenant_id=tenant, entity_type=cat):
            finding_ids.add(row.entity_id)
    on_paths: set[str] = set()
    for p in paths:
        on_paths.update(p.entities)
    surfaced_findings = len(finding_ids & on_paths)

    return Coverage(
        domains_covered=domains_covered,
        domains_total=domains_total,
        domain_pct=_pct(domains_covered, domains_total),
        collectors_ok=collectors_ok,
        collectors_run=collectors_run,
        collector_pct=collector_pct,
        surfaced_findings=surfaced_findings,
        total_findings=total_findings,
        surfaced_pct=_pct(surfaced_findings, total_findings),
    )
```

- [ ] **Step 4: Run to verify they pass**

Run: `uv run pytest packages/agents/meta-harness/tests/test_posture.py -q`
Expected: PASS (10 tests total).

- [ ] **Step 5: Commit**

```bash
git add packages/agents/meta-harness/src/meta_harness/posture.py packages/agents/meta-harness/tests/test_posture.py
git commit -m "feat(posture): store-derived category counts + coverage metric"
```

---

### Task 4: `PostureRollup.compute` orchestration + JSON + markdown render

**Files:**

- Modify: `packages/agents/meta-harness/src/meta_harness/posture.py`
- Test: `packages/agents/meta-harness/tests/test_posture.py`

**Interfaces:**

- Consumes: Tasks 1–3; `AttackPathRanker`, `KgQuery` (for `paths=None`).
- Produces: `class PostureRollup(store, tenant)` with `async compute(*, now, paths=None, feeders=None)->PostureSummary`; `write_posture_json(summary, workspace_root)->Path`; `render_posture_summary(summary)->str`; `summary_to_dict(summary)->dict`.

- [ ] **Step 1: Write the failing tests**

```python
# append to test_posture.py
import json
from datetime import UTC, datetime


@pytest.mark.asyncio
async def test_compute_full_summary_on_fixture():
    async with in_memory_semantic_store() as store:
        f1 = await store.upsert_entity(tenant_id="t", entity_type=NC.CVE_FINDING.value, external_id="cve-1", properties={})
        await store.upsert_entity(tenant_id="t", entity_type=NC.CLOUD_RESOURCE.value, external_id="arn:x", properties={})
        paths = [_p("crown_jewel", 95, entities=(f1,)), _p("internet_exposed_vulnerable", 80, kev=True, epss=0.9, entities=(f1,))]
        now = datetime(2026, 7, 8, tzinfo=UTC)
        s = await P.PostureRollup(store, "t").compute(now=now, paths=paths, feeders=[_Feeder(True)])
        assert s.tenant == "t" and s.scan_at == now.isoformat()
        assert s.totals["attack_paths"] == 2
        assert s.severity_distribution == {"critical": 1, "high": 1, "medium": 0, "low": 0}
        assert s.exposure_funnel.exposed == 1 and s.exposure_funnel.kev == 1
        assert s.coverage.surfaced_findings == 1 and s.coverage.collectors_ok == 1
        assert s.inventory_counts[NC.CLOUD_RESOURCE.value] == 1


@pytest.mark.asyncio
async def test_compute_empty_graph_is_all_zero():
    async with in_memory_semantic_store() as store:
        s = await P.PostureRollup(store, "t").compute(now=datetime(2026, 7, 8, tzinfo=UTC), paths=[], feeders=[])
        assert s.totals["attack_paths"] == 0
        assert s.severity_distribution == {"critical": 0, "high": 0, "medium": 0, "low": 0}
        assert s.by_domain == () and s.by_path_type == () and s.top_paths == ()
        assert s.coverage.domain_pct == 0 and s.coverage.surfaced_pct == 0


@pytest.mark.asyncio
async def test_write_posture_json_round_trips(tmp_path):
    async with in_memory_semantic_store() as store:
        s = await P.PostureRollup(store, "t").compute(now=datetime(2026, 7, 8, tzinfo=UTC), paths=[], feeders=[])
        path = P.write_posture_json(s, tmp_path)
        assert path == tmp_path / "aggregation" / "posture.json"
        data = json.loads(path.read_text())
        assert data["tenant"] == "t" and "coverage" in data and data["severity_distribution"]["critical"] == 0


def test_render_leads_with_coverage_and_omits_missing_collectors():
    cov = P.Coverage(4, 9, 44, None, None, None, 3, 10, 30)
    s = P.PostureSummary(
        tenant="t", scan_at="2026-07-08T00:00:00+00:00", coverage=cov,
        totals={"attack_paths": 5, "findings": 10, "nodes": 20},
        severity_distribution={"critical": 1, "high": 2, "medium": 1, "low": 1},
        by_domain=(P.DomainCount("data", 1, 0, 0, 0, 1),), by_path_type=(),
        exposure_funnel=P.ExposureFunnel(2, 2, 1, 1), inventory_counts={}, top_paths=(),
    )
    md = P.render_posture_summary(s)
    first_line = md.strip().splitlines()[0]
    assert "Coverage" in first_line and "44%" in first_line
    assert "collector" not in md.lower()  # omitted when None
    assert "data" in md
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest packages/agents/meta-harness/tests/test_posture.py -q`
Expected: FAIL — `AttributeError: ... has no attribute 'PostureRollup'`.

- [ ] **Step 3: Implement compute + json + render**

```python
# add to posture.py
import dataclasses
import json
from pathlib import Path

from meta_harness.kg_query import KgQuery
from meta_harness.attack_paths import AttackPathRanker

_TOP_N = 10


class PostureRollup:
    """Read-only rollup of the post-scan graph into a PostureSummary. Tenant-scoped."""

    def __init__(self, store: SemanticStore, tenant: str) -> None:
        self._store = store
        self._tenant = tenant

    async def compute(
        self,
        *,
        now: datetime,
        paths: list[AttackPath] | None = None,
        feeders: Sequence[object] | None = None,
    ) -> PostureSummary:
        if paths is None:
            paths = await AttackPathRanker(KgQuery(self._store, self._tenant)).find_all()

        counts = await count_categories(self._store, self._tenant, _all_counted())
        coverage = await compute_coverage(
            self._store, self._tenant, paths, feeders, category_counts=counts
        )
        inventory = {c: counts.get(c, 0) for c in INVENTORY_CATEGORIES}
        totals = {
            "attack_paths": len(paths),
            "findings": sum(counts.get(c, 0) for c in FINDING_CATEGORIES),
            "nodes": sum(counts.values()),
        }
        top = tuple(
            {"path_type": p.path_type, "severity": p.severity, "title": p.title, "kev": p.kev, "epss": p.epss}
            for p in paths[:_TOP_N]
        )
        return PostureSummary(
            tenant=self._tenant,
            scan_at=now.isoformat(),
            coverage=coverage,
            totals=totals,
            severity_distribution=severity_distribution(paths),
            by_domain=by_domain(paths),
            by_path_type=by_path_type(paths),
            exposure_funnel=exposure_funnel(paths),
            inventory_counts=inventory,
            top_paths=top,
        )


def summary_to_dict(summary: PostureSummary) -> dict[str, Any]:
    return dataclasses.asdict(summary)


def write_posture_json(summary: PostureSummary, workspace_root: Path) -> Path:
    out_dir = workspace_root / "aggregation"
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "posture.json"
    path.write_text(json.dumps(summary_to_dict(summary), indent=2, sort_keys=True))
    return path


def render_posture_summary(summary: PostureSummary) -> str:
    c = summary.coverage
    parts = [f"**Coverage:** {c.domain_pct}% of domains ({c.domains_covered}/{c.domains_total})"]
    if c.collector_pct is not None:
        parts.append(f"{c.collector_pct}% of collectors ({c.collectors_ok}/{c.collectors_run})")
    parts.append(f"{c.surfaced_pct}% of findings surfaced ({c.surfaced_findings}/{c.total_findings})")
    lines = [" · ".join(parts), ""]
    d = summary.severity_distribution
    lines.append(
        f"**Attack paths:** {summary.totals['attack_paths']} "
        f"(critical {d['critical']} · high {d['high']} · medium {d['medium']} · low {d['low']})"
    )
    lines.append("")
    lines.append("**By domain:**")
    for row in summary.by_domain:
        lines.append(f"- {row.domain}: {row.total} (C{row.critical} H{row.high} M{row.medium} L{row.low})")
    f = summary.exposure_funnel
    lines.append("")
    lines.append(f"**Exposure funnel:** {f.exposed} exposed → {f.vulnerable} vulnerable → {f.kev} KEV → {f.exploitable} exploitable")
    return "\n".join(lines)
```

- [ ] **Step 4: Run to verify they pass**

Run: `uv run pytest packages/agents/meta-harness/tests/test_posture.py -q`
Expected: PASS (14 tests total).

- [ ] **Step 5: Typecheck + commit**

```bash
uv run mypy
git add packages/agents/meta-harness/src/meta_harness/posture.py packages/agents/meta-harness/tests/test_posture.py
git commit -m "feat(posture): compute orchestration + posture.json + markdown render"
```

Expected: mypy clean.

---

### Task 5: Cross-scan trends (emit snapshot + read)

**Files:**

- Modify: `packages/agents/meta-harness/src/meta_harness/posture.py`
- Test: `packages/agents/meta-harness/tests/test_posture.py`

**Interfaces:**

- Consumes: `EpisodicStore.append_event` / `query_recent`; `PostureSummary`, `TrendPoint`.
- Produces: `async emit_posture_snapshot(episodic, tenant, summary, *, correlation_id)->None`; `async posture_trend(episodic, tenant, *, limit=30)->list[TrendPoint]`. Constant `SNAPSHOT_ACTION = "posture_snapshot"`, `SNAPSHOT_AGENT = "posture-rollup"`.

- [ ] **Step 1: Write the failing tests**

```python
# append to test_posture.py
from charter.memory.episodic import EpisodicStore
from charter.memory.models import Base
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine


async def _episodic():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    return EpisodicStore(async_sessionmaker(engine, expire_on_commit=False))


def _summary(at, ap, crit, high):
    cov = P.Coverage(0, 9, 0, None, None, None, 0, 0, 0)
    return P.PostureSummary(
        tenant="t", scan_at=at, coverage=cov,
        totals={"attack_paths": ap, "findings": 0, "nodes": 0},
        severity_distribution={"critical": crit, "high": high, "medium": 0, "low": 0},
        by_domain=(), by_path_type=(), exposure_funnel=P.ExposureFunnel(0, 0, 0, 0),
        inventory_counts={}, top_paths=(),
    )


@pytest.mark.asyncio
async def test_trend_returns_snapshots_in_time_order():
    ep = await _episodic()
    await P.emit_posture_snapshot(ep, "t", _summary("2026-07-01T00:00:00+00:00", 3, 1, 1), correlation_id="c1")
    await P.emit_posture_snapshot(ep, "t", _summary("2026-07-08T00:00:00+00:00", 5, 2, 2), correlation_id="c2")
    trend = await P.posture_trend(ep, "t")
    assert [t.attack_paths for t in trend] == [3, 5]  # ascending by emit order
    assert trend[1].critical == 2 and trend[1].high == 2


@pytest.mark.asyncio
async def test_trend_empty_when_no_snapshots():
    ep = await _episodic()
    assert await P.posture_trend(ep, "t") == []
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest packages/agents/meta-harness/tests/test_posture.py -q`
Expected: FAIL — `AttributeError: ... has no attribute 'emit_posture_snapshot'`.

- [ ] **Step 3: Implement emit + read**

```python
# add to posture.py
from charter.memory.episodic import EpisodicStore

SNAPSHOT_ACTION = "posture_snapshot"
SNAPSHOT_AGENT = "posture-rollup"


async def emit_posture_snapshot(
    episodic: EpisodicStore, tenant: str, summary: PostureSummary, *, correlation_id: str
) -> None:
    await episodic.append_event(
        tenant_id=tenant,
        correlation_id=correlation_id,
        agent_id=SNAPSHOT_AGENT,
        action=SNAPSHOT_ACTION,
        payload={
            "at": summary.scan_at,
            "totals": summary.totals,
            "severity_distribution": summary.severity_distribution,
        },
    )


async def posture_trend(episodic: EpisodicStore, tenant: str, *, limit: int = 30) -> list[TrendPoint]:
    # query_recent returns DESC; over-fetch to survive interleaved actions, filter, reverse to ASC.
    rows = await episodic.query_recent(tenant_id=tenant, limit=max(limit * 4, 100))
    snaps = [r for r in rows if r.action == SNAPSHOT_ACTION]
    snaps.reverse()
    points = [
        TrendPoint(
            at=str(r.payload.get("at", "")),
            attack_paths=int(r.payload.get("totals", {}).get("attack_paths", 0)),
            critical=int(r.payload.get("severity_distribution", {}).get("critical", 0)),
            high=int(r.payload.get("severity_distribution", {}).get("high", 0)),
        )
        for r in snaps
    ]
    return points[-limit:]
```

- [ ] **Step 4: Run to verify they pass**

Run: `uv run pytest packages/agents/meta-harness/tests/test_posture.py -q`
Expected: PASS (16 tests total).

- [ ] **Step 5: Commit**

```bash
git add packages/agents/meta-harness/src/meta_harness/posture.py packages/agents/meta-harness/tests/test_posture.py
git commit -m "feat(posture): cross-scan trend snapshots via episodic memory"
```

---

### Task 6: Non-fatal scan-pipeline hook + `ScanRunResult.posture`

**Files:**

- Modify: `packages/runtime/src/nexus_runtime/scan_pipeline.py`
- Test: `packages/runtime/tests/test_posture_pipeline.py`

**Interfaces:**

- Consumes: `PostureRollup`, `write_posture_json`, `emit_posture_snapshot` (from `meta_harness.posture`); `EpisodicStore`.
- Produces: `ScanRunResult.posture: object | None` (a `PostureSummary` or `None`).

- [ ] **Step 1: Write the failing integration tests**

```python
# packages/runtime/tests/test_posture_pipeline.py
"""Posture rollup is wired into scan_run: writes posture.json, populates result, never fatal."""
from __future__ import annotations

import json
from collections.abc import AsyncIterator

import pytest
from nexus_runtime.scan_pipeline import ScanSources, scan_run
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from charter.memory.models import Base


@pytest.fixture
async def session_factory() -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield async_sessionmaker(engine, expire_on_commit=False)
    await engine.dispose()


@pytest.mark.asyncio
async def test_scan_run_writes_posture_json_and_result(session_factory, tmp_path):
    res = await scan_run(
        session_factory=session_factory, tenant="t", sources=ScanSources(), workspace_root=tmp_path / "ws"
    )
    assert res.posture is not None
    posture_file = tmp_path / "ws" / "aggregation" / "posture.json"
    assert posture_file.exists()
    data = json.loads(posture_file.read_text())
    assert data["tenant"] == "t" and "coverage" in data


@pytest.mark.asyncio
async def test_rollup_failure_is_non_fatal(session_factory, tmp_path, monkeypatch):
    # Force the rollup to blow up; the scan must still return.
    import meta_harness.posture as posture_mod

    async def _boom(self, **kwargs):  # noqa: ANN001
        raise RuntimeError("rollup exploded")

    monkeypatch.setattr(posture_mod.PostureRollup, "compute", _boom)
    res = await scan_run(
        session_factory=session_factory, tenant="t", sources=ScanSources(), workspace_root=tmp_path / "ws"
    )
    assert res.posture is None  # rollup failed...
    assert isinstance(res.feeders, list)  # ...but the scan still produced its authoritative output
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest packages/runtime/tests/test_posture_pipeline.py -q`
Expected: FAIL — `AttributeError: 'ScanRunResult' object has no attribute 'posture'`.

- [ ] **Step 3: Add the field to `ScanRunResult`**

In `packages/runtime/src/nexus_runtime/scan_pipeline.py`, in the `ScanRunResult` dataclass (≈ line 277), add the field after `ocsf_findings`:

```python
    ocsf_findings: list[dict[str, Any]] = field(default_factory=list)  # OCSF 2005 Incident Findings
    posture: object | None = None  # meta_harness.posture.PostureSummary | None (best-effort rollup)
```

- [ ] **Step 4: Add the non-fatal hook after `analyze()`**

Find the `analyze()` call (≈ line 655). Capture `now`, then add the rollup block immediately after. Thread `posture` into the `ScanRunResult(...)` constructed at the end of `scan_run`.

```python
# near the top of scan_pipeline.py, with the other imports:
import logging
from meta_harness.posture import PostureRollup, emit_posture_snapshot, write_posture_json
from charter.memory.episodic import EpisodicStore

_log = logging.getLogger(__name__)

# replace the existing analyze() call:
now = datetime.now(UTC)
scan_result = await analyze(store, tenant, persist=True, now=now)

# --- posture rollup (best-effort; a failure must NOT fail the scan) ---
posture = None
try:
    posture = await PostureRollup(store, tenant).compute(
        now=now, paths=scan_result.confirmed, feeders=feeders
    )
    write_posture_json(posture, workspace_root)
    await emit_posture_snapshot(
        EpisodicStore(session_factory), tenant, posture,
        correlation_id=f"scan:{tenant}:{now.isoformat()}",
    )
except Exception:  # noqa: BLE001 — rollup is additive; never break the scan
    _log.warning("posture rollup failed; scan output unaffected", exc_info=True)
    posture = None
```

Then in the `return ScanRunResult(...)` at the end of `scan_run`, add `posture=posture`:

```python
    return ScanRunResult(
        confirmed=[...],
        candidates=[...],
        feeders=feeders,
        ocsf_findings=[...],
        posture=posture,
    )
```

(If `logging`, `datetime`, `UTC` are already imported, do not duplicate them. Verify `datetime.now(UTC)` was the exact prior argument — replace only that inline expression with the captured `now`.)

- [ ] **Step 5: Run to verify they pass**

Run: `uv run pytest packages/runtime/tests/test_posture_pipeline.py -q`
Expected: PASS (2 tests). If the first test's `res.posture` is `None`, read the warning — the rollup raised on the empty-scan graph; fix `compute`/coverage to handle empty inputs (Task 4 covers empty-graph, so this should be green).

- [ ] **Step 6: Full suite + typecheck + commit**

```bash
uv run pytest packages/runtime/tests/test_posture_pipeline.py packages/agents/meta-harness/tests/test_posture.py -q
uv run mypy
git add packages/runtime/src/nexus_runtime/scan_pipeline.py packages/runtime/tests/test_posture_pipeline.py
git commit -m "feat(posture): wire non-fatal rollup into scan_run + ScanRunResult.posture"
```

---

### Task 7: CLI rendering of posture in the `scan` subcommand

**Files:**

- Modify: `packages/agents/meta-harness/src/meta_harness/cli.py`
- Test: `packages/agents/meta-harness/tests/test_cli_scan.py` (extend; mirror its existing setup)

**Interfaces:**

- Consumes: `res.posture` (`ScanRunResult`); `render_posture_summary`, `summary_to_dict` (from `meta_harness.posture`).

- [ ] **Step 1: Add a failing assertion mirroring the existing CLI scan test**

Open `packages/agents/meta-harness/tests/test_cli_scan.py`, copy its existing scan-invocation test, and add an assertion that the text output includes the coverage line:

```python
def test_scan_cli_renders_posture_coverage(...):  # mirror the existing test's fixtures/invocation
    result = runner.invoke(main, ["scan", "--customer-id", "t", "--dsn", dsn])  # match existing args
    assert result.exit_code == 0
    assert "Coverage:" in result.output
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest packages/agents/meta-harness/tests/test_cli_scan.py -q`
Expected: FAIL — `assert "Coverage:" in result.output` (not yet rendered).

- [ ] **Step 3: Wire the render into the `scan` subcommand**

In `cli.py`, add the import near the other `meta_harness` imports inside the scan command (≈ line 588):

```python
    from meta_harness.posture import render_posture_summary, summary_to_dict
```

In the text branch (≈ line 620–625), render posture between the feeder echoes and `render_report`:

```python
        else:
            for f in res.feeders:
                click.echo(f"feeder {f.agent}: {'ok' if f.ok else 'FAILED ' + (f.error or '')}")
            click.echo()
            if res.posture is not None:
                click.echo(render_posture_summary(res.posture))  # type: ignore[arg-type]
                click.echo()
            click.echo(render_report(res.confirmed, tenant_id=customer_id, limit=limit))  # type: ignore[arg-type]
            click.echo()
            click.echo(render_candidates(res.candidates, tenant_id=customer_id))  # type: ignore[arg-type]
```

In the `as_json` branch, add posture to the dumped dict:

```python
                    {
                        "feeders": [...],
                        "posture": summary_to_dict(res.posture) if res.posture is not None else None,  # type: ignore[arg-type]
                        "confirmed": [...],
                        "candidates": [...],
                    },
```

- [ ] **Step 4: Run to verify it passes**

Run: `uv run pytest packages/agents/meta-harness/tests/test_cli_scan.py -q`
Expected: PASS.

- [ ] **Step 5: Full suite + typecheck + commit**

```bash
uv run pytest packages/agents/meta-harness/tests/ packages/runtime/tests/test_posture_pipeline.py -q
uv run mypy
git add packages/agents/meta-harness/src/meta_harness/cli.py packages/agents/meta-harness/tests/test_cli_scan.py
git commit -m "feat(posture): render posture coverage + summary in the scan CLI"
```

---

## Final verification (after all tasks)

- [ ] `uv run mypy` — clean (no path args).
- [ ] `uv run pytest packages/agents/meta-harness/tests/ packages/runtime/tests/ -q` — green.
- [ ] Manual sanity: `posture.json` contains `coverage` first-class; `render_posture_summary` leads with the coverage line; a forced rollup failure leaves the scan green (Task 6 test proves it).
- [ ] Confirm no plaintext (only counts / ids / path_types / percentages) in `posture.json` and the snapshot payload.

## Notes / deliberate deferrals (YAGNI)

- No OCSF export of posture; no graph POSTURE node; no per-finding-severity heatmap (v1 uses attack-path severities). All recorded in the spec's non-goals.
- `totals["nodes"]` is the sum of the categories we tally (inventory + finding + domain categories), not a full all-category scan — cheap and honest.
- `posture_trend` over-fetches `query_recent` then filters `posture_snapshot`; fine for v1 volumes. If snapshot history grows huge, add a dedicated `query_by_action` to `EpisodicStore` later.
