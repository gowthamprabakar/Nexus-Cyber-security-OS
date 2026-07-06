# Cycle 1: Make the Expected-Loss Ranking REAL — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire KEV + EPSS end-to-end onto graph CVE nodes so the expected-loss ranking's
exploitability signal actually fires in the pipeline — a CISA-KEV-listed vuln outranks a non-KEV one
of equal severity.

**Architecture:** Mirror the existing injectable-seam + live-gated pattern. The graph writer stamps
`kev` (already) + `epss_score` (new) on CVE nodes; `run()` sources both from injected maps (offline)
or the already-registered `is_kev`/`nvd_enrich` tools (live, 24h-cached); the pipeline injects maps
via `ScanSources`; the 6 named detectors read the `kev` key the writer actually stamps.

**Tech Stack:** Python 3.12, async, SQLAlchemy SemanticStore, pytest-asyncio.

## Global Constraints

- Branch: `feat/tier3-multicloud-ranking` (folds into held #801). Do NOT open a new PR.
- Commit subjects lowercase, ≤100 chars; body lines ≤100. Husky must pass; NEVER `--no-verify`.
- Before trusting local mypy/tests: `uv sync --all-packages --all-extras` (root `.venv` omits
  per-package deps like fastapi/fleet_testkit/aiosqlite → local-green/CI-red otherwise).
- Verify env: `uv run mypy`, `uv run ruff check`, `uv run pytest` (scoped packages) all clean.
- Security unchanged: only AWS AKIA/ASIA in clear; live network stays behind existing enrichment
  gating; no plaintext secret evidence.
- The writer reads Trivy-native `raw_findings` (pre-OCSF). Do NOT reverse-parse OCSF dicts to source
  kev/epss — source them from `is_kev`/`nvd_enrich` (the tools), or from injected maps.
- Align direction is FIXED: fix the readers in `kg_query.py` (`kev_listed`→`kev`). Do NOT change the
  writer's `kev` key or `path_engine.py`'s `kev` reads.
- sink_id / blast are OUT OF SCOPE (honest floors for data-less paths, not defects).

---

### Task 1: Writer stamps `epss_score`

**Files:**

- Modify: `packages/agents/vulnerability/src/vulnerability/kg_writer.py` (`record_scan_results`, ~:38-70)
- Test: `packages/agents/vulnerability/tests/test_kg_writer.py` (add; or extend existing writer test file)

**Interfaces:**

- Consumes: nothing new.
- Produces: `record_scan_results(trivy_results, *, kev_cve_ids=None, epss_scores=None)` where
  `epss_scores: Mapping[str, float] | None`. CVE node properties become
  `{"severity": str, "kev": bool, "epss_score": float}` — `epss_score` present only when the CVE id
  is in `epss_scores`.

- [ ] **Step 1: Write the failing test**

```python
# test_kg_writer.py  (async; uses an in-memory SemanticStore fixture like the other writer tests)
async def test_record_scan_results_stamps_kev_and_epss(store, tenant):
    writer = KnowledgeGraphWriter(store, tenant)
    trivy = _trivy_result_with_cves(["CVE-AAA", "CVE-BBB"])  # helper: two CVEs on one image
    await writer.record_scan_results(
        trivy,
        kev_cve_ids=frozenset({"CVE-AAA"}),
        epss_scores={"CVE-AAA": 0.97},
    )
    aaa = await _get_cve_node(store, tenant, "CVE-AAA")
    bbb = await _get_cve_node(store, tenant, "CVE-BBB")
    assert aaa.properties.get("kev") is True
    assert aaa.properties.get("epss_score") == 0.97
    assert bbb.properties.get("kev") is False
    assert bbb.properties.get("epss_score") is None  # not in either map → absent
```

- [ ] **Step 2: Run it, verify it fails** (`epss_scores` param does not exist yet / epss_score not stamped).

Run: `uv run pytest packages/agents/vulnerability/tests/test_kg_writer.py -k stamps_kev_and_epss -v`
Expected: FAIL (TypeError unexpected kwarg, or epss_score None).

- [ ] **Step 3: Implement**

Add the param and stamp. In `record_scan_results`:

```python
async def record_scan_results(
    self,
    trivy_results: Iterable[TrivyResult],
    *,
    kev_cve_ids: frozenset[str] | set[str] | None = None,
    epss_scores: Mapping[str, float] | None = None,
) -> None:
    kev = kev_cve_ids or frozenset()
    epss = epss_scores or {}
    ...
    # where the CVE node properties dict is built (currently kg_writer.py:67):
    props = {"severity": str(raw.get("Severity", "")), "kev": cve_id in kev}
    if cve_id in epss:
        props["epss_score"] = float(epss[cve_id])
    # ...use props for the CVE node upsert
```

Add `from collections.abc import Mapping` to the `TYPE_CHECKING` / imports block as appropriate
(`Mapping` is only a type hint → `TYPE_CHECKING` import is fine; `frozenset`/`float` are runtime).

- [ ] **Step 4: Run the test, verify it passes.**

Run: `uv run pytest packages/agents/vulnerability/tests/test_kg_writer.py -k stamps_kev_and_epss -v`
Expected: PASS.

- [ ] **Step 5: Run the vulnerability package tests** (`uv run pytest packages/agents/vulnerability -q`) — green.

- [ ] **Step 6: Commit**

```bash
git add packages/agents/vulnerability/src/vulnerability/kg_writer.py packages/agents/vulnerability/tests/test_kg_writer.py
git commit -m "feat(vuln): graph writer stamps epss_score on CVE nodes (mirrors kev_cve_ids)"
```

---

### Task 2: Align the 6 named-detector KEV reads + ranking-through-the-writer test

**Files:**

- Modify: `packages/agents/meta-harness/src/meta_harness/kg_query.py` (:680, 787, 850, 882, 1328, 1422)
- Test: `packages/agents/meta-harness/tests/test_probabilistic_ranking.py` (add a through-the-writer test)

**Interfaces:**

- Consumes: CVE node property key `kev` (Task 1 / existing writer) + `epss_score` (Task 1).
- Produces: named detectors now surface real `kev_listed`/`epss_score` on their `*Cve` dataclasses.

- [ ] **Step 1: Write the failing test** — build the graph THROUGH the real writer, not hand-planted
      properties. Two equal-severity CVEs, one KEV, on two equivalent internet-exposed workloads; assert
      the KEV workload's path ranks first.

```python
async def test_kev_path_outranks_non_kev_through_real_writer(store, tenant):
    # Build two internet-exposed vulnerable workloads via the REAL writers:
    #   workload-A image has CVE-KEV (HIGH, KEV-listed), workload-B image has CVE-PLAIN (HIGH, not KEV).
    # cloud-posture writer: two is_public workloads each RUNS_IMAGE an image.
    # vulnerability writer: record_scan_results(..., kev_cve_ids={"CVE-KEV"}) so ONLY the KEV node
    #   gets kev=True — through record_scan_results, NOT store.upsert with hand-set properties.
    await _seed_two_exposed_vuln_workloads_via_writers(store, tenant)  # helper
    kq = KgQuery(store, tenant)
    confirmed = await AttackPathRanker(kq).find_all()
    ranked = await rank_by_expected_loss(confirmed, store, tenant)
    top = ranked[0][0]
    assert top.kev is True, "the KEV-listed workload must rank first"
    # And prove it's the KEV lift, not a title/severity artifact: the two paths tie on severity,
    # differ only by kev — under the OLD kev_listed reader this assertion FAILS (both kev=False).
```

- [ ] **Step 2: Run it, verify it fails** under the current `kev_listed` reader (both paths `kev=False`
      → order decided by title, KEV path not guaranteed first).

Run: `uv run pytest packages/agents/meta-harness/tests/test_probabilistic_ranking.py -k through_real_writer -v`
Expected: FAIL.

- [ ] **Step 3: Implement** — change the 6 reader sites in `kg_query.py` from
      `cve.properties.get("kev_listed", False)` to `cve.properties.get("kev", False)`. Leave the dataclass
      field name `kev_listed` and the `epss_score` reads unchanged (epss reads already match Task 1).

- [ ] **Step 4: Run the test, verify it passes.**

Run: `uv run pytest packages/agents/meta-harness/tests/test_probabilistic_ranking.py -k through_real_writer -v`
Expected: PASS.

- [ ] **Step 5: Run meta-harness tests** (`uv run pytest packages/agents/meta-harness -q`) — green,
      including the existing `test_probabilistic_ranking.py` / `test_path_engine.py` (they use the `kev`
      key already, so aligning the named readers to `kev` keeps them green).

- [ ] **Step 6: Commit**

```bash
git add packages/agents/meta-harness/src/meta_harness/kg_query.py packages/agents/meta-harness/tests/test_probabilistic_ranking.py
git commit -m "fix(meta-harness): named detectors read the kev property the writer stamps (was kev_listed)"
```

---

### Task 3: `run()` threads KEV + EPSS to the writer (injected + live auto-source)

**Files:**

- Modify: `packages/agents/vulnerability/src/vulnerability/agent.py` (`run()` sig + graph-write block ~:258-260)
- Test: `packages/agents/vulnerability/tests/test_agent_unit.py` (add graph-write kev/epss assertions)

**Interfaces:**

- Consumes: `record_scan_results(..., kev_cve_ids=, epss_scores=)` (Task 1); `is_kev` (tools/kev.py:94,
  `async is_kev(cve_id)->bool`), `nvd_enrich` (tools/nvd.py:149, `async nvd_enrich(cve_id)->NVDEnrichment`
  with `.epss_probability: float|None`).
- Produces: `run(..., kev_cve_ids: frozenset[str]|None=None, epss_scores: Mapping[str,float]|None=None)`.

- [ ] **Step 1: Write the failing test** — with a `semantic_store` injected and `kev_cve_ids` provided,
      the CVE node ends up `kev=True`.

```python
async def test_run_graph_write_stamps_injected_kev_epss(store):
    # run() with semantic_store + injected kev/epss maps (enrich=False to avoid network):
    await run(
        contract=_contract(tenant="t"),
        image_refs=["img@sha256:..."],   # a fixture image the trivy stub scans to CVE-KEV
        enrich=False,
        semantic_store=store,
        kev_cve_ids=frozenset({"CVE-KEV"}),
        epss_scores={"CVE-KEV": 0.9},
    )
    node = await _get_cve_node(store, "t", "CVE-KEV")
    assert node.properties.get("kev") is True
    assert node.properties.get("epss_score") == 0.9
```

- [ ] **Step 2: Run it, verify it fails** (run() has no kev_cve_ids param; writer gets none).

Run: `uv run pytest packages/agents/vulnerability/tests/test_agent_unit.py -k injected_kev_epss -v`
Expected: FAIL.

- [ ] **Step 3: Implement** — add the two params to `run()`; in the graph-write block (agent.py:258):

```python
if semantic_store is not None:
    kg = KnowledgeGraphWriter(semantic_store, contract.customer_id)
    # Source KEV/EPSS for the scanned CVEs: injected maps win (offline/pipeline); else, when
    # enrich=True, reuse the already-registered is_kev/nvd_enrich tools (24h-cached → the
    # normalizer below warms the same cache, so this is cache-cheap, not a second live fetch).
    cve_ids = {
        f.get("VulnerabilityID", "")
        for r in trivy_results for f in r.raw_findings
        if f.get("VulnerabilityID")
    }
    kev_ids = kev_cve_ids
    epss_map = epss_scores
    if kev_ids is None and enrich:
        kev_ids = frozenset({c for c in cve_ids if await is_kev(c)})
    if epss_map is None and enrich:
        epss_map = {
            c: e.epss_probability
            for c in cve_ids
            if (e := await nvd_enrich(c, api_key=nvd_api_key)).epss_probability is not None
        }
    await kg.record_scan_results(trivy_results, kev_cve_ids=kev_ids, epss_scores=epss_map)
    # ... existing CONTAINS_PACKAGE loop unchanged ...
```

`ponytail:` when `enrich=False` and no injected maps, kev_ids/epss_map stay None → writer stamps
`kev=False`/no epss (the eval-runner path, unchanged). Add `Mapping` import.

- [ ] **Step 4: Run the test, verify it passes.**

Run: `uv run pytest packages/agents/vulnerability/tests/test_agent_unit.py -k injected_kev_epss -v`
Expected: PASS.

- [ ] **Step 5: Run vulnerability tests** (`uv run pytest packages/agents/vulnerability -q`) — green
      (existing `enrich=False` eval-runner tests unaffected: no injected maps + enrich=False → no kev/epss,
      same as before).

- [ ] **Step 6: Commit**

```bash
git add packages/agents/vulnerability/src/vulnerability/agent.py packages/agents/vulnerability/tests/test_agent_unit.py
git commit -m "feat(vuln): run() threads kev_cve_ids + epss_scores to graph writer (injected or live-sourced)"
```

---

### Task 4: Pipeline injectable seam + e2e

**Files:**

- Modify: `packages/runtime/src/nexus_runtime/scan_pipeline.py` (`ScanSources` + vulnerability feeder block)
- Test: `packages/runtime/tests/integration/test_scan_pipeline_e2e.py` (add a KEV-ranking e2e)

**Interfaces:**

- Consumes: `vulnerability_run(..., kev_cve_ids=, epss_scores=)` (Task 3).
- Produces: `ScanSources.vuln_kev_cve_ids: frozenset[str] | None`,
  `ScanSources.vuln_epss_scores: Mapping[str, float] | None`.

- [ ] **Step 1: Write the failing test** — `scan_run` with an internet-exposed vulnerable workload +
      `vuln_kev_cve_ids={the CVE}` produces a confirmed path whose `.kev is True`.

```python
async def test_scan_run_kev_reaches_confirmed_path(tmp_path):
    sources = ScanSources(
        # existing offline feeds that form an internet_exposed_vulnerable workload with CVE-KEV:
        cloud_ec2_workloads=_one_public_workload_running_image(),
        vuln_image_refs=("img@sha256:...",),   # trivy stub → CVE-KEV on that image
        vuln_kev_cve_ids=frozenset({"CVE-KEV"}),
        vuln_epss_scores={"CVE-KEV": 0.95},
    )
    res = await scan_run(session_factory=factory, tenant="t", sources=sources, workspace_root=tmp_path/"ws")
    assert all(f.ok for f in res.feeders), [f for f in res.feeders if not f.ok]
    kev_paths = [p for p in res.confirmed if p.kev]
    assert kev_paths, f"a KEV-flagged path must reach confirmed; got {[(p.path_type, p.kev) for p in res.confirmed]}"
```

- [ ] **Step 2: Run it, verify it fails** (`ScanSources` has no `vuln_kev_cve_ids`).

Run: `uv run pytest packages/runtime/tests/integration/test_scan_pipeline_e2e.py -k kev_reaches_confirmed -v`
Expected: FAIL.

- [ ] **Step 3: Implement** — add the two fields to `ScanSources` (near the other `vuln_*` fields,
      scan_pipeline.py:165-171); in the vulnerability feeder block, pass them through:

```python
# in ScanSources:
vuln_kev_cve_ids: frozenset[str] | None = None
vuln_epss_scores: Mapping[str, float] | None = None

# in the vulnerability feeder call to vulnerability_run(...):
kev_cve_ids=sources.vuln_kev_cve_ids,
epss_scores=sources.vuln_epss_scores,
```

Add `Mapping` import to scan_pipeline.py if not present.

- [ ] **Step 4: Run the test, verify it passes.**

Run: `uv run pytest packages/runtime/tests/integration/test_scan_pipeline_e2e.py -k kev_reaches_confirmed -v`
Expected: PASS.

- [ ] **Step 5: Run runtime tests** (`uv run pytest packages/runtime -q`) — green (existing e2e that
      don't set the new fields are unaffected: `None` → unchanged behavior).

- [ ] **Step 6: Commit**

```bash
git add packages/runtime/src/nexus_runtime/scan_pipeline.py packages/runtime/tests/integration/test_scan_pipeline_e2e.py
git commit -m "feat(runtime): scan pipeline injects vuln kev/epss maps → exploitability reaches ranking"
```

---

### Task 5: Coverage doc + #801 honesty correction

**Files:**

- Modify: `docs/strategy/operating-path-detector-coverage.md`

**Interfaces:** none (docs).

- [ ] **Step 1: Update the doc** — note that KEV + EPSS now flow end-to-end onto graph CVE nodes
      (writer stamps `kev`/`epss_score`; `run()` sources injected-or-live; detectors read `kev`); the
      expected-loss ranking's exploitability lift is now live, not cosmetic. Correct any prior wording
      implying KEV already flowed. Keep the honest ceiling: live auto-source uses the agent's existing
      `is_kev`/`nvd_enrich` (24h cache) behind `enrich=True`; offline/pipeline injects maps.

- [ ] **Step 2: Commit**

```bash
git add docs/strategy/operating-path-detector-coverage.md
git commit -m "docs(coverage): KEV/EPSS exploitability now live end-to-end (corrects #801 record)"
```

---

## Final whole-branch review

After Task 5: dispatch a whole-branch review over the FULL #801 branch (merge-base main..HEAD — this
includes the original Tier-3 commits AND Cycle 1) on the most capable model. Focus: (1) the ranking
now flows KEV/EPSS through the REAL writer end-to-end (no hand-planted-property tests remain as the
sole proof); (2) the align direction didn't break the generic engine's `kev` read; (3) no
double-live-fetch regression; (4) `sink_id`/`blast` correctly untouched. Then
superpowers:finishing-a-development-branch (push to the existing #801 branch; operator merges).
