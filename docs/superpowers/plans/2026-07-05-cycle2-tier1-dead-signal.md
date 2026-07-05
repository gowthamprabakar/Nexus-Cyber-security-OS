# Cycle 2: Tier 1 Dead-Signal — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Light up lateral-movement (`CAN_REACH`/`PEERED_WITH`) + SBOM supply-chain (`CONTAINS_PACKAGE`)
as named first-class attack paths in `scan_run`, plus a `sensitive_resource` sink so a lateral pivot
reaching a managed datastore is impact.

**Architecture:** Wire a network-topology seam into `network_threat.run()` (pure `reach_grants` compute →
`record_reachability`); add the sink marker; add two named detectors mirroring existing ones; prove each
through `scan_run` + `ScanSources`.

**Tech Stack:** Python 3.12, async, SemanticStore, pytest-asyncio.

## Global Constraints

- Branch: `feat/cycle2-tier1-dead-signal` (off clean main; independent of the held #801 — do NOT stack).
- Commit subjects lowercase ≤100 chars; body ≤100. Husky must pass; NEVER `--no-verify`.
- `uv sync --all-packages --all-extras` before trusting local mypy/tests.
- **Cycle-1 lesson (binding):** before declaring the cycle done, run `uv run pytest packages/charter`
  (structural guards — ADR-016 tool-routing etc.) AND the whole suite. Scoped runs + diff-reviewers miss
  cross-package invariants. A new `run()` that calls a registered tool MUST go via `ctx.call_tool`.
- Detectors read CVE property keys `kev` / `epss_score` (the keys the writer actually stamps — the
  Cycle-1-correct keys; independent of #801 merge order).
- Query API: `self._semantic_store.list_entities_by_type(tenant_id=self._customer_id, entity_type=Cat.value)`,
  `self._edges_from(entity_id, (EdgeType.X.value, ...))` → `list[RelationshipRow]` (`.dst_entity_id`,
  `.properties`), `self._semantic_store.get_entity(tenant_id=self._customer_id, entity_id=...)` →
  entity (`.entity_id`, `.external_id`, `.properties`). `_float_or_none` helper exists in kg_query.

---

### Task 1: `sensitive_resource` sink marker (P2)

**Files:**

- Modify: `packages/agents/meta-harness/src/meta_harness/path_taxonomy.py` (`SINK_MARKERS`, ~:90-95)
- Test: `packages/agents/meta-harness/tests/test_path_taxonomy.py`

- [ ] **Step 1: failing test** — a CLOUD_RESOURCE with `kind="rds-instance"` (and one with `kind="kms-key"`)
      matches the `sensitive_resource` sink; a plain CLOUD_RESOURCE (no such kind) does not. Use the taxonomy's
      existing `match_sink`/marker-matching helper (mirror how `test_path_taxonomy.py` tests other markers).

- [ ] **Step 2: run, verify fail** (`uv run pytest packages/agents/meta-harness/tests/test_path_taxonomy.py -k sensitive_resource -v`).

- [ ] **Step 3: implement** — add to `SINK_MARKERS`:

```python
NodeMarker(
    "sensitive_resource",
    NodeCategory.CLOUD_RESOURCE,
    lambda p: p.get("kind") in {"rds-instance", "kms-key"},
),
```

- [ ] **Step 4: run, verify pass.**
- [ ] **Step 5:** `uv run pytest packages/agents/meta-harness -q` green (the generic engine now has a new
      sink — confirm no existing path_engine test regresses; if one asserts an exact candidate count, it may
      legitimately gain the new sink — reconcile honestly, don't force-green).
- [ ] **Step 6: commit** `feat(meta-harness): add sensitive_resource (rds/kms) sink marker`

---

### Task 2: `network_threat.run()` topology seam (P1a)

**Files:**

- Modify: `packages/agents/network-threat/src/network_threat/agent.py` (`run()` sig + the
  `semantic_store is not None` write block; `record_flows` is at ~:241)
- Test: `packages/agents/network-threat/tests/` (add a unit mirroring how the flow-write path is tested)

**Interfaces:**

- Consumes: `reach_grants(instances, security_groups)`, `peering_reach_grants(instances, peerings)`,
  `record_reachability(grants)`, `record_peering_reachability(grants)` (network_threat tools/kg_writer),
  dataclasses `NetworkInstance`/`SecurityGroup`/`VpcInstance` (`tools/reachability.py`).
- Produces: `run(..., network_instances=None, security_groups=None, vpc_instances=None, vpc_peerings=None)`.

- [ ] **Step 1: failing test** — call `run()` with a `semantic_store` + injected `network_instances`
      (a public foothold + a reachable target sharing an SG-allowed reach) + `security_groups`; assert a
      `CAN_REACH` edge lands (query the store). Then a `vpc_instances`+`vpc_peerings` case → `PEERED_WITH`.
      Use whatever contract/registry fixture the existing network-threat run() tests use.

- [ ] **Step 2: run, verify fail** (params don't exist).

- [ ] **Step 3: implement** — add the four params (types: `Sequence[NetworkInstance] | None` etc.,
      `frozenset[frozenset[str]] | None` for `vpc_peerings`). In the `semantic_store is not None` block,
      alongside the existing flow write:

```python
from network_threat.tools.reachability import reach_grants, peering_reach_grants  # top-of-file import
...
if network_instances is not None and security_groups is not None:
    grants = reach_grants(tuple(network_instances), tuple(security_groups))
    if grants:
        await writer.record_reachability(grants)
if vpc_instances is not None and vpc_peerings is not None:
    pgrants = peering_reach_grants(tuple(vpc_instances), vpc_peerings)
    if pgrants:
        await writer.record_peering_reachability(pgrants)
```

`reach_grants`/`peering_reach_grants` are PURE (no tool dispatch) → no ctx.call_tool / ADR-016 concern.
Do NOT touch `record_flows` or the live-reader follow-on. `None` inputs skip (unchanged behavior).

- [ ] **Step 4: run, verify pass.**
- [ ] **Step 5:** `uv run pytest packages/agents/network-threat -q` green + `uv run pytest packages/charter -q`
      (guard: no new direct tool-call introduced) + `uv run mypy packages/agents/network-threat`.
- [ ] **Step 6: commit** `feat(network-threat): run() topology seam writes CAN_REACH/PEERED_WITH offline`

---

### Task 3: pipeline seam (P1b)

**Files:**

- Modify: `packages/runtime/src/nexus_runtime/scan_pipeline.py` (`ScanSources` + network-threat feeder ~:461-475)
- Test: `packages/runtime/tests/integration/test_scan_pipeline_e2e.py` (edge-lands assertion)

**Interfaces:**

- Produces: `ScanSources.network_instances`, `.network_security_groups`, `.network_vpc_instances`,
  `.network_vpc_peerings` (all `... | None = None`).

- [ ] **Step 1: failing test** — `scan_run` with `network_instances`/`network_security_groups` injected
      (a public foothold reaching a target) → assert a `CAN_REACH` relationship exists in the store after the run.
      (This proves the feeder threads them; the full lateral-path assertion is Task 4.)

- [ ] **Step 2: run, verify fail** (`ScanSources` has no such field).

- [ ] **Step 3: implement** — add the four `ScanSources` fields near the other network feed fields; in the
      network-threat feeder: widen `needed` to `sources.network_vpc_flow_feed is not None or
sources.network_instances is not None or sources.network_vpc_instances is not None`; pass
      `network_instances=sources.network_instances, security_groups=sources.network_security_groups,
vpc_instances=sources.network_vpc_instances, vpc_peerings=sources.network_vpc_peerings` to
      `network_threat_run(...)`. Import the reachability dataclasses if a type hint needs them.

- [ ] **Step 4: run, verify pass.**
- [ ] **Step 5:** `uv run pytest packages/runtime -q` green (existing e2e unaffected — `None` defaults).
- [ ] **Step 6: commit** `feat(runtime): scan pipeline injects network topology → CAN_REACH/PEERED_WITH land`

---

### Task 4: named lateral-movement-via-reachability detector (P3)

**Files:**

- Modify: `packages/agents/meta-harness/src/meta_harness/kg_query.py` (new detector + dataclass + `__all__`)
- Modify: `packages/agents/meta-harness/src/meta_harness/attack_paths.py` (`find_all`, `_SEVERITY`, `_title`)
- Test: `packages/agents/meta-harness/tests/test_kg_query_*.py` (new) + `packages/runtime/tests/integration/test_scan_pipeline_e2e.py` (scan_run e2es)

**Interfaces:**

- Produces: `KgQuery.find_lateral_movement_via_reachability() -> list[LateralReachable]`;
  `AttackPath(path_type="lateral_reachable", ...)`.

- [ ] **Step 1: failing kg_query unit** — seed (via store upserts or the network writer) a public
      CLOUD_RESOURCE `--CAN_REACH--> target`, where target `--VULNERABLE_TO--> CVE`; assert the detector
      returns one hit with `impact="vulnerable_host"`. Second case: target `kind="rds-instance"` → one hit
      `impact="sensitive_resource"`. Third: `PEERED_WITH` → hit with `reach_kind="vpc_peering"`.

- [ ] **Step 2: run, verify fail.**

- [ ] **Step 3: implement the detector** in kg_query.py (mirror `find_internet_exposed_vulnerable_workload`
      style):

```python
@dataclass(frozen=True, slots=True)
class LateralReachable:
    foothold_id: str
    target_id: str
    reach_kind: str          # "lateral_sg" | "vpc_peering" (from edge property "method")
    impact: str              # "vulnerable_host" | "sensitive_resource"
    cve_id: str = ""
    severity: str = ""

async def find_lateral_movement_via_reachability(self) -> list["LateralReachable"]:
    """Derived (config-based) lateral movement: a public foothold that CAN_REACH / PEERED_WITH a
    target which is either a vulnerable host or a managed datastore. Distinct from the observed-flow
    find_lateral_movement_to_vulnerable_host (this fires before any traffic). Read-only."""
    hits: list[LateralReachable] = []
    for foothold in await self._semantic_store.list_entities_by_type(
        tenant_id=self._customer_id, entity_type=NodeCategory.CLOUD_RESOURCE.value
    ):
        if foothold.properties.get("is_public") is not True:
            continue
        for reach in await self._edges_from(
            foothold.entity_id, (EdgeType.CAN_REACH.value, EdgeType.PEERED_WITH.value)
        ):
            if reach.dst_entity_id == foothold.entity_id:
                continue
            target = await self._semantic_store.get_entity(
                tenant_id=self._customer_id, entity_id=reach.dst_entity_id
            )
            if target is None:
                continue
            reach_kind = str(reach.properties.get("method", ""))
            if target.properties.get("kind") in {"rds-instance", "kms-key"}:
                hits.append(LateralReachable(
                    foothold.entity_id, target.entity_id, reach_kind, "sensitive_resource"))
            for vuln in await self._edges_from(target.entity_id, (EdgeType.VULNERABLE_TO.value,)):
                cve = await self._semantic_store.get_entity(
                    tenant_id=self._customer_id, entity_id=vuln.dst_entity_id)
                if cve is None:
                    continue
                hits.append(LateralReachable(
                    foothold.entity_id, target.entity_id, reach_kind, "vulnerable_host",
                    cve.external_id, str(cve.properties.get("severity", ""))))
    return hits
```

Add `LateralReachable` to `__all__`.

- [ ] **Step 4: wire into `attack_paths.py`** — in `find_all`, add a loop grouping by `(foothold, target)`:

```python
for lr in await self._kg.find_lateral_movement_via_reachability():
    g("lateral_reachable", (lr.foothold_id, lr.target_id)).add(
        (lr.foothold_id, lr.target_id),
        lr.cve_id or lr.impact,
        cve_severity=lr.severity,
        reach_kind=lr.reach_kind,
        impact=lr.impact,
    )
```

Add `_SEVERITY["lateral_reachable"] = 78` (below the observed-flow lateral 82 — derived = potential, not
confirmed traffic; verify the observed value and stay just under it). Add a `_title` branch, e.g.
`"Public foothold can reach an internal {impact} over the network ({reach_kind}) — lateral movement"`.

- [ ] **Step 5: scan_run e2es** in `test_scan_pipeline_e2e.py` — (a) foothold `CAN_REACH` a
      `vuln_host_target_arn` vulnerable host → a `lateral_reachable` confirmed path; (b) foothold `CAN_REACH`
      an injected private `rds-instance` (via `ScanSources.cloud_rds_instances`) → `lateral_reachable`
      `sensitive_resource` path (proves the Task-1 sink); (c) `PEERED_WITH` across two VPCs. Assert
      `all(f.ok for f in res.feeders)` + the confirmed path present. Mirror the `network_instances` seam from
      Task 3's test for the foothold+target node ids (they must match the `is_public` node cloud-posture wrote).

- [ ] **Step 6:** `uv run pytest packages/agents/meta-harness packages/runtime -q` green; `uv run mypy` (whole-repo).
- [ ] **Step 7: commit** `feat(meta-harness): find_lateral_movement_via_reachability (derived CAN_REACH/PEERED_WITH)`

---

### Task 5: named SBOM supply-chain detector (P4)

**Files:**

- Modify: `packages/agents/meta-harness/src/meta_harness/kg_query.py` (detector + dataclass + `__all__`)
- Modify: `packages/agents/meta-harness/src/meta_harness/attack_paths.py` (`find_all` + subsume, `_SEVERITY`, `_title`)
- Test: `packages/agents/meta-harness/tests/` + `test_scan_pipeline_e2e.py`

**Interfaces:**

- Produces: `KgQuery.find_supply_chain_sbom() -> list[SupplyChainSbom]`;
  `AttackPath(path_type="supply_chain_sbom", ...)`.

- [ ] **Step 1: failing kg_query unit** — public workload `--RUNS_IMAGE--> image --CONTAINS_PACKAGE-->
pkg --VULNERABLE_TO--> CVE`; assert one hit with the package name + cve. FIRST verify what property the
      SBOM_PACKAGE node carries the package name in (read `vulnerability/kg_writer.py:record_sbom_packages`
      ~:91-112 — the node is keyed `{image}#{name}`; confirm whether `name` is a property or must be parsed;
      use the real property).

- [ ] **Step 2: run, verify fail.**

- [ ] **Step 3: implement** (mirror `find_internet_exposed_vulnerable_workload` + one extra hop):

```python
@dataclass(frozen=True, slots=True)
class SupplyChainSbom:
    workload_id: str
    image_id: str
    package_name: str
    cve_id: str
    severity: str
    kev_listed: bool = False
    epss_score: float | None = None

async def find_supply_chain_sbom(self) -> list["SupplyChainSbom"]:
    """Public workload runs an image whose SBOM package has a CVE (dependency-level supply chain).
    Package granularity over find_internet_exposed_vulnerable_workload (which stops at image→CVE)."""
    hits: list[SupplyChainSbom] = []
    for workload in await self._semantic_store.list_entities_by_type(
        tenant_id=self._customer_id, entity_type=NodeCategory.CLOUD_RESOURCE.value
    ):
        if workload.properties.get("is_public") is not True:
            continue
        for runs in await self._edges_from(workload.entity_id, (EdgeType.RUNS_IMAGE.value,)):
            for contains in await self._edges_from(
                runs.dst_entity_id, (EdgeType.CONTAINS_PACKAGE.value,)
            ):
                pkg = await self._semantic_store.get_entity(
                    tenant_id=self._customer_id, entity_id=contains.dst_entity_id)
                if pkg is None:
                    continue
                for vuln in await self._edges_from(pkg.entity_id, (EdgeType.VULNERABLE_TO.value,)):
                    cve = await self._semantic_store.get_entity(
                        tenant_id=self._customer_id, entity_id=vuln.dst_entity_id)
                    if cve is None:
                        continue
                    hits.append(SupplyChainSbom(
                        workload_id=workload.entity_id, image_id=runs.dst_entity_id,
                        package_name=str(pkg.properties.get("name", "")),  # verify key in Step 1
                        cve_id=cve.external_id, severity=str(cve.properties.get("severity", "")),
                        kev_listed=bool(cve.properties.get("kev", False)),
                        epss_score=_float_or_none(cve.properties.get("epss_score"))))
    return hits
```

- [ ] **Step 4: wire + subsume** in `attack_paths.py` — run the SBOM loop and collect its workload ids into
      a `subsumed_sbom_workloads: set[str]`; in the `find_internet_exposed_vulnerable_workload` loop, add
      `if v.workload_id in subsumed_sbom_workloads: continue` (mirror the existing `subsumed_workloads`
      pattern for crown_jewel). The SBOM path is the more specific framing when package data exists. Group SBOM
      by `(workload_id, image_id)`; carry `cve_kev`/`cve_epss`. Add `_SEVERITY["supply_chain_sbom"]` (same tier
      as `internet_exposed_vulnerable` — it's the same workload, finer attribution). `_title` names the
      package(s): `"Internet-exposed workload runs a vulnerable dependency ({packages}) — {cve_phrase}"`.

- [ ] **Step 5: scan_run e2e** — `cloud_ecs_workloads=(EcsWorkload(image_ref=IMG, is_public=True),)` +
      `vuln_image_refs=(IMG,)` → `scan_run` → a `supply_chain_sbom` confirmed path naming the package; assert
      NO separate `internet_exposed_vulnerable` row for that same workload (subsumed).

- [ ] **Step 6:** `uv run pytest packages/agents/meta-harness packages/runtime -q` green; `uv run mypy` (whole-repo).
- [ ] **Step 7: commit** `feat(meta-harness): find_supply_chain_sbom names vulnerable dependency + subsumes vuln-workload`

---

### Task 6: coverage doc

**Files:** Modify `docs/strategy/operating-path-detector-coverage.md`

- [ ] **Step 1:** add two rows (`find_lateral_movement_via_reachability`, `find_supply_chain_sbom`) with
      the required spine legs + feeders; note the honest scoping (SBOM = package attribution over the existing
      vuln-workload detector, subsumes it; lateral = derived/config, distinct from the observed-flow one; the
      `sensitive_resource` sink lets a pivot reach a managed datastore). Note MEMBER_OF/ATTACHED_TO/POD_CAN_REACH
      parked (redundant / live-only).
- [ ] **Step 2: commit** `docs(coverage): lateral-movement-via-reachability + sbom supply-chain detectors`

---

## Final whole-branch review

After Task 6: `scripts/review-package $(git merge-base main HEAD) HEAD` → dispatch a whole-branch review on
the most capable model. Focus: (1) lateral + SBOM fire through `scan_run` green-for-right-reason (seams
land the edges, detectors read them, e2es load-bearing); (2) the SBOM subsume doesn't drop legitimate
distinct paths; (3) no new ADR-016 direct-tool-call (run `packages/charter`); (4) the `sensitive_resource`
sink didn't perturb existing generic-engine candidate counts unexpectedly; (5) whole suite green. Then
superpowers:finishing-a-development-branch (push; open PR off main for operator merge).
