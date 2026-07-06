# Cycle 1: Make the Expected-Loss Ranking REAL — Design

**Date:** 2026-07-05
**Branch:** `feat/tier3-multicloud-ranking` (folds into the held #801 — operator: "hold #801, fold the fix in")
**Status:** design — awaiting operator review before planning

## Goal

Make the expected-loss ranking's **exploitability signal actually fire in the running pipeline.**
Today the KEV lift and the EPSS branch of `leaf_probability` are both structurally dead: every
CVE-bearing attack path ranks as if `kev=False, epss=None`. This cycle wires KEV + EPSS end-to-end
so a CISA-KEV-listed vulnerability genuinely outranks a non-KEV one of equal severity.

## The honest correction to #801 (no lipstick)

#801's summary claimed "the lift is KEV-driven" and the ranking surfaces "worst-CVE KEV/EPSS onto
AttackPath." **That was green-for-the-wrong-reason.** #801's ranking tests planted CVE node
`properties={"kev_listed": True, "epss_score": 0.97}` _directly_ onto the store, bypassing the real
writer — so they proved the _reader_ reads `kev_listed`, but not that anything ever _writes_ it. In
the real pipeline nothing does. #801's expected-loss ordering is still a genuine improvement for the
data-reaching paths (blast × belief is real there), but its exploitability lift is inert. This cycle
makes it real and corrects the record.

## The defect (file:line verified)

Three stacked breaks kill the exploitability signal in the pipeline:

1. **`run()` never passes the KEV catalog to the graph writer.** `agent.py:260` calls
   `kg.record_scan_results(trivy_results)` with **no `kev_cve_ids`** → the writer's `kev = kev_cve_ids
or frozenset()` is empty → every CVE node is stamped `kev=False` (`kg_writer.py:51,67`),
   regardless of KEV status.
2. **The named detectors read the wrong key.** The 6 CVE-reading detectors in `kg_query.py`
   (`:680, 787, 850, 882, 1328, 1422`) read `cve.properties.get("kev_listed")` — but the writer
   stamps the property under key **`kev`**. Even if break #1 were fixed, the named detectors would
   still see nothing. (The _generic_ engine reads the correct key — `path_engine.py:118,414` read
   `properties.get("kev")` — which is why the align direction below fixes the readers, not the writer.)
3. **EPSS is never propagated to the graph at all.** `kg_writer.py:67` stamps only `severity` + `kev`;
   there is no `epss_score`. The detectors read `epss_score` (`kg_query.py:681, …`) → always `None`.
   EPSS **is already sourced** upstream (`tools/nvd.py:_fetch_epss` hits FIRST.org; `normalizer.py`
   enriches every CVE; `schemas.py:165` carries `epss_probability`) — it just never reaches the node.

Net effect in `leaf_probability(severity, kev, epss)` (`path_priors.py:17`): `kev` always False (no
0.9 floor), `epss` always None (severity-linear proxy only). So every CVE path scores
`severity/100 × 0.8`, and the exploitability model is cosmetic.

## Align direction (decision)

**Fix the 6 reader sites in `kg_query.py` (`kev_listed` → `kev`), NOT the writer.** The writer's `kev`
key is the established one: the generic engine (`path_engine.py:118,414`) and three test files
(`test_probabilistic_ranking.py`, `test_path_engine.py`, `fleet_testkit/test_known_limitations.py`)
all read `properties.get("kev")`. The named detectors are the lone dissenters. Aligning them to `kev`
is the minimal, safe change; flipping the writer would break the generic engine's KEV read. The
detector dataclass _field_ stays named `kev_listed` (semantic), it just reads from property key `kev`.

## Explicitly OUT OF SCOPE — honest floors, not defects (YAGNI)

The validation flagged "blast floors to 1 for ~10/24" and "no sink_id for 11/24." **These are correct,
not defects, and this cycle does NOT touch them:**

- The 11 paths without a sink (`internet_exposed_vulnerable`, `privileged_vulnerable`,
  `internet_exposed_host_vulnerable`, `runtime_exploit_vulnerable`, `exposed_kms_key`,
  `exposed_database`, `rbac_privilege_escalation`, `malicious_destination`, `lateral_movement`,
  `iac_misconfig_deployed`, `cicd_compromise`) genuinely terminate at a CVE / public resource / C2 IP
  / admin role / repo — **not a DATA_CLASSIFICATION node**. `sink_id=""` and `blast=1` are honest.
- The 13 data-reaching paths already set `sink=data_classification_id` (`attack_paths.py:269,…`) and
  `_blast` already resolves their `resource_id` via `resource_reach` (#801) → real blast.
- Once KEV/EPSS are real, `leaf_probability` differentiates the 11 no-sink paths correctly (a KEV
  exposed-vuln → route_p ≥ 0.9 outranks a non-KEV one ≤ 0.8). **Fixing exploitability is the fix**;
  forcing a sink/blast onto data-less paths would be wrong.

## Architecture

Mirror the existing injectable-seam + live-gated pattern used by every pipeline feeder.

**C1 — writer stamps EPSS.** `KnowledgeGraphWriter.record_scan_results` gains
`epss_scores: Mapping[str, float] | None = None`. When a CVE id is present in the map, stamp
`epss_score` on the CVE node's properties alongside `kev`. Absent → omit (node has no `epss_score`,
detector reads `None`). KEV already flows via the existing `kev_cve_ids` param.

**C2 — `run()` threads KEV + EPSS to the writer.** `agent.py:258-260` passes `kev_cve_ids` +
`epss_scores` to `record_scan_results`. Source (mirrors every feeder's live-gated / offline-injectable
split):

- **Offline / pipeline:** injected maps (new `run()` params, defaulting `None`), supplied by
  `ScanSources` (C3). This is the testable path — Done = watched-it-work offline.
- **Live:** reuse the agent's existing per-CVE KEV/EPSS enrichment (`normalizer`/`nvd.py`) that already
  runs for the OCSF path; build `kev_cve_ids` + `epss_scores` from it. Live network stays behind the
  agent's existing enrichment gating. (Plan confirms the exact reuse point; no new external feed.)

**C3 — pipeline injectable seam.** `ScanSources` gains `vuln_kev_cve_ids: frozenset[str] | None` +
`vuln_epss_scores: Mapping[str, float] | None`; the vulnerability feeder in `scan_pipeline.py` passes
them into `vulnerability_run(...)`. `None` → unchanged behavior (existing tests green).

**C4 — reader alignment.** The 6 `kg_query.py` sites read `properties.get("kev")` instead of
`get("kev_listed")`. `epss_score` reads are already correct (they match C1's stamp).

**C5 — the AttackPath rollup is already correct.** `_Group.add(cve_kev=…, cve_epss=…)` →
`AttackPath.kev/epss` (`attack_paths.py:127-130,456-457`) and `rank_by_expected_loss` already consume
`p.kev/p.epss` (`report_card.py:214`). No change — C1–C4 make the inputs real.

## Data flow / join keys

```
CISA KEV catalog ─┐                                   ┌─ named detector reads properties["kev"]  (C4)
                  ├─ run() (C2) ─ record_scan_results ─┤
FIRST.org EPSS  ──┘   kev_cve_ids + epss_scores (C3)   └─ named detector reads properties["epss_score"] (C1)
                                        │
                        CVE_FINDING node.properties = {severity, kev, epss_score}   (C1)
                                        │
        _Group.worst/kev/max_epss ─ AttackPath.kev/epss ─ leaf_probability(sev, kev, epss)   (C5, live)
                                        │
                        route_p ≥ 0.9 for KEV  ⇒  KEV path outranks non-KEV at equal severity
```

## Error handling

- `epss_scores`/`kev_cve_ids` `None` or missing a CVE → node simply carries no such property; the
  detector default (`False`/`None`) applies. Never raise on a missing enrichment (best-effort, matches
  `normalizer.py`'s existing contract).
- Writer stays inert with no `semantic_store` (unchanged). Pipeline feeder try/except degrade-not-abort
  (unchanged).

## Testing (all through the REAL writer — this is the anti-regression that #801 lacked)

- **Writer unit:** `record_scan_results` with `kev_cve_ids={CVE-A}` + `epss_scores={CVE-A: 0.97}` →
  the CVE-A node has `properties["kev"] is True` and `properties["epss_score"] == 0.97`; a CVE not in
  either map has neither. (Proves C1 + that the property KEYS match what detectors read.)
- **Ranking through the writer:** build a graph via `record_scan_results` (NOT hand-planted
  properties) with one KEV CVE and one non-KEV CVE of equal severity on two equivalent exposed
  workloads → `find_all()` → `rank_by_expected_loss` → the KEV path ranks first. Replace/augment
  #801's hand-planted `kev_listed` test so a future key drift FAILS. (Proves C1+C4+C5 end-to-end.)
- **Pipeline e2e:** `scan_run` with `ScanSources(vuln_image_refs=…, vuln_kev_cve_ids={…})` →
  `res.confirmed` has the KEV workload's path with `.kev is True`. (Proves C2+C3 in the pipeline.)
- **Regression:** existing `test_probabilistic_ranking.py` / generic-engine KEV tests stay green
  (they use the `kev` key already; C4 aligns the named detectors to them, not away).
- Env synced with `uv sync --all-packages --all-extras`; `uv run mypy` + `uv run ruff check` +
  `uv run pytest packages/agents/vulnerability packages/agents/meta-harness packages/runtime -q` clean.

## Build sequence

1. **C1** — writer `epss_scores` param + stamp `epss_score` (+ writer unit test). (S)
2. **C4** — 6 reader sites `kev_listed` → `kev` (+ the ranking-through-the-writer test that would fail
   under the old key). (S)
3. **C2** — `run()` threads `kev_cve_ids` + `epss_scores` (injected params; live reuse of existing
   enrichment). (M)
4. **C3** — `ScanSources` seam + vuln feeder wiring + pipeline e2e. (S–M)
5. **Close** — coverage doc: note KEV/EPSS now live end-to-end + the #801 honesty correction;
   whole-branch review of the folded #801.

## Out of scope (parked)

- sink_id / blast changes (honest floors above).
- A standalone EPSS _feed_ wiring in the pipeline beyond reusing the agent's existing enrichment —
  the offline-injectable seam + live reuse is sufficient; a dedicated pipeline EPSS collector is
  needs-collection and not required to make the ranking real.
- Live-cloud / live-network emission stays gated (unchanged).
