# Posture Rollup — Aggregation Layer Design

**Date:** 2026-07-08 · **Status:** approved shape, pre-plan
**Branch:** `feat/posture-rollup`

## Goal

Turn data the scan **already** puts in the knowledge graph into **board/dashboard data** — a
per-scan posture summary (severity distribution, per-domain scorecards, a domain×severity heatmap
matrix, an exposure→vulnerable→exploitable funnel, inventory counts, and cross-scan trends). No new
collection, no frontend. This is the single highest-leverage product-surface gap: it moves the
design's Overview, inventory-overview, heatmap, ASM-funnel, and trends pages from "no producer"
(🔴/🟡) toward "backed by real data" (🟢), and lifts every persona's backend-readiness at once.

## Non-goals (YAGNI / deferred)

- **No frontend.** Output is a JSON artifact + a CLI markdown section; a future UI/API consumes the JSON.
- **No OCSF export of posture.** Posture is a rollup, not a finding. (Deferred; revisit if a SIEM needs it.)
- **No new graph node.** Posture is not persisted as a KG node/edge. Cross-scan trend snapshots use the
  existing **episodic-memory** table (separate from the graph), not new node types.
- **No per-finding-severity heatmap.** Raw finding nodes store severity inconsistently per domain; v1
  aggregates the **clean attack-path severities** + node-category counts. A finding-severity heatmap is a
  documented follow-up.

## Architecture

A new module `packages/agents/meta-harness/src/meta_harness/posture.py` with three clear units:

1. **`PostureRollup(store, tenant)` — pure reader/computer.** Reads the post-scan graph (via
   `store.list_entities_by_type(...)` and the already-ranked `AttackPath`s) and returns a frozen
   `PostureSummary`. No writes, no side effects. Tenant-scoped by construction (mirrors `KgQuery` /
   `KnowledgeGraphWriterBase`).
2. **`render_posture_summary(summary) -> str` — pure renderer.** Markdown section for the CLI report
   (sibling to `report_card.render_report_card`).
3. **Persistence (two explicit, best-effort functions):**
   - `write_posture_json(summary, workspace_root) -> Path` → `workspace_root/aggregation/posture.json`.
   - `emit_posture_snapshot(store, tenant, summary, now)` → appends one episodic-memory row
     (`action="posture_snapshot"`, compact payload) so trends accrue across scans.
   - `posture_trend(store, tenant) -> list[TrendPoint]` → reads snapshots ordered by time.

Separation matters: **compute is pure and unit-testable in isolation**; rendering and persistence are
independent and individually testable. Consumers can compute a summary without touching disk or the
episode table.

## Data flow (the scan hook)

In `packages/runtime/src/nexus_runtime/scan_pipeline.py`, `scan_run(...)` already calls
`analyze(store, tenant, persist=True, now=...)` (≈ line 655) which produces ranked `AttackPath`s and
OCSF findings. Immediately after, add a **best-effort** rollup step:

```
scan_result = await analyze(store, tenant, persist=True, now=now)          # existing
# --- new, non-fatal: a rollup failure must NOT fail the scan ---
try:
    summary = await PostureRollup(store, tenant).compute(now=now)
    write_posture_json(summary, workspace_root)
    await emit_posture_snapshot(store, tenant, summary, now=now)
except Exception:
    log.warning("posture rollup failed; scan output unaffected", exc_info=True)
```

The primary scan deliverable (attack paths + OCSF) is unchanged and authoritative; the rollup is an
additive, isolated, non-fatal step. `ScanRunResult` gains one optional field
`posture: PostureSummary | None` so callers/tests can assert on it without re-reading disk.

## Data model

```python
SEVERITY_BUCKETS = {"critical": (90, 100), "high": (75, 89), "medium": (50, 74), "low": (0, 49)}

@dataclass(frozen=True, slots=True)
class DomainCount:            # one row of the per-domain scorecard AND the heatmap matrix
    domain: str              # "vulnerability" | "identity" | "data" | "cloud" | "container" | "appsec" | ...
    critical: int
    high: int
    medium: int
    low: int
    total: int

@dataclass(frozen=True, slots=True)
class PathTypeCount:
    path_type: str           # e.g. "crown_jewel", "internet_exposed_vulnerable"
    count: int
    max_severity: int

@dataclass(frozen=True, slots=True)
class ExposureFunnel:
    exposed: int             # internet-exposed workloads/resources on any path
    vulnerable: int          # of those, carrying a CVE
    kev: int                 # of those, on a CISA-KEV path
    exploitable: int         # of those, EPSS > EPSS_EXPLOITABLE (0.5)

@dataclass(frozen=True, slots=True)
class PostureSummary:
    tenant: str
    scan_at: str                          # ISO-8601
    totals: dict[str, int]                # attack_paths = len(ranked paths); findings = sum of finding-category
                                          #   counts (CVE+misconfig+secret+data); nodes = all entities for the tenant
    severity_distribution: dict[str, int] # {"critical","high","medium","low"} — distribution of ATTACK PATHS by
                                          #   severity bucket (clean int severities), not raw findings
    by_domain: tuple[DomainCount, ...]    # scorecard rows == heatmap (rows=domain, cols=severity)
    by_path_type: tuple[PathTypeCount, ...]
    exposure_funnel: ExposureFunnel
    inventory_counts: dict[str, int]      # NodeCategory.value -> count (resources, identities, datastores, images, ...)
    top_paths: tuple[dict, ...]           # worst-N: {path_type, severity, title, kev, epss}

@dataclass(frozen=True, slots=True)
class TrendPoint:
    at: str                               # ISO-8601 of the snapshot
    attack_paths: int
    critical: int
    high: int
```

**Severity bucketing:** attack-path `severity` is an int 0–100 (from `attack_path_writer` props). Buckets
above. Single source of truth: a `bucket_of(severity:int) -> str` helper.

**Domain mapping:** a `PATH_DOMAIN: dict[str, str]` maps each `path_type` to a product domain (e.g.
`crown_jewel→data`, `internet_exposed_vulnerable→vulnerability`, `rbac_escalation_to_cloud_data→identity`,
`k8s_escape_to_cloud_data→container`, `public_secret→identity`, `exposed_kms_key→data`, …). The plan
enumerates the full map against the live `path_type` list; an unmapped type falls back to domain
`"other"` (and the test asserts no live path_type lands in `"other"`, so the map stays complete).

**Inventory counts:** count these `NodeCategory` values via `store.list_entities_by_type`:
`CLOUD_RESOURCE, IDENTITY, DATA_CLASSIFICATION, CVE_FINDING, MISCONFIGURATION_FINDING, SECRET_FINDING`
(+ container/k8s/repo/sbom categories that exist in `graph_types`). The plan confirms exact enum members.

## Trends

Cross-scan durability without a new graph node: `emit_posture_snapshot` appends one **episodic-memory**
row per scan (`action="posture_snapshot"`, payload = `{severity_distribution, totals, at}`).
`posture_trend` reads rows for the tenant ordered by `emitted_at` and returns `TrendPoint`s.

- First scan → one point (or empty history) — **honest**; trends render "insufficient history".
- The plan locates the episodic-memory append path (`charter.memory`, `EpisodeModel`). If no clean writer
  exists, that is a plan-level decision surfaced to the human — **not** silently worked around.

## Error handling

- **Non-fatal in the pipeline:** the scan hook wraps the rollup in try/except; a failure logs a warning
  and leaves the scan's authoritative output (paths + OCSF) intact.
- **Empty / single-tenant no-op graph:** `compute` on an empty graph returns a fully-zeroed
  `PostureSummary` (all counts 0, empty tuples) — never raises.
- **Missing/odd properties:** a node missing `severity` is bucketed by an explicit default rule (documented),
  never a crash.

## Testing

- **Unit — `compute` (pure):** build a fixture `SemanticStore` with a known set of attack-path nodes +
  category nodes; assert **exact** `severity_distribution`, `by_domain`, `by_path_type`,
  `exposure_funnel`, `inventory_counts`, `totals`.
- **Unit — empty graph:** `compute` returns the all-zero summary without raising.
- **Unit — `render_posture_summary`:** asserts the markdown contains the headline totals + one domain row +
  the funnel line (not just "renders without error").
- **Unit — domain map completeness:** every live `path_type` maps to a real domain (none fall to `"other"`).
- **Unit — trends:** two synthetic snapshots → `posture_trend` returns two ordered `TrendPoint`s;
  zero snapshots → empty.
- **Integration — scan pipeline:** run `scan_run` on an existing fixture scenario; assert
  `posture.json` is written and well-formed, `ScanRunResult.posture` is populated, and — with an injected
  rollup failure — the scan still returns its paths/OCSF (non-fatal proven).

## Files

- **Create:** `packages/agents/meta-harness/src/meta_harness/posture.py` (compute + model + render + persist + trend)
- **Create:** `packages/agents/meta-harness/tests/test_posture.py` (unit + render + trend + domain-map)
- **Modify:** `packages/runtime/src/nexus_runtime/scan_pipeline.py` (best-effort hook; `ScanRunResult.posture`)
- **Modify:** `packages/runtime/tests/…` (integration assertion + non-fatal proof)
- **Modify (optional):** the CLI report path to append `render_posture_summary` output

## Invariants honored

Tenant-scoped constructor (no per-call tenant); typed `NodeCategory` reads; **counts/categorical only —
no plaintext** in `posture.json` or snapshots; compute is read-only; persistence is explicit, tenant-scoped,
and best-effort. `uv run mypy` (no path args) + `uv run pytest` green to match CI; husky clean, no `--no-verify`.
