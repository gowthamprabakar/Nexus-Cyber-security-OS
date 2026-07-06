# Cycle 3: Productize the Moat — Durable ATTACK_PATH Node + OCSF 2005 Emission — Design

**Date:** 2026-07-06
**Branch:** `feat/cycle3-moat-productization` (off updated main `a2c658e5`, which includes #801's expected-loss ranking)
**Status:** design APPROVED by operator (OCSF 2005; RDS→PII deferred to Cycle 4; branched off main after #801 merged)

## Goal

Make the moat — the ranked cross-agent attack paths — **durable, cross-scan-trackable, and exportable**.
Today `analyze` returns `list[AttackPath]` that dead-ends at Markdown/JSON at the CLI (scan.py:53-57;
cli.py render). It is never persisted as a graph node and never emitted as an OCSF finding, so it
cannot be tracked run-over-run, queried, or consumed by a SIEM. This cycle persists each ranked
`AttackPath` as an `ATTACK_PATH` node and emits it as an OCSF 2005 Incident Finding, and deepens two
commodity detectors into real cross-agent combos.

## Background (deep-scope verified — mostly WIRING, not invention)

- **The vocabulary is pre-carved:** `NodeCategory.ATTACK_PATH` / `TOXIC_COMBINATION` /
  `BLAST_RADIUS_RECORD` (`charter/memory/graph_types.py:82-86`) + edges `CONTRIBUTES_TO` / `PART_OF_PATH`
  / `IN_BLAST_RADIUS` (`:175-177`). `ATTACK_PATH` is defined but **never written** (the deferred
  "decorations migration", `stage-3-rest-closed-2026-06-18.md:39,57`). This cycle is that migration.
- **The writer base + dedup exist:** `KnowledgeGraphWriterBase` (ADR-019, `kg_writer_base.py:38-101`);
  cross-run dedup is FREE (ADR-022: node upsert merges props `semantic.py:194-202`; edge UNIQUE index
  first-wins `:241-291`).
- **A near-verbatim template exists:** investigation's `ToxicCombinationWriter`
  (`investigation/toxic_combination.py:36-51`) already writes a `TOXIC_COMBINATION` node +
  `CONTRIBUTES_TO` edges for ONE archetype (public-data-exposure), with a deterministic key
  `_combo_external_id = "toxic:" + sha256(...)[:16]`. We generalize this to persist EVERY ranked
  `AttackPath` (the ranked `AttackPath` IS the fully-realized toxic combination; the narrow
  `ToxicCombination` dataclass — 3 fixed ids — is NOT the right payload).
- **`analyze` already has the ranked tuples:** `ranked = rank_by_expected_loss(confirmed, store,
tenant_id)` (scan.py:54) is `list[(AttackPath, expected_loss, blast)]`, immediately reduced to
  `confirmed = [t[0] for t in ranked]` (:55) — dropping `expected_loss`. We consume `ranked` (with
  `expected_loss`) before the reduction.
- **OCSF pattern exists:** investigation emits **class_uid 2005 Incident Finding**
  (`investigation/schemas.py:49`); the builder template is `aispm/schemas._base_payload`
  (`aispm/schemas.py:126-175`) → OCSF v1.3 skeleton (`category_uid=2`, `class_uid`, `finding_info.uid/
types/first_seen_time/last_seen_time`, `resources`, `evidences`) wrapped in `NexusEnvelope`. Bus
  publish is optional/best-effort (`investigation/bus_emit.py:11-13`).

## Approved decisions

- **OCSF class = 2005 (Incident Finding).** A ranked attack path is a _correlated incident_ (not a
  single-control 2003 compliance or single-signal 2004 detection). Precedented for toxic-combos
  (`investigation/schemas.py:1-19`). NO 2001 "Security Finding" class exists in the fleet taxonomy — do
  not invent one. Discriminator `finding_info.types[0] = "attack_path_<path_type>"` (ADR-020 convention).
- **public-RDS→PII deepening DEFERRED to Cycle 4.** It needs a NEW producer (`record_rds_instances`
  writes the node only — no RDS→`DATA_CLASSIFICATION` edge exists; `cloud_posture/tools/kg_writer.py:
215-222`). That is collection wiring, not productization. (Cycle 4 first checks data-security
  `db_classify.py`.)

## Architecture

### P1 — `AttackPathWriter` (persist ranked paths as ATTACK_PATH nodes)

New `packages/agents/meta-harness/src/meta_harness/attack_path_writer.py`:
`AttackPathWriter(KnowledgeGraphWriterBase)` (mirror `ToxicCombinationWriter`). Method
`persist(ranked: Sequence[tuple[AttackPath, float, int]]) -> list[dict]` (returns the OCSF findings, P2):

- Per `(path, expected_loss, blast)`:
  - `external_id = "attackpath:" + sha256(f"{path.path_type}|" + "|".join(sorted(path.entities)))[:16]`
    — the ranker's own grouping subject (`attack_paths.py:245`), so "the same path" collapses run-over-run.
  - `upsert_node(NodeCategory.ATTACK_PATH, external_id, props)` with props: `path_type, severity,
expected_loss, blast_radius, title, evidence` (tuple→list), `sink_id, count, kev, epss,
entities` (tuple→list), `last_seen` (a timestamp passed in by the caller — scan.py/scan_run stamps
    it; scripts can't call Date.now, so the caller supplies `now`), and **`first_seen` written ONLY IF
    the node does not already exist** (upsert merge is later-wins → would clobber; read the node first via
    `get_entity` and set `first_seen=now` only when absent, else preserve).
  - `add_edge(entity, node_id, EdgeType.CONTRIBUTES_TO)` from each id in `path.entities`
    (`toxic_combination.py:45-50` pattern). Optional `PART_OF_PATH` to `sink_id` when set.
- Inert when `semantic_store is None` (base contract) — but in `analyze` the store is always present, so
  gating is via the `persist` flag (P3), not None.

### P2 — OCSF 2005 emission

New `packages/agents/meta-harness/src/meta_harness/ocsf_attack_path.py`: `build_incident_finding(path,
expected_loss, blast, *, tenant_id, now) -> dict` — an OCSF v1.3 Incident Finding (class_uid 2005,
category_uid 2), mirroring `aispm/schemas._base_payload` shape:

- `finding_info.uid` = the same `attackpath:<hash>` external*id (stable, so a SIEM dedups too);
  `finding_info.types = ["attack_path*<path_type>"]`; `finding_info.title = path.title`;
`first_seen_time`/`last_seen_time`.
- `severity_id` mapped from `path.severity` (the fleet's severity→id map — reuse the existing helper if
  one exists; else the standard OCSF 1..6 bands); a custom `risk_score`/`confidence` = `expected_loss`.
- `resources` = each `path.entities` id (type_uid/uid); `evidences` = `path.evidence` (CVE ids / data
  types) + the `sink_id`. NO plaintext secrets (evidence is ids/types only — matches the security
  invariant).
- Wrap in `NexusEnvelope` (agent_id="meta-harness") like the other emitters. `persist` returns the list;
  the CLI/scan_run decides where to write them (findings file) — bus publish is a later/optional wire,
  NOT in this cycle.

### P3 — wire into `analyze` (flag-gated) + `scan_run`

- `analyze(store, tenant_id, *, suppressed=..., persist: bool = False, now: datetime | None = None)`.
  When `persist=True`: after `ranked = rank_by_expected_loss(...)`, call
  `findings = await AttackPathWriter(store, tenant_id).persist(ranked, now=now or <caller-required>)`.
  Attach `findings` to the result. Default `persist=False` → **zero side-effects** (CLI + every existing
  test that calls `analyze` is byte-unaffected — this is the safety guard).
- `ScanResult` gains `ocsf_findings: list[dict] = field(default_factory=list)` (empty unless persisted).
- `scan_run` (`scan_pipeline.py`) calls `analyze(..., persist=True, now=<stamped>)` so the pipeline
  persists + collects findings; expose them on `ScanRunResult` (new `ocsf_findings` field) so the
  operator/exporter can consume them. (`now` is threaded from the caller — scripts/tests pass an explicit
  timestamp; production stamps `datetime.now(UTC)` at the scan_run boundary.)

### P4 — deepen 2 commodity detectors (offline-provable NOW)

Two new NAMED detectors (the deep siblings' data already lands in `scan_run`):

- **`find_rbac_escalation_to_cloud_data`** — a cluster-**admin** SA (`find_rbac_privilege_escalation`'s
  `is_admin` BINDS) that ALSO reaches cloud data via the `k8s_escape_to_cloud_data` chain
  (`USES_SERVICE_ACCOUNT → IRSA_MAPPING → HAS_ACCESS_TO → EXPOSES_DATA`). Intersection of two shapes
  that already run (`kg_query.py:903,1117`); all legs written offline (k8s ClusterReader seam). Severity
  ≥ `rbac_privilege_escalation`, ≤ `k8s_escape_to_cloud_data` (82).
- **`find_exposed_kms_key_over_data`** — a **public** KMS key (`find_exposed_kms_key`'s `is_public`) that
  ALSO `EXPOSES_DATA` (the leg `find_kms_key_access` already reads, written by
  `record_kms_protected_data`, `cloud_posture/tools/kg_writer.py:197-213`). Turns "public key policy"
  (sev 72) into "public key over classified data." Both legs offline-provable now.

Each is a full new named path_type — **apply the Cycle-2 REGISTRATION CHECKLIST**: `_SEVERITY` + `_title`

- `find_all` (attack_paths.py); `_OUT_OF_MODEL` (test_path_taxonomy); `REMEDIATION` + `_FIX`
  (attack_path_remediation.py); `_INTERNET_FACING` + `_generic_path_type` + `_generic_title`
  (report_card.py); `_LABELS` (attack_path_report.py). Consider subsuming the shallow parent
  (`exposed_kms_key` / `rbac_privilege_escalation`) for the same subject when the deep combo fires (mirrors
  crown_jewel / SBOM subsume) — so a public-KMS-over-data isn't ALSO shown as a bare exposed-kms-key.

## Components

- `meta-harness/.../attack_path_writer.py` — `AttackPathWriter` (P1) — NEW.
- `meta-harness/.../ocsf_attack_path.py` — `build_incident_finding` (P2) — NEW.
- `meta-harness/.../scan.py` — `analyze` `persist`/`now` params + `ScanResult.ocsf_findings` (P3).
- `runtime/.../scan_pipeline.py` — `scan_run` calls `analyze(persist=True)`; `ScanRunResult.ocsf_findings` (P3).
- `meta-harness/.../kg_query.py` + `attack_paths.py` (+ report_card / remediation / report / taxonomy) —
  2 new detectors + full registration (P4).
- `docs/strategy/operating-path-detector-coverage.md` — moat-productization note + 2 rows.

## Cross-scan identity + dedup

`external_id = "attackpath:" + sha256(path_type | sorted(entities))[:16]` → same path = same node
run-over-run (ADR-022 node upsert). `CONTRIBUTES_TO` edges dedup via the UNIQUE index (re-emit = no-op).
`first_seen` set-once (conditional write); `last_seen` overwritten each scan. The OCSF `finding_info.uid`
= the same key so downstream SIEMs dedup too.

## Error handling / security

- `persist=False` default → no behavior change for any existing caller (the guard).
- Writer inert with no store; persist total (never drops a path); a malformed path never aborts the scan
  (best-effort per-path, like `normalizer`).
- OCSF evidence = ids / CVE ids / data-types ONLY — no plaintext secrets (security invariant); the
  AWS-AKIA-only cleartext rule is unaffected (attack paths carry no secret material).
- Bus publish is NOT wired this cycle (filesystem/graph is the contract); OCSF findings are returned for
  the caller to persist.

## Testing (through `scan_run` — the durability proof)

- **P1/P3 e2e:** `scan_run(persist=True)` on a scene that forms a confirmed path → assert an
  `ATTACK_PATH` node exists (stable key) with `path_type`/`expected_loss`/`first_seen`/`last_seen` +
  `CONTRIBUTES_TO` edges from its entities. Run `scan_run` TWICE → assert the SAME node (no duplicate),
  `first_seen` unchanged, `last_seen` bumped (cross-scan dedup proof).
- **P2:** `build_incident_finding` → a valid OCSF 2005 dict (class*uid 2005, category_uid 2, types[0]
  `attack_path*<pt>`, uid == node key, no plaintext); `scan_run(persist=True)` returns findings.
- **P3 guard:** `analyze(persist=False)` (default) writes NO `ATTACK_PATH` node — existing analyze tests
  unaffected (assert count of ATTACK_PATH nodes == 0).
- **P4:** kg_query unit (each deep detector fires on its intersection; the shallow-only case does NOT
  fire the deep one) + scan_run e2e (the deep combo forms + subsumes the shallow parent).
- Env synced `uv sync --all-packages --all-extras`; whole-repo `uv run mypy` + `uv run ruff check` +
  `uv run pytest packages/agents/meta-harness packages/runtime -q` clean; **full suite + `packages/charter`
  guard before close** (Cycle-1 lesson).

## Build sequence

1. **P1** — `AttackPathWriter` + node model + stable key + first_seen-conditional (+ writer unit). (M)
2. **P2** — `build_incident_finding` OCSF 2005 (+ schema unit). (M)
3. **P3** — `analyze` persist flag + `ScanResult.ocsf_findings` + `scan_run` wiring + cross-scan e2e. (M)
4. **P4a** — `find_rbac_escalation_to_cloud_data` + full registration + subsume + tests. (M)
5. **P4b** — `find_exposed_kms_key_over_data` + full registration + subsume + tests. (M)
6. **Close** — coverage doc + whole-branch review + full-suite/charter guard.

## Out of scope (parked, honest)

- **public-RDS→PII** deepening (needs new RDS data-classification producer) → Cycle 4.
- **Bus/JetStream publish** of the OCSF findings (filesystem/graph is the contract this cycle).
- **`BLAST_RADIUS_RECORD`** node (the other deferred decoration) — not needed for the moat's
  durability/export; leave for a later pass.
- Multi-cloud parity (native Azure-MI/GCP-SA, Azure/GCP host-vuln) → Cycle 4.
