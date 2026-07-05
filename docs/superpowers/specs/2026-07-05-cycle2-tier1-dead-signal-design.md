# Cycle 2: Tier 1 Dead-Signal — Lateral Movement + SBOM + Sensitive-Resource Sink — Design

**Date:** 2026-07-05
**Branch:** `feat/cycle2-tier1-dead-signal` (new, off clean main — Cycle 1 is in the held #801, separate)
**Status:** design — scope approved by operator (lateral + SBOM + sink; MEMBER_OF + ATTACHED_TO dropped as redundant)

## Goal

Light up two high-value **written-but-unread** edges as first-class attack paths in `scan_run`, and add
the sink that makes the highest-value variant land:

1. **Lateral movement** — `CAN_REACH` / `PEERED_WITH` (derived network reachability from security-group /
   VPC-peering config). Genuinely NEW detection: these edges are **not written in `scan_run` today**
   (`network_threat.run()` only calls `record_flows`, never `record_reachability`).
2. **SBOM supply-chain** — `CONTAINS_PACKAGE` (image → vulnerable dependency). The edge already lands in
   `scan_run` (vuln `run()` writes it) and the generic engine already produces the candidate; this cycle
   promotes it to a **named** detector for first-class ranking + package-level remediation attribution.
3. **`sensitive_resource` sink** — a managed datastore (rds-instance / kms-key) as an impact node, so a
   lateral pivot that reaches a database counts as impact (not only a pivot that reaches a CVE).

Out of scope (deep-scoped as redundant — see the honest correction below): **MEMBER_OF** and
**ATTACHED_TO** IAM detectors, and `POD_CAN_REACH` (live-cluster-only, no offline feed).

## The honest scoping (no lipstick)

- **MEMBER_OF / ATTACHED_TO dropped.** The identity driver's `_synthesize_admin_grants`
  (`identity/agent.py:472-490`) already folds a user's **group-inherited admin** into an
  `EffectiveGrant` on the _user_ node → `HAS_ACCESS_TO` every resource → existing
  `find_fine_grained_data_exposure` already fires. A group-membership detector re-detects what's already
  detected. The only real gap (non-admin group-inherited access in the default path) is an
  effective-grants-simulator concern, not a dead-signal-edge detector. Building either would be
  scaffolding-that-adds-no-detection.
- **SBOM is naming, not new detection.** `find_internet_exposed_vulnerable_workload` already flags the
  workload via `image –VULNERABLE_TO→ CVE`; the SBOM path (`image –CONTAINS_PACKAGE→ pkg –VULNERABLE_TO→
CVE`) reaches the same CVE with **package granularity**. Value = actionable "upgrade package X"
  remediation + first-class ranking (vs a capped generic candidate). Honest and worth it, but not a new
  breach class.
- **Lateral movement is the genuinely-new core.** Its edges are dark in `scan_run`; the seam makes a real
  new attack class (public foothold → pivot to a private/peered vulnerable host or datastore) fire.

## Background (file:line verified)

- **Reachability compute is pure + injectable** (`network_threat/tools/reachability.py`):
  `reach_grants(instances: tuple[NetworkInstance,...], security_groups: tuple[SecurityGroup,...])` →
  `list[(src,dst,"lateral_sg",via)]`; `peering_reach_grants(instances: tuple[VpcInstance,...],
peerings: frozenset[frozenset[str]])` → `list[(src,dst,"vpc_peering",via)]`. Dataclasses:
  `NetworkInstance(resource_id, security_group_ids)`, `SecurityGroup(group_id, ingress)`,
  `IngressRule(protocol, from_port, to_port, source_sgs)`, `VpcInstance(resource_id, vpc_id)`.
- **Writers exist but are unwired from `run()`:** `record_reachability(grants)` → `CAN_REACH`,
  `record_peering_reachability(grants)` → `PEERED_WITH` (`network_threat/kg_writer.py:56,72`).
  `network_threat.run()` calls only `record_flows` (`agent.py:241`); no reach/SG/instance param exists.
- **Edges already traversable:** `CAN_REACH` (path_taxonomy.py:120), `PEERED_WITH` (:122),
  `CONTAINS_PACKAGE` (:123) are all in `TRAVERSABLE_EDGES`.
- **SINK_MARKERS** (path_taxonomy.py:90-95): `sensitive_data`/`known_vulnerability`/`ai_model`/
  `saas_tenant` — **no managed-datastore sink.** `SOURCE_MARKERS` has `public_resource`
  (CLOUD_RESOURCE `is_public=True`) — the foothold.
- **The full SBOM chain is offline-provable via existing seams:** `ScanSources.vuln_image_refs` (writes
  image + `CONTAINS_PACKAGE` + `VULNERABLE_TO`) + `ScanSources.cloud_ecs_workloads`
  (`EcsWorkload{image_ref, is_public}` → `RUNS_IMAGE` on the same image key; EC2 does NOT write
  RUNS_IMAGE — use ECS).

## Architecture

### P1 — network-topology seam (makes CAN_REACH / PEERED_WITH land in `scan_run`)

**P1a.** `network_threat.run()` gains injectable params (mirror cloud-posture's `ec2_workloads` seam):
`network_instances: Sequence[NetworkInstance] | None`, `security_groups: Sequence[SecurityGroup] | None`,
`vpc_instances: Sequence[VpcInstance] | None`, `vpc_peerings: frozenset[frozenset[str]] | None`. In the
`semantic_store is not None` path: when SG inputs present, `record_reachability(reach_grants(...))`; when
peering inputs present, `record_peering_reachability(peering_reach_grants(...))`. The live
`describe-security-groups` reader stays the operator-gated follow-on (unchanged); the flow path
(`record_flows`) is untouched.

**P1b.** `ScanSources` gains `network_instances` / `network_security_groups` / `network_vpc_instances` /
`network_vpc_peerings`; the network-threat feeder passes them to `run()`. Feeder `needed` predicate adds
"or any network-topology source set" (today it gates only on `network_vpc_flow_feed`). `None` → unchanged.

### P2 — `sensitive_resource` sink marker

Add to `SINK_MARKERS`: `NodeMarker("sensitive_resource", NodeCategory.CLOUD_RESOURCE, lambda p:
p.get("kind") in {"rds-instance", "kms-key"})`. A managed datastore is impactful to _reach_ even when not
itself public (distinct from `find_exposed_database`/`find_exposed_kms_key`, which flag a _public_ one).
This lets the generic engine emit `public_resource –CAN_REACH/PEERED_WITH→ … → sensitive_resource`.

### P3 — named lateral-movement-via-reachability detector

New `KgQuery.find_lateral_movement_via_reachability` (`kg_query.py`): a `public_resource` foothold that
`CAN_REACH` or `PEERED_WITH` a target, where the target either `VULNERABLE_TO` a CVE **or** is a
`sensitive_resource` (kind rds/kms). Distinct from the existing `find_lateral_movement_to_vulnerable_host`
(which uses **observed** `COMMUNICATES_WITH`) — this is **derived/proactive** (config-based, fires before
any traffic), so it is a separate detector with its own confidence, not an extension. Wire into
`AttackPathRanker.find_all` (grouped by foothold+target), add `_SEVERITY["lateral_reachable"]`, add a
`_title` branch. Severity below the observed-flow lateral (derived = potential, not confirmed traffic).

### P4 — named SBOM supply-chain detector

New `KgQuery.find_supply_chain_sbom` (`kg_query.py`): `CLOUD_RESOURCE{is_public} –RUNS_IMAGE→ image
–CONTAINS_PACKAGE→ SBOM_PACKAGE –VULNERABLE_TO→ CVE`. Evidence rolls up the vulnerable **package name(s)**
(the remediation delta over `find_internet_exposed_vulnerable_workload`). Wire into `find_all`,
`_SEVERITY["supply_chain_sbom"]`, `_title`. To avoid a duplicate row for the same workload already shown
as `internet_exposed_vulnerable`, SUBSUME per-workload (same pattern crown_jewel uses to subsume its
constituent legs) — the SBOM path is the more specific framing when package data exists.

## Components

- `network-threat/src/network_threat/agent.py` — `run()` seam (P1a).
- `runtime/src/nexus_runtime/scan_pipeline.py` — `ScanSources` fields + network feeder (P1b).
- `meta-harness/src/meta_harness/path_taxonomy.py` — `sensitive_resource` sink (P2).
- `meta-harness/src/meta_harness/kg_query.py` — `find_lateral_movement_via_reachability` (P3) +
  `find_supply_chain_sbom` (P4).
- `meta-harness/src/meta_harness/attack_paths.py` — `find_all` wiring, `_SEVERITY`, `_title` for both.
- `docs/strategy/operating-path-detector-coverage.md` — two new rows + honest notes.

## Data flow / join keys

- **Lateral:** `NetworkInstance(resource_id=<instance ARN/id>)` must key on the SAME node id
  cloud-posture wrote `is_public` on (so the foothold is a `public_resource` source and the target is the
  reached instance). `reach_grants` emits only when the referenced source SG is actually held by an
  instance (no dangling edges).
- **SBOM:** `EcsWorkload.image_ref` == the vuln scan's image key (`_artifact_name`), so `RUNS_IMAGE` and
  `CONTAINS_PACKAGE` share the image node.

## Error handling

P1 feeder follows the try/except degrade-not-abort contract; `None` topology sources skip it. P3/P4
detectors are read-only queries; empty graph → empty list. Named-detector ranking stays total.

## Testing (all through `scan_run` + `ScanSources` — the offline-provable bar)

- **P3 lateral-to-vuln-host e2e:** inject `network_instances` (a public foothold + a private host in the
  same SG-reachable set) + `security_groups` + `vuln_image_refs`/host-CVE so the private host is
  `VULNERABLE_TO` a CVE → `scan_run` → a `lateral_reachable` confirmed path forms. RED before P1+P3.
- **P3 lateral-to-datastore e2e:** foothold `CAN_REACH` a private `rds-instance` node → after P2 the
  path reaches the `sensitive_resource` sink → confirmed path. (Proves P2 + the datastore variant.)
- **P3 peering e2e:** two instances in different but peered VPCs (`network_vpc_instances` +
  `network_vpc_peerings`) → `PEERED_WITH` lateral path.
- **P4 SBOM e2e:** `cloud_ecs_workloads=(EcsWorkload(image_ref=img, is_public=True),)` +
  `vuln_image_refs=(img,)` → `scan_run` → a `supply_chain_sbom` confirmed path naming the vulnerable
  package; assert it SUBSUMES the plain `internet_exposed_vulnerable` row for that workload (no double
  count).
- Unit: `network_threat.run()` seam calls the writers when topology injected; `sensitive_resource`
  marker matches rds/kms and not a plain resource.
- Env synced `uv sync --all-packages --all-extras`; `uv run mypy` (whole-repo) + `uv run ruff check` +
  `uv run pytest packages/agents/network-threat packages/agents/meta-harness packages/runtime -q` clean.
- **Full-suite guard (Cycle-1 lesson):** run `uv run pytest packages/charter` (structural guards) +
  the whole suite before close — new `run()` tool calls / taxonomy changes can trip cross-package
  invariants that scoped runs miss.

## Build sequence

1. **P2** — `sensitive_resource` sink marker (+ unit). Small, unblocks the datastore variant. (S)
2. **P1a** — `network_threat.run()` topology seam + writer calls (+ unit). (M)
3. **P1b** — `ScanSources` fields + network feeder. (S–M)
4. **P3** — `find_lateral_movement_via_reachability` + ranker + severity + title + e2es (vuln-host,
   datastore, peering). (M–L)
5. **P4** — `find_supply_chain_sbom` + ranker + severity + title + subsume + e2e. (M)
6. **Close** — coverage doc (2 rows + honest notes) + whole-branch review + full-suite/charter guard.

## Out of scope (parked, honest)

- MEMBER_OF / ATTACHED_TO detectors (redundant with effective-grants folding).
- `POD_CAN_REACH` K8s lateral (live-cluster-only; no offline feed).
- Live `describe-security-groups` / live VPC-peering readers (operator-gated, as with the flow reader).
- SG-refined peering (peering opens the VPC boundary; per-SG refinement across the peer is a follow-on).
