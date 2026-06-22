# Canonical Entity Resolution — Foundation — Design Spec

**Date:** 2026-06-22
**Branch:** `entity-resolution-foundation`
**Context:** The moat needs cross-agent correlation. Recon (2026-06-22) found that **four agents already key `CLOUD_RESOURCE` by canonical ARN** (cloud-posture, data-security, identity, multi-cloud-posture) — so their signals about the same resource already converge on one node (path 1 proved it REAL). But the convergence is _accidental_: no shared helper, no ADR, no test. This slice makes it **guaranteed and provable** — the keystone the ARN-joinable paths (1, 3, 4, 7, 8) rest on.

This slice is **mechanism ① (canonical keys)** only. Mechanism ② (bridge edges for the misfit agents — vulnerability by image-ref, network by IP) is a separately-scoped follow-up.

## Goal

Turn the accidental ARN convergence into a **guaranteed, tested foundation**: one shared canonical-ARN module every agent uses, an ADR codifying the convention, and a reusable cross-agent join test that proves two agents' independent writes about the same resource collapse to one node.

## Non-goals (explicit)

- Bridge edges (`RUNS_IMAGE`/`OWNED_BY`/`RUNS_ON`) for vuln/network/runtime misfits — follow-up.
- Migrating every agent's keys today — most ARN-group agents already comply; we centralize the helper and add the guarantee, not rewrite working code.
- New ARN builders nobody uses yet (YAGNI) — only the ones agents actually need now.

## Components

### 1. Shared canonical-ARN module — `charter/src/charter/canonical.py` (NEW)

The single source of truth for canonical resource identifiers. `charter` is the shared dependency every agent already has.

- Move `s3_bucket_arn(name) -> "arn:aws:s3:::{name}"` here from `data_security/canonical.py`.
- `data_security/canonical.py` re-exports from charter (`from charter.canonical import s3_bucket_arn`) so existing call sites keep working with no churn — single source of truth.
- Add a module docstring stating the convention + how to add a builder when a new resource type joins the spine.
- **Scope:** start with `s3_bucket_arn` (the only one in use). Do not speculatively add EC2/IAM/etc. builders — add each when an agent needs it (the ADR documents the rule; the module grows on demand).

### 2. ADR-023 — Canonical resource keys (NEW)

`docs/_meta/decisions/ADR-023-canonical-resource-keys.md`. Codifies:

- **The rule:** every agent keys `CLOUD_RESOURCE` (and infra nodes) by its **canonical cloud ARN**, built via `charter.canonical`. Same real resource → same `external_id` → same node (via `upsert_entity`'s `(tenant, type, external_id)` idempotency).
- **The ARN-joinable group** (cloud-posture, data-security, identity, multi-cloud-posture) — already compliant; cross-agent convergence guaranteed + tested.
- **The misfits** (vulnerability=image-ref, network=IP, runtime=host-uid) and the **mechanism ② bridge-edge plan** (`RUNS_IMAGE`, `OWNED_BY`, `RUNS_ON`) — documented as the deferred follow-up, with the data sources each needs.
- Supersedes the one-off `s3_bucket_arn` location; references ADR-018 (type catalogue) + ADR-019 (writer base).

### 3. Reusable cross-agent join test + assertion — `fleet_testkit` (NEW)

The template that proves _any_ future path actually joins.

- A reusable assertion in `packages/integration/src/fleet_testkit/` :
  `async def assert_single_node(store, *, tenant_id, entity_type, external_id)` — asserts exactly one node exists for that canonical key (count via `list_entities_by_type`).
- A cross-agent test driving the **real** ARN-group writers (cloud-posture `upsert_asset` + data-security `record` + identity `record_access`) about the **same** resource ARN → assert they converge to ONE `CLOUD_RESOURCE` node (extends the existing `test_entity_resolution.py` from path 1 to the full ARN trio).

## Data flow / how it guarantees convergence

`charter.canonical.s3_bucket_arn(name)` → every agent passes the identical canonical ARN as `external_id` → `SemanticStore.upsert_entity(tenant, "cloud_resource", arn)` is idempotent on that key → all agents' signals (is_public, EXPOSES_DATA, HAS_ACCESS_TO, VULNERABLE_TO-via-bridge-later) land on the **one** node → correlation queries traverse a joined graph.

## Testing

1. **Unit:** `charter.canonical.s3_bucket_arn` returns the canonical ARN; the data-security re-export resolves to the same function.
2. **Cross-agent convergence (the keystone test):** the 3 ARN-group writers, writing about one bucket ARN, produce exactly one `CLOUD_RESOURCE` node (`assert_single_node` == 1). Run against the in-memory store; the join is real, not asserted by construction.
3. **No regression:** data-security + the existing `test_entity_resolution` still green (the helper moved, behavior identical).

## Honest scope / deferred

- Mechanism ② bridges (vuln/network/runtime) — the genuinely-new work for paths 2/5/9 — captured in the ADR, built in a follow-up gated on the misfit feeders' data sources.
- Per-feeder REAL verification (cloud-posture, compliance) needed before the ARN-joinable paths (3/7/8) ship REAL — separate truth-audit work.
- Non-AWS canonical keys (Azure/GCP resource ids) — multi-cloud-posture already uses native ids; a provider-aware builder grows the module when needed.

## Constraints (carried)

- Additive; single source of truth (no duplicate ARN logic); no rewrite of compliant agents.
- Typed vocabulary (`NodeCategory`/`EdgeType`); tenant-scoped; the convergence proven by running, not by assertion-of-construction.
