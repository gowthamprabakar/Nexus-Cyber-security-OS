# ADR-023: Canonical resource keys for cross-agent entity resolution

**Status:** Accepted — 2026-06-22

## Context

Cross-agent correlation (the moat) requires that different agents' signals about the
SAME real-world resource land on the SAME graph node. A 2026-06-22 audit found four
agents already key `CLOUD_RESOURCE` by canonical cloud ARN — cloud-posture, data-security,
identity, multi-cloud-posture — so they already converge (path 1 proved it REAL). But the
convergence was _accidental_: no shared helper, no rule, no test, so it could silently
drift.

## Decision

**Every agent keys `CLOUD_RESOURCE` (and infra nodes) by its canonical cloud ARN**, built
via the single-source-of-truth module `charter.canonical`. Same real resource → same
`external_id` → same node, via `SemanticStore.upsert_entity` idempotency on
`(tenant, type, external_id)`. A reusable `fleet_testkit.assert_single_node` proves
convergence by _running_ the real writers (see
`packages/integration/src/fleet_testkit/tests/test_canonical_convergence.py`). References
ADR-018 (type catalogue), ADR-019 (writer base).

## The ARN-joinable group (compliant today)

cloud-posture (F.3), data-security (D.5, via `charter.canonical.s3_bucket_arn`), identity
(D.2), multi-cloud-posture (D.15). Unblocks attack paths 1, 3, 4, 7, 8 (see
`docs/strategy/attack-path-roadmap-to-northstar.md`).

## Mechanism ② — bridge edges (DEFERRED, the misfits)

Agents that key by something other than the resource ARN need a linking _edge_, not a key
change, because the canonical id is not knowable at write time:

- **vulnerability (D.1)** keys by image-ref/host-path → `RUNS_IMAGE` edge (image → workload
  ARN). Source: deployment / registry-to-workload mapping.
- **network-threat (D.4)** keys by IP → `OWNED_BY` edge (IP → instance ARN). Source:
  ENI / VPC metadata.
- **runtime-threat (D.3)** keys by host-uid → `RUNS_ON` edge (uid → instance ARN). Source:
  Falco/Tracee metadata or the K8s API.

Bridges unblock paths 2, 5, 9 and are built per-misfit when the linking data source is
verified REAL. Out of scope for this ADR's slice.

## Consequences

- One place to build resource ARNs; agents stop re-deriving them. The lone
  `data_security/canonical.py` helper became a thin re-export of `charter.canonical`.
- Cross-agent joins are guaranteed + test-enforced, not accidental.
- The bridge work for the misfit agents is explicit and tracked, not forgotten.
