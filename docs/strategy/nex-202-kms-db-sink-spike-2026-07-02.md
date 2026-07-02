# NEX-202 — KMS/DB-as-sink Spike (ADR) — SPIKE OUTPUT

**Timebox: 1 day. Deliverable: a design decision + a validating proof. Status: RESOLVED.**

## The feared problem

The deep seam analysis said "new sinks (KMS/DB) are blocked by the walker." Verified: `walk_paths` is a
recursive CTE that matches sinks by **entity-type category** (`d.entity_type IN :sinks`). KMS keys / RDS
are written as `CLOUD_RESOURCE`. So making them sinks looked like it needed either:
- a **CTE property predicate** (`properties->>'kind' IN (...)`) — breaks the SQLite/Postgres dialect
  portability the CTE guarantees, or
- a **distinct node category** (`KMS_KEY`) — orphans identity's `HAS_ACCESS_TO`→KMS edge (a convergence
  cascade), and breaks the existing `exposed_kms_key` named detector.

Both are ugly. Estimated as a risky substrate rewrite.

## The reframe (the decision)

**Reaching a KMS key or database that protects/holds sensitive data IS reaching the data.** So model it
with the EXISTING sink: write ``KMS-key/DB --EXPOSES_DATA--> DATA_CLASSIFICATION`` (the data the key
decrypts / the DB holds). The walk ``principal → HAS_ACCESS_TO → kms-key → EXPOSES_DATA → data``
terminates at the existing `sensitive_data` sink — **no walker change, no new category, no convergence
cascade.** The KMS/DB node stays `CLOUD_RESOURCE` (edges converge as before); only a new `EXPOSES_DATA`
edge is added.

## Proof

`test_kms_db_sink_spike_e2e.py` (both KMS and DB): a principal `HAS_ACCESS_TO` a `kind=kms-key` /
`kind=database` resource that `EXPOSES_DATA` → the named `fine_grained` detector surfaces the path
today. **Zero substrate change. PASSES.**

## Re-scoped implementation (NEX-202-IMPL → a DETECTION ticket, not a rewrite)

- **NEX-202a (detection)**: cloud-posture / data-security writes `EXPOSES_DATA` from a KMS key to the
  data it protects, and from a DB to the sensitive data it holds (sample-based, like S3). Bank + e2e.
- **NEX-202b (labels, optional/small)**: the report card / a named detector relabels a path whose
  penultimate node is `kind=kms-key` / `kind=database` as `kms_key_access` / `exposed_database` (the
  catalog family names), instead of the generic `fine_grained_data`. Cosmetic — the PATH already forms.

## Consequence for the deep-analysis gap list

The "new sinks blocked by the walker" item is **wrong** — it was never a walker problem. It downgrades
from a substrate landmine to a normal detection slice. Est: S+S, not L/XL. The `kms_key_access` and
`exposed_database` catalog families move from PLANNED toward BUILT once NEX-202a lands.
