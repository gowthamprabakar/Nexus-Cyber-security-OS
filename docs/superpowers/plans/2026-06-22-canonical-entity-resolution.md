# Canonical Entity-Resolution Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the accidental cross-agent ARN convergence into a guaranteed, tested foundation — one shared canonical-ARN module, an ADR, and a cross-agent join test that PROVES (by running) that independent agents' writes about the same resource collapse to one node.

**Architecture:** Move the lone `s3_bucket_arn` helper from `data_security` into a shared `charter.canonical` module (single source of truth); data-security re-exports it (no call-site churn). Add a reusable `fleet_testkit.assert_single_node` + a test driving the three real ARN-group writers (cloud-posture, data-security, identity) about one bucket ARN → exactly one `CLOUD_RESOURCE` node. Codify the convention in ADR-023.

**Tech Stack:** Python 3.12, `charter`, `fleet_testkit`, `charter.memory.SemanticStore`, pytest + pytest-asyncio.

## Global Constraints

- **Additive / single source of truth** — no duplicate ARN logic; do not rewrite compliant agents; the data-security re-export keeps existing call sites working unchanged.
- **YAGNI** — only `s3_bucket_arn` (the one in use). Do NOT add speculative EC2/IAM/etc. builders.
- **Convergence proven by running**, not by assertion-of-construction (drive the real writers).
- Typed vocabulary (`NodeCategory`); tenant-scoped. Commit lines ≤100 chars. Branch is `entity-resolution-foundation`.

---

## File Structure

| File                                                                         | Create/Modify | Responsibility                                                  |
| ---------------------------------------------------------------------------- | ------------- | --------------------------------------------------------------- |
| `packages/charter/src/charter/canonical.py`                                  | Create        | Shared canonical resource-ARN builders (single source of truth) |
| `packages/charter/tests/test_canonical.py`                                   | Create        | Unit test for the canonical ARN builder                         |
| `packages/agents/data-security/src/data_security/canonical.py`               | Modify        | Re-export from `charter.canonical` (no churn)                   |
| `packages/integration/src/fleet_testkit/__init__.py` + `assertions.py`       | Modify        | Add `assert_single_node` reusable assertion                     |
| `packages/integration/src/fleet_testkit/tests/test_canonical_convergence.py` | Create        | Cross-agent convergence keystone test                           |
| `docs/_meta/decisions/ADR-023-canonical-resource-keys.md`                    | Create        | Codify the convention + the deferred bridge plan                |

---

### Task 1: shared `charter.canonical` module + data-security re-export

**Files:**

- Create: `packages/charter/src/charter/canonical.py`
- Test: `packages/charter/tests/test_canonical.py`
- Modify: `packages/agents/data-security/src/data_security/canonical.py`

**Interfaces:**

- Produces: `charter.canonical.s3_bucket_arn(bucket_name: str) -> str` returning `f"arn:aws:s3:::{bucket_name}"`. data-security's `s3_bucket_arn` becomes a re-export of this (same callable).

- [ ] **Step 1: Write the failing test**

```python
# packages/charter/tests/test_canonical.py
"""Unit tests for the shared canonical resource-ARN builders."""

from charter.canonical import s3_bucket_arn


def test_s3_bucket_arn_is_canonical():
    assert s3_bucket_arn("acme-pii") == "arn:aws:s3:::acme-pii"


def test_data_security_reexports_the_same_callable():
    # Single source of truth: the agent helper IS the charter helper.
    from data_security.canonical import s3_bucket_arn as ds_s3
    from charter.canonical import s3_bucket_arn as charter_s3

    assert ds_s3 is charter_s3
```

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest packages/charter/tests/test_canonical.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'charter.canonical'`.

- [ ] **Step 3: Create the shared module**

```python
# packages/charter/src/charter/canonical.py
"""Canonical cross-agent resource identifiers — the fleet-graph join key (ADR-023).

Single source of truth: every agent keys its CLOUD_RESOURCE node by the canonical
cloud ARN built here, so independent signals about the same real resource collapse
onto ONE graph node (SemanticStore.upsert_entity is idempotent on
``(tenant, type, external_id)``). See ADR-023 for the convention and the deferred
bridge-edge plan for the misfit agents (vulnerability=image-ref, network=IP).

Add a builder here when a new resource type joins the spine — do not re-derive ARNs
in agent code.
"""
from __future__ import annotations


def s3_bucket_arn(bucket_name: str) -> str:
    """Canonical ARN for an S3 bucket: ``arn:aws:s3:::{bucket_name}``.

    # ponytail: S3-only. Other resource ARNs aren't name-derivable — add a
    # per-service builder here when a second resource type joins the spine.
    """
    return f"arn:aws:s3:::{bucket_name}"
```

- [ ] **Step 4: Re-export from data-security (single source of truth)**

Replace the body of `packages/agents/data-security/src/data_security/canonical.py` with a re-export (keeps every existing `from data_security.canonical import s3_bucket_arn` call site working, now backed by charter):

```python
# packages/agents/data-security/src/data_security/canonical.py
"""Canonical cross-agent resource identifiers — re-exported from the shared
``charter.canonical`` single source of truth (ADR-023). Kept as a thin re-export so
existing data-security call sites are unchanged."""
from __future__ import annotations

from charter.canonical import s3_bucket_arn

__all__ = ["s3_bucket_arn"]
```

> Confirm `charter` is a declared dependency of data-security (it is — data-security already imports `charter.memory.*`). No pyproject change needed.

- [ ] **Step 5: Run the tests + no-regression**

Run: `uv run pytest packages/charter/tests/test_canonical.py -v` → PASS.
Run: `uv run pytest packages/agents/data-security -q` → all PASS (the helper moved; behavior identical; existing `test_entity_resolution` still green).

- [ ] **Step 6: Commit**

```bash
git add packages/charter/src/charter/canonical.py packages/charter/tests/test_canonical.py \
        packages/agents/data-security/src/data_security/canonical.py
git commit -m "feat(charter): shared canonical resource-ARN module (single source of truth)"
```

---

### Task 2: `fleet_testkit.assert_single_node` + cross-agent convergence test

**Files:**

- Modify: `packages/integration/src/fleet_testkit/assertions.py` + `packages/integration/src/fleet_testkit/__init__.py` (export it)
- Test: `packages/integration/src/fleet_testkit/tests/test_canonical_convergence.py`

**Interfaces:**

- Consumes: `charter.canonical.s3_bucket_arn` (Task 1); `SemanticStore.list_entities_by_type`; the three writers (`cloud_posture.tools.kg_writer.KnowledgeGraphWriter.upsert_asset`, `data_security.kg_writer.KnowledgeGraphWriter.record`, `identity.kg_writer.KnowledgeGraphWriter.record_access`).
- Produces: `async def assert_single_node(store, *, tenant_id: str, entity_type: str, external_id: str) -> None` — asserts exactly one node of `entity_type` exists for the tenant AND its `external_id` matches (catches both "missing" and "diverged into duplicates").

- [ ] **Step 1: Write the failing test**

```python
# packages/integration/src/fleet_testkit/tests/test_canonical_convergence.py
"""Keystone test: the ARN-group writers (cloud-posture, data-security, identity),
writing INDEPENDENTLY about the same bucket, converge to ONE CLOUD_RESOURCE node.
This proves the canonical-key foundation by RUNNING the real writers — the template
for verifying every future cross-agent path actually joins."""
import pytest
from charter.canonical import s3_bucket_arn
from charter.memory.graph_types import NodeCategory
from cloud_posture.tools.kg_writer import KnowledgeGraphWriter as CpWriter
from data_security.kg_writer import KnowledgeGraphWriter as DsWriter
from data_security.schemas import ClassifierLabel
from fleet_testkit import assert_single_node, in_memory_semantic_store
from identity.kg_writer import KnowledgeGraphWriter as IdWriter


class _Acl:
    grants_all_users = True
    grants_authenticated_users = False


class _Enc:
    algorithm = "NONE"


class _Bucket:
    def __init__(self, name: str) -> None:
        self.name = name
        self.region = "us-east-1"
        self.acl = _Acl()
        self.encryption = _Enc()


@pytest.mark.asyncio
async def test_arn_group_writers_converge_to_one_node():
    name = "acme-pii"
    arn = s3_bucket_arn(name)
    role_arn = "arn:aws:iam::1:role/app"
    async with in_memory_semantic_store() as store:
        # three agents, independently, about the SAME bucket:
        await CpWriter(store, "t").upsert_asset("s3-bucket", arn, {"region": "us-east-1"})
        await DsWriter(store, "t").record([_Bucket(name)], {name: [ClassifierLabel.SSN]})
        await IdWriter(store, "t").record_access([(role_arn, arn)])

        # they must collapse to ONE cloud_resource node, keyed by the canonical ARN.
        await assert_single_node(
            store, tenant_id="t",
            entity_type=NodeCategory.CLOUD_RESOURCE.value, external_id=arn,
        )
```

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest packages/integration/src/fleet_testkit/tests/test_canonical_convergence.py -v`
Expected: FAIL — `ImportError: cannot import name 'assert_single_node' from 'fleet_testkit'`.

- [ ] **Step 3: Implement the assertion + export it**

Append to `packages/integration/src/fleet_testkit/assertions.py`:

```python
async def assert_single_node(
    store: SemanticStore,
    *,
    tenant_id: str,
    entity_type: str,
    external_id: str,
) -> None:
    """Assert exactly ONE node of ``entity_type`` exists for the tenant and it carries
    ``external_id`` — i.e. all agents converged on the same canonical key (no duplicates,
    no divergent-key nodes). The reusable cross-agent-join check (ADR-023)."""
    nodes = await store.list_entities_by_type(tenant_id=tenant_id, entity_type=entity_type)
    matching = [n for n in nodes if n.external_id == external_id]
    assert len(matching) == 1, (
        f"expected exactly one {entity_type} node with external_id={external_id!r}, "
        f"got {len(matching)} (all {entity_type} external_ids: {[n.external_id for n in nodes]})"
    )
    assert len(nodes) == 1, (
        f"convergence failure: {len(nodes)} {entity_type} nodes exist "
        f"(expected the single canonical node). external_ids: {[n.external_id for n in nodes]}"
    )
```

Ensure `SemanticStore` is imported at the top of `assertions.py` (`from charter.memory.semantic import SemanticStore` — add if absent). Then export it in `packages/integration/src/fleet_testkit/__init__.py`: add `from fleet_testkit.assertions import assert_single_node` (mirroring how the other assertions are imported) and add `"assert_single_node"` to `__all__`.

> Read `assertions.py` + `__init__.py` first to match the existing import/export style (e.g. `assert_entity_written`, `assert_two_tenant_disjoint`).

- [ ] **Step 4: Run to verify it passes**

Run: `uv run pytest packages/integration/src/fleet_testkit/tests/test_canonical_convergence.py -v` → PASS.
Run: `uv run pytest packages/integration -q` → all PASS.

- [ ] **Step 5: Commit**

```bash
git add packages/integration/src/fleet_testkit/assertions.py \
        packages/integration/src/fleet_testkit/__init__.py \
        packages/integration/src/fleet_testkit/tests/test_canonical_convergence.py
git commit -m "test(fleet): assert_single_node + cross-agent ARN convergence keystone test"
```

---

### Task 3: ADR-023 — canonical resource keys

**Files:**

- Create: `docs/_meta/decisions/ADR-023-canonical-resource-keys.md`

- [ ] **Step 1: Write the ADR**

```markdown
# ADR-023: Canonical resource keys for cross-agent entity resolution

**Status:** Accepted — 2026-06-22

## Context

Cross-agent correlation (the moat) requires that different agents' signals about the
SAME real-world resource land on the SAME graph node. A 2026-06-22 audit found four
agents already key `CLOUD_RESOURCE` by canonical cloud ARN — cloud-posture, data-security,
identity, multi-cloud-posture — so they already converge (path 1 proved it REAL). But the
convergence was accidental: no shared helper, no rule, no test.

## Decision

**Every agent keys `CLOUD_RESOURCE` (and infra nodes) by its canonical cloud ARN**, built
via the single-source-of-truth module `charter.canonical`. Same real resource → same
`external_id` → same node, via `SemanticStore.upsert_entity` idempotency on
`(tenant, type, external_id)`. A reusable `fleet_testkit.assert_single_node` proves
convergence by running the real writers. References ADR-018 (type catalogue), ADR-019
(writer base).

## The ARN-joinable group (compliant today)

cloud-posture (F.3), data-security (D.5, via `s3_bucket_arn`), identity (D.2),
multi-cloud-posture (D.15). Unblocks attack paths 1, 3, 4, 7, 8.

## Mechanism ② — bridge edges (DEFERRED, the misfits)

Agents that key by something other than the resource ARN need a linking edge, not a key
change, because the canonical id is not knowable at write time:

- **vulnerability (D.1)** keys by image-ref/host-path → `RUNS_IMAGE` edge (image → workload
  ARN). Source: deployment/registry-to-workload mapping.
- **network-threat (D.4)** keys by IP → `OWNED_BY` edge (IP → instance ARN). Source:
  ENI/VPC metadata.
- **runtime-threat (D.3)** keys by host-uid → `RUNS_ON` edge (uid → instance ARN).
  Bridges unblock paths 2, 5, 9 and are built per-misfit when the linking data source is
  verified. Out of scope for this ADR's slice.

## Consequences

- One place to build resource ARNs; agents stop re-deriving them.
- Cross-agent joins are guaranteed + test-enforced, not accidental.
- The bridge work for misfits is explicit and tracked, not forgotten.
```

- [ ] **Step 2: Commit**

```bash
git add docs/_meta/decisions/ADR-023-canonical-resource-keys.md
git commit -m "docs(adr): ADR-023 canonical resource keys + deferred bridge plan"
```

---

## Self-Review

**Spec coverage:** shared module (Task 1) ✓; ADR-023 (Task 3) ✓; reusable `assert_single_node` + cross-agent join test (Task 2) ✓; data-security re-export / single source of truth (Task 1 Step 4) ✓; bridges deferred + documented (Task 3 ADR) ✓.

**Type consistency:** `s3_bucket_arn` signature identical (Task 1 def, Task 2 use). `assert_single_node(store, *, tenant_id, entity_type, external_id)` identical (Task 2 def + call). Writers consumed with their confirmed signatures (`upsert_asset`, `record`, `record_access`).

**Open items to confirm during execution (tests surface each):**

1. `fleet_testkit/assertions.py` + `__init__.py` exact export style — read before editing (Task 2 Step 3).
2. `ClassifierLabel.SSN` member + the `_Bucket` duck-typed shape data-security's `record` reads (`name`/`region`/`acl.grants_all_users`/`encryption.algorithm`) — confirmed from prior slices; adjust if a field differs.

**Honest scope:** mechanism ① only; bridges + per-feeder REAL verification explicitly deferred (ADR + spec).
