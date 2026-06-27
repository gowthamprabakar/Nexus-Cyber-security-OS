# Toxic-Combination OCSF 2005 Emit (opt-in) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** When opted in, investigation (D.7) surfaces a detected public-data-exposure toxic combination as a hypothesis in its OCSF 2005 `IncidentReport`, through D.7's existing emit path — default OFF, byte-identical when off.

**Architecture:** A composing function in `investigation/toxic_combination.py` derives over-permissioned principals from identity's real overprivilege findings, runs the existing `KgQuery.find_public_data_exposure` detector over the graph, writes the `TOXIC_COMBINATION` node, and builds a `Hypothesis` citing a resolvable `finding:<uid>`. A new `run()` parameter `detect_toxic_combinations` (default `False`) merges those hypotheses in before Stage 4 VALIDATE so they pass D.7's existing invariants like any other.

**Tech Stack:** Python 3.12, async, `charter.memory` (`SemanticStore`, `NodeCategory`), `meta_harness.kg_query.KgQuery`, investigation `RelatedFinding`/`Hypothesis`, pytest + pytest-asyncio, `fleet_testkit.in_memory_semantic_store`.

## Global Constraints

- **Additive / reversible.** `run()` default behavior byte-identical (`detect_toxic_combinations=False`). No existing signature changed except an added keyword-only param with a default. Offline-inert preserved.
- **No new cross-package dependency.** Do NOT import identity's enums. Match the overprivilege marker by its OCSF **wire string** `"overprivilege"`. (investigation already declares `meta_harness` and charter as deps; do not add identity.)
- **Evidence refs must resolve.** D.7's evidence index (`synthesizer._build_evidence_index`) admits only `audit_event:<hash16>` and `finding:<uid>`. The toxic hypothesis MUST cite `finding:<uid>` where uid = `payload["finding_info"]["uid"]` of the identity overprivilege finding (guaranteed in corpus). No `entity:` refs.
- **Typed vocabulary** (`NodeCategory`/`EdgeType`), **tenant-scoped** (`customer_id`), **read/write separation** (`kg_query` read-only; the node write is in investigation).
- Commit lines ≤100 chars. Branch is already `slice-toxic-combo-ocsf-emit`.

---

## File Structure

| File                                                                   | Create/Modify         | Responsibility                                                            |
| ---------------------------------------------------------------------- | --------------------- | ------------------------------------------------------------------------- |
| `packages/agents/investigation/src/investigation/toxic_combination.py` | Modify (add function) | `detect_toxic_combination_hypotheses(...)` — seeds→detect→node→hypotheses |
| `packages/agents/investigation/tests/test_toxic_combination.py`        | Modify (add tests)    | unit coverage for the composing function                                  |
| `packages/agents/investigation/src/investigation/agent.py`             | Modify (param + seam) | opt-in `detect_toxic_combinations` merges toxic hypotheses before Stage 4 |
| `packages/agents/investigation/tests/test_agent.py`                    | Modify (add tests)    | run() e2e: flag ON surfaces it (survives Stage 4); flag OFF inert         |

---

### Task 1: composing function `detect_toxic_combination_hypotheses`

**Files:**

- Modify: `packages/agents/investigation/src/investigation/toxic_combination.py`
- Test: `packages/agents/investigation/tests/test_toxic_combination.py`

**Interfaces:**

- Consumes: `KgQuery.find_public_data_exposure(*, over_permissioned_principal_ids)` → `list[ToxicCombination]`; `ToxicCombinationWriter(store, customer_id).record(combo)`; `to_hypothesis(combo, *, evidence_refs)` → `Hypothesis` (all already in this module / `meta_harness.kg_query`); `RelatedFinding` (fields `source_agent: str, source_run_id: str, class_uid: int, payload: dict[str,Any]`) from `investigation.tools.related_findings`; `SemanticStore` from `charter.memory.semantic`.
- Produces: `async def detect_toxic_combination_hypotheses(*, semantic_store: SemanticStore, customer_id: str, related_findings: Sequence[RelatedFinding]) -> tuple[Hypothesis, ...]`.

- [ ] **Step 1: Write the failing tests**

```python
# add to packages/agents/investigation/tests/test_toxic_combination.py
import pytest
from charter.memory.graph_types import EdgeType, NodeCategory
from fleet_testkit import in_memory_semantic_store
from investigation.toxic_combination import detect_toxic_combination_hypotheses
from investigation.tools.related_findings import RelatedFinding


def _overpriv_finding(uid: str, principal_arn: str) -> RelatedFinding:
    return RelatedFinding(
        source_agent="identity",
        source_run_id="run-1",
        class_uid=2004,
        payload={
            "class_uid": 2004,
            "finding_info": {"uid": uid, "types": ["overprivilege"]},
            "affected_principals": [{"type": "Role", "name": "app", "uid": principal_arn}],
        },
    )


async def _seed_toxic_graph(store, *, principal_arn, bucket_arn):
    t = "tenant-1"
    role = await store.upsert_entity(tenant_id=t, entity_type=NodeCategory.IDENTITY.value,
                                     external_id=principal_arn, properties={})
    bucket = await store.upsert_entity(tenant_id=t, entity_type=NodeCategory.CLOUD_RESOURCE.value,
                                       external_id=bucket_arn, properties={})
    data = await store.upsert_entity(tenant_id=t, entity_type=NodeCategory.DATA_CLASSIFICATION.value,
                                     external_id=f"{bucket_arn}:ssn", properties={"data_type": "ssn"})
    await store.add_relationship(tenant_id=t, src_entity_id=role, dst_entity_id=bucket,
                                 relationship_type=EdgeType.HAS_ACCESS_TO.value, properties={})
    await store.add_relationship(tenant_id=t, src_entity_id=bucket, dst_entity_id=data,
                                 relationship_type=EdgeType.EXPOSES_DATA.value, properties={})


@pytest.mark.asyncio
async def test_detect_emits_one_hypothesis_with_resolvable_evidence_ref():
    arn = "arn:aws:iam::1:role/app"
    bucket = "arn:aws:s3:::acme-pii"
    async with in_memory_semantic_store() as store:
        await _seed_toxic_graph(store, principal_arn=arn, bucket_arn=bucket)
        hyps = await detect_toxic_combination_hypotheses(
            semantic_store=store, customer_id="tenant-1",
            related_findings=[_overpriv_finding("IDENT-OVERPRIV-app-001-x", arn)])
        assert len(hyps) == 1
        assert hyps[0].evidence_refs == ("finding:IDENT-OVERPRIV-app-001-x",)
        assert "over-permissioned" in hyps[0].statement.lower()


@pytest.mark.asyncio
async def test_detect_empty_when_no_overprivilege_finding():
    async with in_memory_semantic_store() as store:
        # a 2004 finding of a different type must be ignored
        rf = RelatedFinding(source_agent="identity", source_run_id="r", class_uid=2004,
                            payload={"finding_info": {"uid": "u", "types": ["dormant"]},
                                     "affected_principals": [{"uid": "arn:aws:iam::1:role/x"}]})
        hyps = await detect_toxic_combination_hypotheses(
            semantic_store=store, customer_id="tenant-1", related_findings=[rf])
        assert hyps == ()


@pytest.mark.asyncio
async def test_detect_empty_when_principal_has_no_toxic_path():
    arn = "arn:aws:iam::1:role/app"
    async with in_memory_semantic_store() as store:
        # principal node exists but no HAS_ACCESS_TO/EXPOSES_DATA path
        await store.upsert_entity(tenant_id="tenant-1", entity_type=NodeCategory.IDENTITY.value,
                                  external_id=arn, properties={})
        hyps = await detect_toxic_combination_hypotheses(
            semantic_store=store, customer_id="tenant-1",
            related_findings=[_overpriv_finding("IDENT-OVERPRIV-app-001-x", arn)])
        assert hyps == ()
```

- [ ] **Step 2: Run them to verify they fail**

Run: `uv run pytest packages/agents/investigation/tests/test_toxic_combination.py -k detect -v`
Expected: FAIL — `ImportError: cannot import name 'detect_toxic_combination_hypotheses'`.

- [ ] **Step 3: Implement the function**

```python
# add to packages/agents/investigation/src/investigation/toxic_combination.py
# new imports at top (keep existing ones):
from collections.abc import Sequence
from typing import TYPE_CHECKING

from charter.memory.graph_types import NodeCategory
from meta_harness.kg_query import KgQuery

if TYPE_CHECKING:
    from charter.memory.semantic import SemanticStore
    from investigation.tools.related_findings import RelatedFinding

# OCSF wire value of identity's FindingType.OVERPRIVILEGE. D.7 consumes findings by
# their wire shape, NOT by importing the producer's enum (avoids a cross-package dep).
_OVERPRIVILEGE = "overprivilege"


async def detect_toxic_combination_hypotheses(
    *,
    semantic_store: SemanticStore,
    customer_id: str,
    related_findings: Sequence[RelatedFinding],
) -> tuple[Hypothesis, ...]:
    """Turn identity overprivilege findings into toxic-combination hypotheses.

    For each over-permissioned principal, resolve it to its graph node, run the
    public-data-exposure detector, write the TOXIC_COMBINATION node, and build a
    Hypothesis citing the identity finding's uid (a `finding:<uid>` ref D.7's
    Stage 4 validator resolves). Empty tuple when nothing qualifies.
    """
    ref_by_principal: dict[str, str] = {}
    for rf in related_findings:
        if rf.class_uid != 2004:
            continue
        info = rf.payload.get("finding_info") or {}
        types = info.get("types") or []
        if not types or types[0] != _OVERPRIVILEGE:
            continue
        finding_uid = str(info.get("uid", ""))
        if not finding_uid:
            continue
        for principal in rf.payload.get("affected_principals", []):
            arn = str(principal.get("uid", ""))
            if not arn:
                continue
            entity_id = await semantic_store.upsert_entity(
                tenant_id=customer_id,
                entity_type=NodeCategory.IDENTITY.value,
                external_id=arn,
                properties={},
            )
            ref_by_principal.setdefault(entity_id, f"finding:{finding_uid}")

    if not ref_by_principal:
        return ()

    hits = await KgQuery(semantic_store, customer_id).find_public_data_exposure(
        over_permissioned_principal_ids=list(ref_by_principal),
    )
    writer = ToxicCombinationWriter(semantic_store, customer_id)
    hypotheses: list[Hypothesis] = []
    for combo in hits:
        ref = ref_by_principal.get(combo.principal_id)
        if ref is None:
            continue
        await writer.record(combo)
        hypotheses.append(to_hypothesis(combo, evidence_refs=(ref,)))
    return tuple(hypotheses)
```

Add `"detect_toxic_combination_hypotheses"` to `__all__`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest packages/agents/investigation/tests/test_toxic_combination.py -v`
Expected: PASS (the 3 new + the 2 existing from the prior slice).

- [ ] **Step 5: Commit**

```bash
git add packages/agents/investigation/src/investigation/toxic_combination.py \
        packages/agents/investigation/tests/test_toxic_combination.py
git commit -m "feat(investigation): compose toxic-combination hypotheses from identity findings"
```

---

### Task 2: opt-in `run()` seam + run() e2e

**Files:**

- Modify: `packages/agents/investigation/src/investigation/agent.py` (run() signature + seam after line 257, before Stage 4)
- Test: `packages/agents/investigation/tests/test_agent.py`

**Interfaces:**

- Consumes: `detect_toxic_combination_hypotheses(...)` (Task 1); existing `run()` internals (`scope.tenant_id`, `sub_outputs.related_findings`, `hypotheses`, the required `semantic_store` param).
- Produces: `run(..., detect_toxic_combinations: bool = False)`; when True, toxic hypotheses appear in the emitted `IncidentReport.hypotheses` (and thus `to_ocsf()["unmapped"]["hypotheses"]`).

- [ ] **Step 1: Write the failing tests**

First READ the existing run() test in `packages/agents/investigation/tests/test_agent.py` to reuse its harness (how it builds the `ExecutionContract`, `audit_store`, `semantic_store`, and `sibling_workspaces`). Then add a test that reuses that harness and adds the toxic setup. The toxic-specific pieces (graph population + a sibling workspace whose `findings.json` carries an identity overprivilege finding + the assertions) are:

```python
# add to packages/agents/investigation/tests/test_agent.py
# Reuses the existing run() harness in this file. Names prefixed _tc_ are toxic-specific.
import json

from charter.memory.graph_types import EdgeType, NodeCategory


async def _tc_seed_graph(store, tenant, *, principal_arn, bucket_arn):
    role = await store.upsert_entity(tenant_id=tenant, entity_type=NodeCategory.IDENTITY.value,
                                     external_id=principal_arn, properties={})
    bucket = await store.upsert_entity(tenant_id=tenant, entity_type=NodeCategory.CLOUD_RESOURCE.value,
                                       external_id=bucket_arn, properties={})
    data = await store.upsert_entity(tenant_id=tenant, entity_type=NodeCategory.DATA_CLASSIFICATION.value,
                                     external_id=f"{bucket_arn}:ssn", properties={"data_type": "ssn"})
    await store.add_relationship(tenant_id=tenant, src_entity_id=role, dst_entity_id=bucket,
                                 relationship_type=EdgeType.HAS_ACCESS_TO.value, properties={})
    await store.add_relationship(tenant_id=tenant, src_entity_id=bucket, dst_entity_id=data,
                                 relationship_type=EdgeType.EXPOSES_DATA.value, properties={})


def _tc_identity_workspace(tmp_path, principal_arn):
    ws = tmp_path / "identity_ws"
    ws.mkdir()
    (ws / "findings.json").write_text(json.dumps({
        "source_agent": "identity", "source_run_id": "r1",
        "findings": [{
            "class_uid": 2004,
            "finding_info": {"uid": "IDENT-OVERPRIV-app-001-x", "types": ["overprivilege"]},
            "affected_principals": [{"type": "Role", "name": "app", "uid": principal_arn}],
        }],
    }))
    return ws
```

Then two tests, built on the existing harness (adapt the contract/audit_store/semantic_store construction to match this file's existing run() test):

```python
@pytest.mark.asyncio
async def test_run_surfaces_toxic_combination_when_opted_in(tmp_path):
    # ... build contract (customer_id="tenant-1"), audit_store, semantic_store as the
    # existing run() test does ...
    principal = "arn:aws:iam::1:role/app"
    bucket = "arn:aws:s3:::acme-pii"
    await _tc_seed_graph(semantic_store, "tenant-1", principal_arn=principal, bucket_arn=bucket)
    ws = _tc_identity_workspace(tmp_path, principal)

    report = await run(contract, audit_store=audit_store, semantic_store=semantic_store,
                       sibling_workspaces=[ws], detect_toxic_combinations=True)

    statements = [h.statement.lower() for h in report.hypotheses]
    assert any("over-permissioned" in s for s in statements), "toxic hypothesis must survive Stage 4"
    ocsf = report.to_ocsf()
    assert ocsf["class_uid"] == 2005


@pytest.mark.asyncio
async def test_run_inert_when_flag_off(tmp_path):
    # identical setup to the opted-in test ...
    principal = "arn:aws:iam::1:role/app"
    bucket = "arn:aws:s3:::acme-pii"
    await _tc_seed_graph(semantic_store, "tenant-1", principal_arn=principal, bucket_arn=bucket)
    ws = _tc_identity_workspace(tmp_path, principal)

    report = await run(contract, audit_store=audit_store, semantic_store=semantic_store,
                       sibling_workspaces=[ws])  # detect_toxic_combinations defaults False

    statements = [h.statement.lower() for h in report.hypotheses]
    assert not any("over-permissioned" in s for s in statements), "flag OFF → no toxic hypothesis"
```

> Adapt the `contract`/`audit_store`/`semantic_store` construction to match the existing run() test in this file exactly (same fixtures/helpers). If the existing run() test uses a deterministic LLM-less path, that's fine — the toxic hypothesis is added by the seam, independent of the synthesizer.

- [ ] **Step 2: Run them to verify they fail**

Run: `uv run pytest packages/agents/investigation/tests/test_agent.py -k toxic -v`
Expected: FAIL — `TypeError: run() got an unexpected keyword argument 'detect_toxic_combinations'`.

- [ ] **Step 3: Add the param + the seam**

In `agent.py`, add the keyword-only param to `run()` (after `publish_events_to_bus`):

```python
    publish_events_to_bus: bool = False,
    detect_toxic_combinations: bool = False,
) -> IncidentReport:
```

Then insert the seam immediately AFTER `assert_bounded_retry(1)` (line 257) and BEFORE the `# Stage 4 — VALIDATE` comment (line 259):

```python
            # Cross-agent correlation (opt-in, default OFF → byte-identical). Merge toxic-
            # combination hypotheses BEFORE Stage 4 so they pass the same evidence-resolution
            # + invariants as every other hypothesis. They cite the identity overprivilege
            # finding's uid (in corpus), so they survive validation.
            if detect_toxic_combinations:
                toxic = await detect_toxic_combination_hypotheses(
                    semantic_store=semantic_store,
                    customer_id=scope.tenant_id,
                    related_findings=sub_outputs.related_findings,
                )
                hypotheses = (*hypotheses, *toxic)
```

Add the import near the other investigation imports:

```python
from investigation.toxic_combination import detect_toxic_combination_hypotheses
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest packages/agents/investigation/tests/test_agent.py -k toxic -v`
Expected: PASS (2 passed). The opted-in test proves the toxic hypothesis survives Stage 4; the flag-off test proves the seam is inert.

- [ ] **Step 5: Run the full investigation suite (no regression)**

Run: `uv run pytest packages/agents/investigation -q`
Expected: all PASS, 0 failed (the seam is inert by default; existing run() tests unaffected).

- [ ] **Step 6: Commit**

```bash
git add packages/agents/investigation/src/investigation/agent.py \
        packages/agents/investigation/tests/test_agent.py
git commit -m "feat(investigation): opt-in run() seam surfaces toxic combinations as OCSF 2005"
```

---

## Self-Review

**Spec coverage:**

- Composing function (seed from identity overprivilege findings → detect → node → hypothesis with resolvable ref) → Task 1. ✓
- Opt-in `run()` seam, merged before Stage 4, default OFF byte-identical → Task 2. ✓
- Evidence-ref anchor = identity overprivilege `finding:<uid>` → Task 1 Step 3 + test asserts the exact ref. ✓
- Tests: unit (Task 1, incl. 2 negatives), real-run() e2e (Task 2 flag-on, survives Stage 4), reversibility (Task 2 flag-off inert). ✓
- No new cross-package dep (wire-string `"overprivilege"`, not identity's enum) → Task 1 Step 3. ✓

**Type consistency:** `detect_toxic_combination_hypotheses` signature identical in Task 1 (def) and Task 2 (call). `RelatedFinding` fields (`class_uid`, `payload`) used consistently. `to_hypothesis`/`ToxicCombinationWriter`/`KgQuery.find_public_data_exposure` consumed with the signatures from the prior merged slice.

**Open items to confirm during execution (tests surface each):**

1. The existing run() test harness in `test_agent.py` — its exact `contract`/`audit_store`/`semantic_store` construction (Task 2 reuses it).
2. `RelatedFinding` exact import path + that `from_workspace` parsing maps `findings[].class_uid` → `rf.class_uid` and the OCSF dict → `rf.payload` (Task 2's `_tc_identity_workspace` shape must match what `find_related_findings` parses — read `tools/related_findings.py` if the e2e finding doesn't load).

**Honest scope:** opt-in only (default OFF); live-loop graph population unchanged; S3-only; single evidence anchor (identity finding uid). All per the approved spec.
