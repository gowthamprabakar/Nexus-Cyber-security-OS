# Toxic-Combination → D.7 OCSF 2005 Emit (opt-in) — Design Spec

**Date:** 2026-06-22
**Branch:** `slice-toxic-combo-ocsf-emit`
**Predecessor:** the toxic-combination detection slice (`docs/superpowers/plans/2026-06-22-toxic-combination-slice.md`, merged) built the detector + node-writer + `to_hypothesis`, but nothing wires them into a real run. This slice surfaces a detected toxic combination as a real OCSF 2005 finding.

## Goal

When enabled, investigation (D.7) surfaces a detected public-data-exposure toxic combination as one of the hypotheses in its OCSF 2005 `IncidentReport` — through D.7's **existing** emit path (`to_ocsf()` → `incident_report.json`). No new emit machinery. Wired behind an opt-in `run()` parameter that defaults **OFF**, so default behavior is byte-identical and the change is reversible.

## Approach (chosen: opt-in seam, fully functional)

Considered three scopes: (A) auto-detect in D.7's hot path, (B) opt-in seam default-OFF, (C) standalone function not wired to `run()`. **Chosen: B** — it does the complete real path (derives seeds from real identity findings, runs the detector over the graph, emits a genuine OCSF 2005 finding) while keeping default `run()` byte-identical. Flipping the default ON later is a one-line follow-up.

## Components

### 1. Composing function — `investigation/toxic_combination.py` (extend the existing module)

```
async def detect_toxic_combination_hypotheses(
    *,
    semantic_store: SemanticStore,
    customer_id: str,
    related_findings: Sequence[RelatedFinding],
) -> tuple[Hypothesis, ...]
```

Steps:

1. **Seed sourcing** — filter `related_findings` for identity overprivilege findings: `class_uid == 2004` and the finding's overprivilege marker (confirm exact marker in `identity/schemas.py` during planning — likely `finding_type`/`category` == "overprivilege" in the payload). For each, extract:
   - the **principal ARN** (from the finding payload's `resources[*].uid`/`name`), and
   - the **finding uid** = `str((payload.get("finding_info") or {}).get("uid", ""))` — the SAME extraction `synthesizer._build_evidence_index` uses, so the ref resolves.
2. **Resolve** each principal ARN → graph `entity_id` via `semantic_store.upsert_entity(tenant_id=customer_id, entity_type=NodeCategory.IDENTITY.value, external_id=arn, properties={})` (idempotent — identity already wrote those nodes keyed by ARN, so this returns the existing id; it does not create spurious nodes because the node already exists).
3. **Detect** — `KgQuery(semantic_store, customer_id).find_public_data_exposure(over_permissioned_principal_ids=[resolved ids])`.
4. **Materialize + build hypothesis** — for each `ToxicCombination` hit: `ToxicCombinationWriter(semantic_store, customer_id).record(combo)` (writes the `TOXIC_COMBINATION` node), then `to_hypothesis(combo, evidence_refs=(f"finding:{identity_overprivilege_uid}",))`. The evidence_ref is the identity overprivilege finding uid that produced the seed principal — guaranteed present in D.7's corpus → survives Stage 4 validation.
5. Return the hypotheses tuple (empty when no hits).

### 2. The seam — `investigation/agent.py` `run()`

Add keyword-only parameter `detect_toxic_combinations: bool = False`. After Stage 3 (SYNTHESIZE) produces `hypotheses` and **before** Stage 4 (VALIDATE):

```
if detect_toxic_combinations and semantic_store is not None:
    toxic = await detect_toxic_combination_hypotheses(
        semantic_store=semantic_store,
        customer_id=scope.tenant_id,
        related_findings=sub_outputs.related_findings,
    )
    hypotheses = (*hypotheses, *toxic)
```

Merging **before** Stage 4 is deliberate: the toxic hypotheses then pass through D.7's existing `_stage_validate` + the four load-bearing invariants (`assert_no_speculation`, `assert_evidence_chain`, `assert_findings_cited`, `assert_categorical_only`) exactly like any other hypothesis. They survive because their `evidence_refs` cite a real `finding:<uid>` in the corpus; the generic statement carries no plaintext PII (`assert_categorical_only` passes).

Flag OFF (default) → block skipped → `hypotheses` unchanged → `IncidentReport`/`to_ocsf()` byte-identical.

## Data flow

identity 2004 overprivilege findings (D.7 already reads via sibling workspaces) → principal ARN + finding uid → graph entity_id → `find_public_data_exposure` over the populated graph → `ToxicCombination` hits → `TOXIC_COMBINATION` node + `Hypothesis(evidence_refs=finding:<uid>)` → merged into `hypotheses` → Stage 4 keeps them (refs resolve) → `_build_incident_report` → `to_ocsf()` 2005 → `incident_report.json`.

## Correctness anchor (the one subtle point)

D.7's evidence index resolves **only** `audit_event:<hash16>` and `finding:<uid>` kinds (`synthesizer.py:118,122`). An `entity:`-kind ref would be dropped. Therefore the toxic hypothesis cites the identity overprivilege **finding uid** (always in corpus, since it is the seed source). This is verified, not assumed.

## Testing

1. **Unit** (`test_toxic_combination.py`): `detect_toxic_combination_hypotheses` with a seeded graph (via the three writers) + a synthetic identity overprivilege `RelatedFinding` → returns exactly one `Hypothesis` whose `evidence_refs == ("finding:<that-uid>",)` and whose statement mentions over-permissioned/public. Negative: no identity overprivilege finding → empty tuple.
2. **E2E through real `run()`** (integration test): populate the graph via cloud-posture + data-security + identity writers; pass sibling workspaces containing identity (2004 overprivilege) + data-security findings; call `run(contract, …, semantic_store=store, detect_toxic_combinations=True)` → assert the returned/emitted `IncidentReport.to_ocsf()` `unmapped.hypotheses` contains the toxic-combination hypothesis and it was NOT dropped by Stage 4.
3. **Reversibility test:** same inputs with `detect_toxic_combinations=False` (default) → the emitted report contains no toxic hypothesis and is identical to a baseline run. Proves the seam is inert when off.

## Honest scope / deferred (bounded, not hidden)

- **Default OFF.** Auto-on is a deliberate one-line follow-up after the operator has watched it fire.
- **Live-loop dependency:** D.7 only finds combinations if upstream agents (cloud-posture/data-security/identity) already populated the graph for that tenant in the run. Tests seed it; production population is the existing Phase C live-loop concern, unchanged by this slice.
- **S3-only** path (inherited from the detector slice).
- **Single evidence anchor:** the toxic hypothesis cites the identity overprivilege finding uid. Citing the data-security sensitivity finding uid as a second ref is a nice-to-have deferred (would require mapping the `DATA_CLASSIFICATION` node back to its source finding); not needed for validity.
- **No bus emit change:** stays on the filesystem-artifact path (`incident_report.json`); `publish_events_to_bus` default unchanged.

## Constraints (carried)

- Additive; default behavior byte-identical; offline-inert when no store.
- Typed vocabulary only; tenant-scoped (`customer_id`); read/write separation (`kg_query` read-only — the node write lives in investigation).
- Evidence refs MUST be of resolvable kinds (`finding:`/`audit_event:`) drawn from the corpus.
