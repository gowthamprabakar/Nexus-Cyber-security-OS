# Tool surface — Curiosity Agent (D.12 v0.1)

D.12 v0.1 ships **no charter-registered tools.** SemanticStore reads are pure DB I/O via the substrate's async API; `claims.>` publishes go through `shared.fabric.JetStreamClient` directly. The tool surface is intentionally minimal — v0.2 may register an NLAH-dispatched `read_coverage_gaps` tool if the operator-driven re-run pattern needs it.

## In-driver helpers (NOT charter-registered)

These are called directly from `curiosity.agent.run`, not through `ctx.call_tool`. They have no per-call budget consumption beyond what their underlying substrate calls incur.

### `read_sibling_state`

Stage 1 INGEST — async aggregate-state query over the `SemanticStore`.

- **Signature:** `async read_sibling_state(semantic_store, *, customer_id, window_days=30) -> SiblingState`
- **Behaviour:** Returns an empty `SiblingState` when `semantic_store=None` (Q5 default) + INFO log. Otherwise queries the `aws_account_region` and `finding_aggregate` entity types via `SemanticStore.list_entities_by_type`, projects into `RegionState[]`. Freshest-sample-per-region when multiple aggregates exist for the same region.
- **Tenant guard:** `customer_id` must be non-empty; empty values raise `ValueError` before any DB call.

### `detect_coverage_gaps`

Stage 2 DETECT — pure-function deterministic gap detector.

- **Signature:** `detect_coverage_gaps(state, *, min_asset_count=10, min_gap_days=30) -> tuple[CoverageGap, ...]`
- **Rule:** A region qualifies as a gap iff `asset_count >= min_asset_count` AND (`days_since_last_finding < 0` (never scanned sentinel) OR `days_since_last_finding >= min_gap_days`).
- **Ordering:** asset_count descending, region-name alphabetic tie-break.
- **Severity hint:** `"high"` for ≥100 assets, `"medium"` for ≥30, `"low"` otherwise. Hint only — not a hard floor.

### `hypothesize`

Stage 3 HYPOTHESIZE — single LLM-call orchestration.

- **Signature:** `async hypothesize(*, llm_provider, gaps, model_pin, q6_violation_retry_hint=False) -> CuriosityDraft`
- **Short-circuits** on empty gaps (no LLM call). Otherwise issues one `LLMProvider.complete()` call with `temperature=0.0` against the bundled `hypothesis.md` prompt template.
- **Typed errors:** `HypothesisCallError` (LLM call failure / malformed JSON / schema fail). Caught by the driver and turned into a fallback empty draft.
- **Caps:** max 5 hypotheses per run (truncated with warning if LLM emits more).

### `review`

Stage 4 REVIEW — deterministic Q6 substring guard. **Reuses D.13's reviewer.**

- **Signature:** `review(draft) -> ReviewVerdict`
- **Two layers:** shape checks (non-empty statement + rationale) + Q6 regex pass via `synthesis.reviewer._scan_classifier_labels` (SSN / credit-card with Luhn / AWS access key / JWT).
- **Retry-hint contract:** `q6_violation` → driver re-runs `hypothesize` with `q6_violation_retry_hint=True`; `shape_violation` → driver accepts degraded; `""` → passed.

### `upsert_hypotheses`

Stage 5 PERSIST — SemanticStore batch upsert helper.

- **Signature:** `async upsert_hypotheses(*, semantic_store, entities) -> None`
- **Q5 opt-in default:** `semantic_store=None` → no-op + log. When set, instantiates a `KnowledgeGraphWriter` with the first entity's `customer_id` and upserts each in order. Mixed-customer batches trip the writer's cross-tenant guard.

### `publish_claims`

Stage 6 PUBLISH — `claims.>` fabric batch publish.

- **Signature:** `async publish_claims(*, js_client, claims) -> int`
- **Q5 opt-in default:** `js_client=None` → no-op + log, returns 0. When set, publishes each claim on `claims.tenant.<customer_id>.agent.curiosity` via `JetStreamClient.publish` with the `CLAIMS_STREAM` spec. Per-claim subject preserves each claim's `customer_id` so the publisher is mixed-batch-safe; the driver typically builds single-customer batches.

## Budget envelope

D.12 v0.1's budget is dominated by **one** LLM call per run (skipped entirely on empty gaps). Token budget should comfortably cover ~10K tokens for v0.1's conservative gap-detector floor (1–3 gaps typical per scan window).

- **LLM calls per run:** 1 (or 0 on empty gaps; +1 on Q6 retry).
- **Filesystem I/O:** two output files (~5 KB each).
- **`SemanticStore` writes:** N (one per hypothesis); idempotent upserts on the composite key.
- **`claims.>` publishes:** N (one per hypothesis); per-claim correlation_id headers propagate from the agent's `correlation_scope`.

## ADR-012 subscriber-ACL fence

D.12 is **not** in the forbidden-subscriber set; A.1 Remediation is the only v0.1 entry. D.12 can freely subscribe to `claims.>` in future v0.2+ work (e.g. a Curiosity-consumes-Curiosity feedback loop). The fence prevents A.1 (or any future auto-acting agent) from consuming speculative claims.
