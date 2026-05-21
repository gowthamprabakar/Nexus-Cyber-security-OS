# D.12 Curiosity v0.1 — Verification Record

**Date:** 2026-05-21
**Plan:** [`docs/superpowers/plans/2026-05-21-d-12-curiosity-v0-1.md`](../superpowers/plans/2026-05-21-d-12-curiosity-v0-1.md)
**Operating rule:** [Path-B-breadth-first (2026-05-20)](../../packages/agents/curiosity/README.md#scope-v01) — every unbuilt agent ships to v0.1 in sketch §8 sequence before any v0.2+ work on a shipped agent.
**Outcome:** **D.12 v0.1 shipped.** 16 tasks, 17 PRs (plan + 16 task PRs), all merged to main. 227 tests passing. 10/10 eval cases pass. WI-1 (first `claims.>` publisher) + WI-2 (Q6 no-classifier-substring posture) + WI-3 (stub-LLM byte-equal determinism) + WI-4 (A.1 subscriber-ACL fence still holds at the substrate) all verified at unit, eval, and CLI layers. Path-B sequence advances to **A.4 Meta-Harness** (D.12 was the last D-track agent; A.4 depends on all 6 D-track agents existing — now true).

## Execution-status table

| Task | Status | PR   | Commit    | Summary                                                                                                                                                                                                                                                                                             |
| ---- | ------ | ---- | --------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| -    | ✅     | #124 | `5a28928` | Plan doc — `2026-05-21-d-12-curiosity-v0-1.md` (16-task table, Q1-Q6, WI-1..WI-4, seven-stage pipeline diagram).                                                                                                                                                                                    |
| 1    | ✅     | #125 | `cd8349c` | Package bootstrap — pyproject (BSL 1.1; deps on charter / shared / eval-framework / nexus-synthesis-agent + nexus-cloud-posture + nexus-compliance-agent + nexus-threat-intel-agent + python-ulid 2.7). 12 smoke tests including ADR-012 substrate-reachability + WI-4 A.1-fence-still-ships probe. |
| 2    | ✅     | #126 | `660efb7` | `schemas.py` — 6 pydantic types (`CoverageGap`, `ProbeDirective`, `Hypothesis`, `CuriosityClaim`, `CuriosityDraft`, `CuriosityReport`). ULID-validated `claim_id`; ProbeDirective XOR constraint; agent_id Literal["curiosity"]. 20 tests.                                                          |
| 3    | ✅     | #127 | `6d5e603` | `tools/sibling_state_reader.py` + new `SemanticStore.list_entities_by_type` substrate helper. Async aggregate-state queries; freshest-sample-per-region projection; forgiving on malformed properties. **Bundled substrate addition** (SAFETY-CRITICAL). 14 tests + 5 substrate tests.              |
| 4    | ✅     | #128 | `85dca70` | `tools/coverage_gap_detector.py` — deterministic region-gap detector. Asset-count + day-gap thresholds; severity hint bucketing; alphabetic tie-break. 14 tests.                                                                                                                                    |
| 5    | ✅     | #129 | `bec3043` | `prompts/hypothesis.md` + `load_prompt` helper. Single Stage-3 template carrying the Q6 reminder block + JSON-only constraint + 5-cap. 14 tests.                                                                                                                                                    |
| 6    | ✅     | #130 | `a1359ff` | `hypothesizer.py` — single-call LLM orchestration. Empty-gaps short-circuit; HypothesisCallError typed error; Q6 retry banner. **Schema fix:** relaxed `ProbeDirective.rationale_ref` to allow `""` (pending-driver-fill state). 17 tests.                                                          |
| 7    | ✅     | #131 | `06e7f76` | `reviewer.py` — Q6 substring guard. Two layers (shape + Q6 regex). **Reuses D.13's `synthesis.reviewer._scan_classifier_labels`** end-to-end. 13 tests.                                                                                                                                             |
| 8    | ✅     | #132 | `ff1fa63` | `entities.py` (`HypothesisEntity`; entity_type=`hypothesis`) + `kg_writer.py` (batch upsert helper; single-tenant opt-in default; mixed-customer-batch guard). 21 tests.                                                                                                                            |
| 9    | ✅     | #133 | `277d8bd` | `claims_publisher.py` — **the first DAY-12-specific live use of ADR-012's substrate**. Wraps `JetStreamClient.publish` for `claims.tenant.<tid>.agent.curiosity` emit; `nexus_claim` envelope (NOT OCSF) per the wire-format resolution. 12 tests.                                                  |
| 10   | ✅     | #134 | `804bdf6` | `agent.py` — 7-stage driver (INGEST → DETECT → HYPOTHESIZE → REVIEW → PERSIST → PUBLISH → HANDOFF). ULID claim_id minting + `rationale_ref` backfill via frozen-model rebuild. Q6 retry loop (budget=1). HypothesizerError fallback. 15 driver tests.                                               |
| 11   | ✅     | #135 | `57f0ae5` | NLAH bundle (Curiosity persona README + tools.md + 3 examples: region-gap / q6-rejection / fabric-publish) + 26-LOC `nlah_loader.py` (under 35-LOC budget). **D.12 is the 11th agent shipped natively against ADR-007 v1.2.** 18 tests.                                                             |
| 12   | ✅     | #136 | `b918763` | `eval_runner.py` + 10 YAML cases. `CuriosityEvalRunner` registered via `nexus_eval_runners`. 18 tests (10 parametrised case-pass + 8 framework).                                                                                                                                                    |
| 13   | ✅     | #137 | `b7f7651` | `cli.py` — `curiosity run` + `curiosity eval` click commands. Experimental `--semantic-store-dsn` + `--nats-url` flags reserved for v0.2. 14 CLI tests.                                                                                                                                             |
| 14   | ✅     | #138 | `a0e7f39` | Stub-LLM harness refactor — canned LLM responses lifted from inline YAML into `eval/stub_responses/<case_id>/responses.json`. **WI-3 byte-equal across reruns probe** (×10 cases; timestamps + ULIDs stripped). 28 tests.                                                                           |
| 15   | ✅     | #139 | `50ea102` | README polish + smoke runbook. 3-step runbook, 7-stage architecture diagram, prompt-template authoring guide, ADR-007 + ADR-012 conformance section, experimental-flags documentation.                                                                                                              |
| 16   | ✅     | this | this PR   | This verification record + plan-doc execution-status table update + auto-memory advance.                                                                                                                                                                                                            |

## Gate results

| Gate                                            | Result                                                                             |
| ----------------------------------------------- | ---------------------------------------------------------------------------------- |
| `ruff check`                                    | clean (`All checks passed!`)                                                       |
| `ruff format --check`                           | clean                                                                              |
| `mypy --strict`                                 | clean — 15 source files in `src/curiosity/` + the SemanticStore substrate addition |
| `pytest packages/agents/curiosity`              | **227 passed** in <1s                                                              |
| `curiosity eval` (bundled `eval/cases/`)        | **10/10 passed**                                                                   |
| Operator-side `curiosity run --contract <path>` | exits 0; emits `hypotheses.md` + `probe_directives.json` + one-line digest         |

## 10/10 eval acceptance

All 10 bundled cases pass via `CuriosityEvalRunner` (registered via the `nexus_eval_runners` entry point):

| Case ID                                    | Coverage                                                                                                |
| ------------------------------------------ | ------------------------------------------------------------------------------------------------------- |
| `clean_no_gaps`                            | Empty store → empty draft (LLM call short-circuits).                                                    |
| `single_region_gap`                        | 1 region 42 assets 60 days → 1 hypothesis emitted + PERSIST + PUBLISH.                                  |
| `multi_region_gaps`                        | 3 regions all gaps → 3 hypotheses in one LLM call.                                                      |
| `region_gap_with_tight_threshold`          | 9 assets < 10 floor → no qualification.                                                                 |
| `q6_no_classifier_substring_in_hypothesis` | **WI-2 retry probe**: pass 1 leaks SSN → reviewer rejects → pass 2 clean; `review_retries=1`.           |
| `max_5_hypotheses_cap`                     | LLM emits 7 hypotheses → truncated to 5 with warning log.                                               |
| `probe_directive_shape`                    | `target_finding_id` branch (XOR enforcement at schema layer).                                           |
| `fabric_publish_payload_shape`             | Verifies `claims.>` publish path + payload shape.                                                       |
| `stub_llm_determinism`                     | **WI-3 substring contract**: byte-equal verified separately by the harness tests.                       |
| `kg_upsert_skipped_when_none`              | **Q5 single-tenant default**: `semantic_store=None` + `js_client=None` → zero upserts + zero publishes. |

## Acceptance criteria (plan §Q1-Q6 + watch-items)

| Criterion                                                                                               | Verification                                                                                                                                                                                                                                                                                                            |
| ------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Q1.** Output: 3 directions (KG entity + `claims.>` + workspace md); `nexus_claim` envelope (NOT OCSF) | `entities.py` ships `HypothesisEntity` (entity_type=`hypothesis`); `claims_publisher.py` serialises via `model_dump_json`; `agent.py` writes `hypotheses.md` + `probe_directives.json` via `ctx.write_output`. ADR-012's wire-format Q is resolved here.                                                                |
| **Q2.** Generation pattern: deterministic-trigger + LLM-hypothesis                                      | Stage 2 `detect_coverage_gaps` is pure-function; Stage 3 `hypothesize` issues one LLM call. Empty gaps short-circuit skips the LLM call entirely (verified by `test_empty_gaps_short_circuit_no_llm_call` + eval case 01).                                                                                              |
| **Q3.** Region-gap detector only in v0.1                                                                | `tools/coverage_gap_detector.py` ships ONE detector with `_MIN_ASSET_COUNT=10` + `_MIN_GAP_DAYS=30` thresholds. Asset-type / time-window / severity-distribution / classifier-label / control-coverage gap detectors deferred to v0.2 per README §Deferred.                                                             |
| **Q4.** Probe directive: structured dict in both workspace JSON + claims.> payload                      | `agent._build_claims` and `agent._render_probe_directives_json` produce the same `ProbeDirective` shape on both wires. v0.1 is producer-only; consumer wire-up in D.7/D.5/D.8 v0.2 plans.                                                                                                                               |
| **Q5.** Tenancy: single-tenant `semantic_store=None` + `js_client=None` opt-in default                  | `agent.run` defaults both to `None`; `kg_writer.upsert_hypotheses` + `claims_publisher.publish_claims` no-op-with-log when `None`. Multi-tenant production blocks on SET LOCAL `$1` substrate-fix plan. Eval case 10 (`kg_upsert_skipped_when_none`) is the regression probe.                                           |
| **Q6.** Reuse D.13's reviewer for classifier-substring detection                                        | `reviewer.py` imports `synthesis.reviewer._scan_classifier_labels` directly. Both agents enforce the same Q6 contract end-to-end; eval case 05 (`q6_no_classifier_substring_in_hypothesis`) is the WI-2 regression probe.                                                                                               |
| **WI-1** First `claims.>` publisher in the fleet                                                        | `claims_publisher.py` is the producer-side; `JetStreamClient.publish(CLAIMS_STREAM, claims_subject(tid, "curiosity"), payload)` is the call. ADR-012 amendment (`A.1 -> {claims.>}`) holds at the substrate; D.12's smoke (`test_a1_subscriber_acl_fence_present`) asserts the fence on every run.                      |
| **WI-2** Q6 — no classifier-shaped substrings leak                                                      | Two layers: (1) prompt template `hypothesis.md` carries explicit Q6 reminder; (2) reviewer regex-guards rendered output. Eval case 05 is the regression probe; reviewer test `test_violation_strings_do_not_contain_matched_substring` proves the meta-invariant (violation strings name the label, not the substring). |
| **WI-3** Stub-LLM byte-equal determinism                                                                | Per-case `eval/stub_responses/<case_id>/responses.json`. `test_stub_llm_harness::test_eval_output_byte_equal_across_two_runs` parametrised over all 10 cases verifies byte equality (timestamps + ULIDs stripped — `datetime.now` drifts + claim_ids minted fresh each run; the prose body is identical).               |
| **WI-4** A.1 subscriber-ACL fence holds                                                                 | D.12's smoke (`test_a1_subscriber_acl_fence_present`) imports `_FORBIDDEN_SUBSCRIPTIONS` from `shared.fabric.client` and asserts `"remediation" -> {"claims.>"}` is still in place. The fence is enforced at the substrate layer (ADR-012); D.12 inherits the guarantee + probes its presence at every test run.        |

## ADR conformance

| ADR | Provision                                     | Verification                                                                                                                                                                                                                                                                                                                                                             |
| --- | --------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 005 | Async tool-wrapper convention                 | `read_sibling_state` uses async SemanticStore calls; `hypothesize` is async; `claims_publisher` is async; no blocking DB / network I/O on the event loop.                                                                                                                                                                                                                |
| 006 | LLM adapter                                   | Hypothesizer imports `charter.llm.LLMProvider` Protocol; agent driver doesn't import `anthropic` / `openai` directly. CLI builds providers via `charter.llm_adapter.config_from_env()` + `make_provider()`.                                                                                                                                                              |
| 007 | Reference NLAH (v1.1 + v1.2)                  | **v1.1** — no per-agent `llm.py`; hypothesizer calls `charter.llm.LLMProvider` directly. **v1.2** — `nlah_loader.py` is a 26-LOC shim over `charter.nlah_loader` (under the 35-LOC budget). D.12 is the **11th agent** shipped natively against v1.2.                                                                                                                    |
| 010 | Within-agent version extension                | Execution-status table is the single source of truth for task-commit pinning; deferred features documented in README §Deferred + plan §Next plans queued.                                                                                                                                                                                                                |
| 011 | PR-flow + branch protection discipline        | One-task-one-PR for all 16 tasks; LOW-RISK label on every PR except #127 (SAFETY-CRITICAL — bundled the small `SemanticStore.list_entities_by_type` substrate addition); verified-against-HEAD line in every PR body; no `--no-verify` / `--no-gpg-sign` shortcuts.                                                                                                      |
| 012 | `claims.>` subject namespace (6th fabric bus) | **D.12 is the first publisher.** Uses `shared.fabric.claims_subject(customer_id, "curiosity")` + `shared.fabric.CLAIMS_STREAM` + `JetStreamClient`. Subscriber-ACL fence (forbidding A.1 from consuming `claims.>`) is intact + asserted in D.12's smoke (WI-4). The ADR's deferred wire-format Q is resolved by D.12 Q1: lightweight `nexus_claim` envelope (NOT OCSF). |

## Architecture notes for future maintainers

### First generative agent + first claims.> publisher

D.12 is the first generative agent in the fleet — the proactive counterpart to D.7 Investigation. Where D.7 explains observed events, D.12 proposes targets to look at. Same LLM-driven pattern, opposite direction.

D.12 is also the **first publisher** on the `claims.>` substrate (ADR-012). The substrate was shipped specifically to unblock D.12 (it was the only mid-sequence exception allowed under the Path-B operating rule). Subscribers (D.7 / D.5 / D.8) wire up in their v0.2 plans; D.12 is producer-only.

### Two-layer Q6 defence + reviewer reuse

D.12 reuses D.13's `synthesis.reviewer._scan_classifier_labels` directly. Both agents enforce the same Q6 contract end-to-end — no regex-duplication drift risk. When you add a new LLM-driven agent (A.4 Meta-Harness will be next), import the same helper rather than copying the patterns.

The first layer of Q6 defence is the prompt template (`hypothesis.md` instructs the LLM categorically). The second layer is the deterministic reviewer. Both layers ship in v0.1; the eval case 05 retry-probe verifies the loop end-to-end.

### Single-tenant `semantic_store=None` + `js_client=None` posture

D.12 v0.1's CLI defaults to "produce workspace artifacts, skip PERSIST + PUBLISH." This is consistent with D.13's `semantic_store=None` default but extends to a second opt-in axis (`js_client=None`). Multi-tenant production blocks on the future SET LOCAL `$1` tenant-RLS substrate-fix plan; live `claims.>` integration blocks on operator-side NATS deployment. v0.1 ships with both off; operators wire them as the substrate becomes ready.

### Mixed-customer batch posture

The `kg_writer.upsert_hypotheses` + `claims_publisher.publish_claims` helpers support mixed-customer batches at the publisher layer (each entity/claim uses its OWN `customer_id` for tenant scoping). The driver always builds single-customer batches because Q5 forbids cross-tenant analysis upstream, but the publisher is mixed-batch-safe as defence-in-depth.

### ULID claim_id mint + rationale_ref backfill

D.12's driver mints a fresh ULID per emitted hypothesis at the PERSIST/PUBLISH boundary. The ULID flows two directions: it becomes the `CuriosityClaim.claim_id` AND backfills `ProbeDirective.rationale_ref` (which the LLM emitted as `""` per the prompt template). Both `Hypothesis` and `ProbeDirective` are frozen pydantic, so the backfill builds new instances — the LLM's original hypothesis instance is replaced wholesale with one that has the claim_id wired through.

## Path-B sequence advances

D.12 was **#5 of the 7 unbuilt agents** in the Path-B-breadth-first ordering. After this closure:

- **15 of 17 agents at v0.1** (was 14 after D.13 closure on 2026-05-21).
- **Next agent:** A.4 Meta-Harness (6th in the sketch §8 sequence). **Dependencies:** all 6 D-track agents existing with eval suites — **now true** after D.12 closes. No blockers.
- **Remaining v0.1 work:** A.4 Meta-Harness → Supervisor (#0).

## Cross-references

- Plan: [`docs/superpowers/plans/2026-05-21-d-12-curiosity-v0-1.md`](../superpowers/plans/2026-05-21-d-12-curiosity-v0-1.md)
- README + smoke runbook: [`packages/agents/curiosity/README.md`](../../packages/agents/curiosity/README.md)
- Sketch §4 (D.12 scope): [`docs/superpowers/sketches/2026-05-20-remaining-agents-sketch.md`](../superpowers/sketches/2026-05-20-remaining-agents-sketch.md)
- Substrate ADR: [ADR-012 — `claims.>` subject namespace](decisions/ADR-012-claims-subject-namespace.md)
- Sister agents in Path-B sequence: [D.5 v0.1](d-5-data-security-v0-1-verification-2026-05-21.md) · [D.8 v0.1](d-8-threat-intel-v0-1-verification-2026-05-21.md) · [D.6 v0.1](d-6-compliance-v0-1-verification-2026-05-21.md) · [D.13 v0.1](d-13-synthesis-v0-1-verification-2026-05-21.md)
