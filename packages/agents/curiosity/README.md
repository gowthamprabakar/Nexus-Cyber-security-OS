# `nexus-curiosity-agent`

Curiosity Agent — **D.12**; **fifth of the 7 unbuilt agents** shipped under the [2026-05-20 Path-B-breadth-first operating rule](../../../docs/superpowers/sketches/2026-05-20-agent-version-roadmaps.md); **fifteenth under [ADR-007](../../../docs/_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md)** (F.3 / D.1 / D.2 / D.3 / F.6 / D.7 / D.4 / multi-cloud-posture / k8s-posture / A.1 / D.5 / D.8 / D.6 / D.13 / **D.12**). **The first generative agent in the fleet** — emits hypotheses about what might be under-scanned, not findings about what was scanned. **The first publisher** on the new `claims.>` substrate introduced by [ADR-012](../../../docs/_meta/decisions/ADR-012-claims-subject-namespace.md).

> **v0.1 shipped 2026-05-21.** 16 tasks, PRs #124-#140 merged. 227+ tests passing. 10/10 eval cases pass. WI-1 (first `claims.>` publisher) + WI-2 (Q6 no-classifier-substring posture) + WI-3 (stub-LLM byte-equal determinism) + WI-4 (A.1 subscriber-ACL fence still holds) all verified at unit, eval, and CLI layers. See [`docs/_meta/d-12-curiosity-v0-1-verification-2026-05-21.md`](../../../docs/_meta/d-12-curiosity-v0-1-verification-2026-05-21.md) for the closure record.

## Scope (v0.1)

**3 emit directions per run:**

1. **`SemanticStore` entity** (`entity_type="hypothesis"`) — persistent KG record. External_id is `<customer_id>:<run_id>:<hypothesis_idx>`. One entity per emitted hypothesis (unlike D.13's single `SynthesisReportEntity` per run).
2. **`claims.>` fabric publish** on `claims.tenant.<customer_id>.agent.curiosity`. The lightweight `nexus_claim` envelope (NOT OCSF) per ADR-012's wire-format resolution.
3. **`hypotheses.md`** workspace markdown for operator review + **`probe_directives.json`** for downstream D.7 / D.5 / D.8 v0.2 consumer integration.

**Detection** (Stage 2): ONE deterministic gap detector ships in v0.1 — **region-gap** (regions with `asset_count >= 10` AND (no findings ever observed OR `days_since_last_finding >= 30`)). Future v0.2 adds asset-type / time-window / severity-distribution / classifier-label / control-coverage gap shapes.

**LLM call structure** (Stage 3): **One LLM call per run** (skipped entirely when DETECT returns no gaps — the common case). Single `LLMProvider.complete()` call against the bundled `hypothesis.md` prompt template; returns structured JSON with up to `_MAX_HYPOTHESES_PER_RUN=5` hypotheses. `temperature=0.0`; model pinned at `claude-haiku-4-5-20251001` by default (operator override via `--model-pin`).

**Stub-LLM eval harness** keeps the eval suite deterministic + offline. Single-tenant `semantic_store=None` + `js_client=None` opt-in defaults per Q5.

## Deferred to D.12 v0.2 / v0.3+

- **v0.2:** asset-type / time-window / severity-distribution / classifier-label / control-coverage gap detectors; live-LLM smoke test (`NEXUS_LIVE_LLM=1` gated); D.7 / D.5 / D.8 probe-directive consumer integration (lands in those agents' v0.2 plans, not here); F.7 `findings.>` event correlation for closed-loop "did the probe-directive surface a finding" tracking.
- **v0.3+:** cross-customer baseline drift detection; ML-driven anomaly detection; Curiosity-consumes-Curiosity feedback loops (new claims.> subscription path); auditor-export PDF of all hypotheses + their resolution status.
- **Multi-tenant production** blocks on the future SET LOCAL `$1` tenant-RLS substrate-fix plan.

Full version trajectory: [`docs/superpowers/sketches/2026-05-20-agent-version-roadmaps.md`](../../../docs/superpowers/sketches/2026-05-20-agent-version-roadmaps.md).

## Q6 invariant (carried through from D.5 + D.13)

**Two-layer defence against classifier-substring leakage via LLM hallucination:**

1. **Prompt-template Q6 reminder** — the `hypothesis.md` template instructs the LLM to refer to classifier-matched data categorically (`"data classified as ssn"`) rather than producing the matched substring (`"123-45-6789"`). Strongest reminder in the template.
2. **Stage 4 REVIEW regex-guard** — deterministic regex pass over each `Hypothesis.statement` + `Hypothesis.rationale` + `probe_directive.rationale_ref` for classifier patterns (SSN, credit-card with Luhn check, AWS access key, JWT). **Reuses D.13's `synthesis.reviewer._scan_classifier_labels`** so both agents enforce the same Q6 contract end-to-end.

On Q6 violation: the reviewer returns `retry_hint="q6_violation"`; the driver re-runs `hypothesize()` with `q6_violation_retry_hint=True` (budget=1 retry per run; matches D.13). On retry-budget exhaustion: accept the degraded draft + log a warning.

Eval case 05 (`q6_no_classifier_substring_in_hypothesis`) is the WI-2 regression probe.

## ADR-007 + ADR-012 conformance

D.12 is the **15th** agent under the ADR-007 reference template, **11th** shipped natively against v1.2's 21-LOC NLAH shim pattern (D.3 / F.6 / D.7 / D.4 / multi-cloud-posture / k8s-posture / D.5 / D.8 / D.6 / D.13 / **D.12**). Inherits v1.1 (LLM adapter via `charter.llm_adapter`; no per-agent `llm.py`) and v1.2 (NLAH loader is a 26-LOC shim over `charter.nlah_loader`, under the 35-LOC budget).

**ADR-012 conformance.** D.12 is the **first publisher** on the `claims.>` substrate. It uses the public exports from `shared.fabric`: `claims_subject(customer_id, agent_id)` for subject construction, `CLAIMS_STREAM` for the StreamSpec, and `JetStreamClient` for the publish call. The subscriber-ACL fence ADR-012 ships (forbidding A.1 Remediation from consuming `claims.>`) still holds — D.12's smoke test asserts the `_FORBIDDEN_SUBSCRIPTIONS` map at every test run (WI-4).

## Smoke runbook

### 1. Run the unit test suite

```bash
uv run pytest packages/agents/curiosity -q
```

Expected: **227 passed** in <1s.

### 2. Run the local eval suite

```bash
uv run curiosity eval
```

(Defaults to the bundled `packages/agents/curiosity/eval/cases/` directory.)

Expected output: `10/10 passed`. Exit code 1 on any failure with per-failure `FAIL <case_id>: <reason>` lines. The suite is deterministic + offline — canned LLM responses live in `eval/stub_responses/<case_id>/responses.json`. WI-3 byte-equal acceptance gate is verified at test time in `tests/test_stub_llm_harness.py`.

### 3. Run the agent against an ExecutionContract

```bash
NEXUS_LLM_PROVIDER=anthropic \
NEXUS_LLM_MODEL_PIN=claude-haiku-4-5-20251001 \
ANTHROPIC_API_KEY=... \
uv run curiosity run \
    --contract path/to/execution-contract.yaml
```

The Curiosity Agent writes `hypotheses.md` + `probe_directives.json` to the contract's workspace and prints a one-line digest:

```text
curiosity: 1 hypotheses | 1 gaps addressed | 0 Q6 retries
customer: cust_eval
run_id: 01J7M3X9Z1K8RPVQNH2T8DBHFZ
workspace: /var/run/nexus/curiosity/01J7M.../ws
```

**Experimental flags** (reserved for v0.2):

- `--semantic-store-dsn TEXT` — v0.2 multi-tenant production wiring. v0.1 logs a warning and runs single-tenant (`semantic_store=None`).
- `--nats-url TEXT` — v0.2 live `claims.>` publish wiring. v0.1 logs a warning and runs without a `JetStreamClient` (`js_client=None`; `claims.>` publish no-ops).

v0.1's CLI default is "produce workspace artifacts, skip PERSIST + PUBLISH" — the operator reads `hypotheses.md` to see what the LLM proposed; persistence + fabric emit land in v0.2 when the multi-tenant + NATS substrates are configured.

## Architecture

Seven-stage pipeline (one more than D.13's six — adds **PUBLISH** between PERSIST and HANDOFF for the `claims.>` fabric emit):

```text
INGEST     -> DETECT       -> HYPOTHESIZE   -> REVIEW         -> PERSIST       -> PUBLISH        -> HANDOFF
(SemanticS-  (deterministic  (1 LLM call;     (Q6 substring     (SemanticStore   (claims.>        (hypotheses.md
 tore aggre- region-gap      short-circuits   guard reusing     upsert; opt-in   fabric emit;     + probe_dir-
 gate query  detector)       on empty gaps)   D.13's reviewer)  default None)    opt-in default   ectives.json
 — opt-in                                                                         None)            to charter
 default                                                                                            workspace)
 None)
```

| Stage          | Module                                      | Output                                                                                     |
| -------------- | ------------------------------------------- | ------------------------------------------------------------------------------------------ |
| 1. INGEST      | `tools/sibling_state_reader.py`             | `SiblingState` (per-region asset + finding-aggregate snapshot)                             |
| 2. DETECT      | `tools/coverage_gap_detector.py`            | `tuple[CoverageGap, ...]` (ordered by asset_count desc)                                    |
| 3. HYPOTHESIZE | `hypothesizer.py` + `prompts/hypothesis.md` | `CuriosityDraft` (up to 5 `Hypothesis` + LLM accounting)                                   |
| 4. REVIEW      | `reviewer.py` (+ `synthesis.reviewer`)      | `ReviewVerdict` — shape + Q6 substring guard                                               |
| 5. PERSIST     | `kg_writer.py` + `entities.py`              | `HypothesisEntity` rows in `SemanticStore` (opt-in; default no-op)                         |
| 6. PUBLISH     | `claims_publisher.py`                       | `CuriosityClaim` payloads on `claims.tenant.<tid>.agent.curiosity` (opt-in; default no-op) |
| 7. HANDOFF     | `agent.py`                                  | `hypotheses.md` + `probe_directives.json` to charter workspace + `CuriosityReport`         |

## Prompt-template authoring

Prompt template lives in [`src/curiosity/prompts/hypothesis.md`](src/curiosity/prompts/hypothesis.md), loaded via `importlib.resources` (ships inside the wheel). Single template:

- **`hypothesis.md`** — instructs the LLM to return a JSON object with `{"hypotheses": [...]}` listing up to 5 hypotheses. Each entry must carry a statement (1-2 sentences, max 400 chars) + rationale (3-5 sentences, max 1500 chars) + probe_directive (XOR on `target_resource_arn` / `target_finding_id`) + `cited_gap` echoed from the input. The **Q6 reminder block** instructs the LLM to refer to classifier-matched data categorically by label, never producing SSN-shape / credit-card-shape / AWS-access-key-shape / JWT-shape text. "JSON only — no preamble" constraint.

**Stub-vs-live LLM toggle.** Stub mode is the default for the eval suite (`uv run curiosity eval`) — canned responses live in `eval/stub_responses/<case_id>/responses.json`. Live mode is the default for `curiosity run` — the CLI builds an `LLMProvider` from `charter.llm_adapter.config_from_env()`.

## License

BSL 1.1 per [ADR-001](../../../docs/_meta/decisions/ADR-001-monorepo-bootstrap.md). Substrate this agent consumes (`charter`, `shared`, `eval-framework`, `synthesis`, `cloud-posture`, `compliance`, `threat-intel`) is Apache 2.0; the agent itself is BSL.
