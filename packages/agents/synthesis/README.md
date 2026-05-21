# `nexus-synthesis-agent`

Synthesis Agent — **D.13**; **fourth of the 7 unbuilt agents** shipped under the [2026-05-20 Path-B-breadth-first operating rule](../../../docs/superpowers/sketches/2026-05-20-agent-version-roadmaps.md); **fourteenth under [ADR-007](../../../docs/_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md)** (F.3 / D.1 / D.2 / D.3 / F.6 / D.7 / D.4 / multi-cloud-posture / k8s-posture / A.1 / D.5 / D.8 / D.6 / **D.13**). Customer-facing narration: turns sibling-agent findings (D.7 Investigation + D.6 Compliance + F.3 Cloud Posture) into operator-readable markdown summaries.

**D.13 is the first agent that actually calls the LLM in its hot path.** The 13 agents before it plumb `llm_provider` through their drivers but never invoke it — narration is out-of-scope per F.3's NLAH ("customer-facing narration belongs to the Synthesis Agent"). D.13 closes that loop.

> **v0.1 shipped 2026-05-21.** 16 tasks, PRs #106-#121 merged. 214+ tests passing. 10/10 eval cases pass. WI-1 (first-LLM-call budget consumption) + WI-2 (Q6 no-classifier-substring posture) + WI-3 (stub-LLM byte-equal determinism) all verified at unit, eval, and CLI layers. See [`docs/_meta/d-13-synthesis-v0-1-verification-2026-05-21.md`](../../../docs/_meta/d-13-synthesis-v0-1-verification-2026-05-21.md) for the closure record.

## Scope (v0.1)

**2 narrative artifacts:**

- **`narrative.md`** — sectioned per-finding-class. 4–6 sections is typical; one section per major theme (identity posture, storage exposure, network exposure, compliance posture, runtime activity). H2 per section + cited-finding-id backtick list.
- **`executive_summary.md`** — 1-paragraph C-suite digest (60–200 words) + key-metrics block. The CISO reads this in 30 seconds before deciding whether to read the full narrative.

**3 sibling-workspace sources** (read-only, operator-pinned via flags):

- `--investigation-workspace` — D.7 Investigation conclusions (narrative spine).
- `--compliance-workspace` — D.6 Compliance posture (compliance section).
- `--cloud-posture-workspace` — F.3 Cloud Posture (technical-details fallback).

**LLM call structure** (per stage 3 of the pipeline):

- 1 **outline call** (returns `SynthesisOutline` JSON: section list + per-section `cited_finding_ids` + `overall_narrative_intent`).
- N **per-section narration calls** (one per outline section; returns markdown body).
- 1 **executive summary call** (returns `ExecutiveSummary` JSON: paragraph + key metrics).

All 3 call types pin `temperature=0.0` and use `claude-haiku-4-5-20251001` by default (operator override via `--model-pin`). Prompt templates loaded via `importlib.resources` from `src/synthesis/prompts/`.

Stub-LLM eval harness keeps the eval suite deterministic + offline. Live-LLM smoke test gated by `NEXUS_LIVE_LLM=1`. Single-tenant `semantic_store=None` opt-in default. **No OCSF emit in v0.1** (deferred to v0.2 pending a `class_uid` ADR).

## Deferred to D.13 v0.2 / v0.3+

- **v0.2:** OCSF emit (requires `class_uid` ADR); periodic re-narration on findings deltas via `findings.>` fabric-event subscription; F.7 `synthesis.produced` fabric event; D.12 Curiosity hypothesis narration (blocks on D.12 itself shipping).
- **v0.3+:** vendor-specific narrative styling; customer-pinned section-template subsets; live re-render on hypothesis updates.
- **Multi-tenant production** blocks on the future SET LOCAL `$1` tenant-RLS substrate-fix plan.

Full version trajectory: [`docs/superpowers/sketches/2026-05-20-agent-version-roadmaps.md`](../../../docs/superpowers/sketches/2026-05-20-agent-version-roadmaps.md).

## Q6 invariant (carried through from D.5)

**Two-layer defence against classifier-substring leakage via LLM hallucination:**

1. **Stage 2 ENRICH context bundle carries structured fields only** — finding IDs, severities, control IDs, classifier _labels_ (`"ssn"`, `"credit_card"`, …). NEVER matched-text substrings, bucket-object key fragments, or `evidence.matched_text`-shaped fields.
2. **Stage 4 REVIEW regex-guards the rendered narrative** for classifier patterns (SSN, credit-card with Luhn check, AWS access key, JWT). On violation: reject with `retry_hint=q6_violation`. The driver re-runs `narrate()` with a `[Q6 RETRY]` banner injected into per-section prompts.

Eval case 07 (`classifier_substring_rejection_and_retry`) is the retry-loop regression probe; eval case 10 (`context_bundle_q6_invariant`) is the first-line-scrub probe. Both are WI-2 acceptance gates.

## ADR-007 conformance

D.13 is the **14th** agent under the reference template, **10th** shipped natively against v1.2 (D.3 / F.6 / D.7 / D.4 / multi-cloud-posture / k8s-posture / D.5 / D.8 / D.6 / **D.13**). Inherits v1.1 (LLM adapter via `charter.llm_adapter`; no per-agent `llm.py`) and v1.2 (NLAH loader is a 26-LOC shim over `charter.nlah_loader`, under the 35-LOC budget).

**First-LLM-call agent.** D.13 is the first agent in the fleet where the LLM is on the hot path. The `narrate()` orchestration in [`narrator.py`](src/synthesis/narrator.py) calls `charter.llm.LLMProvider.complete()` 1 + N + 1 times per run (outline + N section narrations + exec summary). Budget consumption is tracked by the provider's charter-context audit emission (WI-1).

## Smoke runbook

### 1. Run the unit test suite

```bash
uv run pytest packages/agents/synthesis -q
```

Expected: **214 passed, 1 skipped** in <1s. (The skipped test is the `NEXUS_LIVE_LLM=1`-gated live smoke; see step 4.)

### 2. Run the local eval suite

```bash
uv run synthesis eval
```

(Defaults to the bundled `packages/agents/synthesis/eval/cases/` directory.)

Expected output: `10/10 passed`. Exit code 1 on any failure with per-failure `FAIL <case_id>: <reason>` lines. The suite is deterministic + offline — canned LLM responses live in `eval/stub_responses/<case_id>/responses.json`. WI-3 byte-equal acceptance gate is verified at test time in `tests/test_stub_llm_harness.py`.

### 3. Run the agent against sibling-agent workspaces

```bash
NEXUS_LLM_PROVIDER=anthropic \
NEXUS_LLM_MODEL_PIN=claude-haiku-4-5-20251001 \
ANTHROPIC_API_KEY=... \
uv run synthesis run \
    --contract path/to/execution-contract.yaml \
    --investigation-workspace path/to/d7-investigation-run/ \
    --compliance-workspace path/to/d6-compliance-run/ \
    --cloud-posture-workspace path/to/f3-cloud-posture-run/
```

Each sibling workspace must contain a `findings.json` produced by the corresponding agent. The Synthesis Agent writes `narrative.md` + `executive_summary.md` to the contract's workspace and prints a one-line digest:

```text
synthesis: 4 sections | 7 cited findings | 0 Q6 retries
customer: cust_eval
run_id: 01J7M3X9Z1K8RPVQNH2T8DBHFZ
workspace: /var/run/nexus/synthesis/01J7M.../ws
```

**Workspace flags are individually optional.** Omitting one silently contributes zero findings from that source; the run still produces a valid narrative. All three may be omitted (the warning is logged to stderr).

### 4. Run the live-LLM smoke test

```bash
NEXUS_LIVE_LLM=1 \
NEXUS_LLM_PROVIDER=anthropic \
NEXUS_LLM_MODEL_PIN=claude-haiku-4-5-20251001 \
ANTHROPIC_API_KEY=... \
uv run pytest packages/agents/synthesis/tests/integration/ -v
```

Skipped in default CI runs. Operator-side smoke verification — runs the agent end-to-end against a real LLM provider with a 1-finding F.3 fixture and asserts shape correctness (≥1 section, non-empty exec summary, no Q6 retries).

## Architecture

Six-stage pipeline:

```text
INGEST     -> ENRICH       -> NARRATE        -> REVIEW         -> SUMMARIZE  -> HANDOFF
(3 sibling   (build           (3 LLM calls:     (deterministic     (assemble     (write narrative.md
 workspace    structured       outline +         shape +            SynthesisRe-  + executive_summary.md
 reads via    ContextBundle    N sections +      Q6 substring       port from     to charter workspace;
 forgiving    -- Q6 first-     exec summary)     guard; retry       draft +       optional KG upsert)
 reader)      line scrub)                        on Q6 violation)   metadata)
```

| Stage        | Module                                                             | Output                                                                            |
| ------------ | ------------------------------------------------------------------ | --------------------------------------------------------------------------------- |
| 1. INGEST    | `tools/sibling_workspace_reader.py`                                | `SiblingFindings` (3 tuples of OCSF dicts)                                        |
| 2. ENRICH    | `context_bundle.py`                                                | `ContextBundle` — structured fields only (no matched substrings) (**Q6 layer 1**) |
| 3. NARRATE   | `narrator.py` + `prompts/{outline,narration,executive_summary}.md` | `SynthesisDraft` (outline + N sections + exec summary)                            |
| 4. REVIEW    | `reviewer.py`                                                      | `ReviewVerdict` — shape + Q6 substring guard (**Q6 layer 2**)                     |
| 5. SUMMARIZE | `agent.py::_assemble_report`                                       | `SynthesisReport` with deduped `cited_finding_ids` + `review_retries`             |
| 6. HANDOFF   | `agent.py`                                                         | `narrative.md` + `executive_summary.md` to charter workspace + optional KG upsert |

## Prompt-template authoring

Prompt templates live in [`src/synthesis/prompts/`](src/synthesis/prompts/) as markdown files loaded via `importlib.resources` (so they ship inside the wheel). Three templates:

- **`outline.md`** — instructs the LLM to return a `SynthesisOutline` JSON object (1–12 sections, each with heading + intent + cited_finding_ids; plus `overall_narrative_intent`). "NO PROSE" constraint — JSON only.
- **`narration.md`** — instructs the LLM to write the markdown body of one section. Carries the **Q6 instruction block** (never produce SSN-shape / credit-card-shape / AWS-access-key-shape / JWT-shape text). 100–400 words per section.
- **`executive_summary.md`** — instructs the LLM to return an `ExecutiveSummary` JSON (paragraph + key_metrics). Strongest Q6 reminder since exec summary is highest-visibility output.

**Stub-vs-live LLM toggle.** Stub mode is the default for the eval suite (`uv run synthesis eval`) — canned responses live in `eval/stub_responses/<case_id>/responses.json`. Live mode is the default for `synthesis run` — the CLI builds an `LLMProvider` from `charter.llm_adapter.config_from_env()`.

## License

BSL 1.1 per [ADR-001](../../../docs/_meta/decisions/ADR-001-monorepo-bootstrap.md). Substrate this agent consumes (`charter`, `shared`, `eval-framework`, `investigation`, `compliance`, `cloud-posture`) is Apache 2.0; the agent itself is BSL.
