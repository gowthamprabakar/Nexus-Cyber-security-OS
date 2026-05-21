# Tool surface — Synthesis Agent (D.13 v0.1)

D.13 v0.1 ships **no charter-registered tools.** Sibling-workspace reads are pure filesystem I/O (no cloud-call budget); LLM calls flow through `charter.llm.LLMProvider` directly (budget tracked via the provider's audit emission). The tool surface is intentionally minimal.

## In-driver helpers (NOT charter-registered)

These are called directly from `synthesis.agent.run`, not through `ctx.call_tool`. They have no per-call budget consumption.

### `read_sibling_workspaces`

Read `findings.json` from up to three operator-pinned sibling workspaces.

- **Signature:** `async read_sibling_workspaces(*, investigation_workspace, compliance_workspace, cloud_posture_workspace) -> SiblingFindings`
- **Arguments:**
  - `investigation_workspace: Path | None` — D.7 Investigation workspace; if None, that source contributes zero findings.
  - `compliance_workspace: Path | None` — D.6 Compliance workspace; same skip-on-None semantics.
  - `cloud_posture_workspace: Path | None` — F.3 Cloud Posture workspace; same.
- **Returns:** `SiblingFindings` dataclass — three tuples of OCSF finding dicts, plus convenience properties (`total_findings`, `any_source_present`).
- **Failure modes:** every error path (missing workspace, missing `findings.json`, malformed JSON, non-mapping payload, non-list `findings`, non-dict entries) is silently dropped. A missing source contributes zero findings; the run continues.

### `build_context_bundle`

Stage 2 ENRICH — project the raw `SiblingFindings` into a structured `ContextBundle` for the LLM.

- **Signature:** `build_context_bundle(sibling_findings, *, customer_id, scan_window_start, scan_window_end) -> ContextBundle`
- **Q6 invariant:** strips every freeform-substring field. Surfaces classifier _labels_ (`ssn`, `credit_card`, …) but NEVER the matched substring values.

### `narrate`

Stage 3 NARRATE — three-call LLM orchestration.

- **Signature:** `async narrate(*, llm_provider, context_bundle, model_pin, q6_violation_retry_hint=False) -> SynthesisDraft`
- **Three calls:**
  1. Outline call (returns `SynthesisOutline` pydantic JSON).
  2. Per-section narration calls (returns markdown body per section).
  3. Executive summary call (returns `ExecutiveSummary` pydantic JSON).
- **Typed errors:** `OutlineCallError`, `NarrationCallError`, `ExecutiveSummaryCallError`. Per-section failure is forgiving (placeholder body); outline / exec-summary failures bubble up to the driver's fallback path.

### `review`

Stage 4 REVIEW — deterministic narrative validator.

- **Signature:** `review(draft) -> ReviewVerdict`
- **Two layers:** shape checks + Q6 substring guard (SSN / credit-card with Luhn / AWS access key / JWT).
- **Retry-hint contract:** `q6_violation` → driver re-runs `narrate` with `q6_violation_retry_hint=True`; `shape_violation` → driver accepts the degraded draft.

## Budget envelope

D.13 v0.1's budget is dominated by **LLM calls**: 1 outline + N section narrations + 1 exec summary. With N=6 sections, that's 8 calls per run (1 retry doubles to 16). Token budget should comfortably cover ~50K tokens for v0.1's modest section counts (operator-summary narratives sit at 4–6 sections).

Filesystem I/O is two output files (`narrative.md` + `executive_summary.md`) — typical size ~3 KB each. The `mb_written` budget axis is over-provisioned.
