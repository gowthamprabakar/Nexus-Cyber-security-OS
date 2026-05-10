# F.2 — Eval Framework v0.1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Pause for review after each numbered task.

**Goal:** Ship the standalone **`nexus-eval-framework`** package — Apache 2.0, vendor-SDK-optional — that the cloud-posture placeholder runner ([`cloud_posture._eval_local`](../../../packages/agents/cloud-posture/src/cloud_posture/_eval_local.py)) gets extracted into. Provides: typed case + result + trace shapes; async suite runner; provider-parity matrix runs; baseline-vs-candidate comparison; configurable gates; markdown + JSON outputs; CLI.

**Architecture:** Generic `EvalRunner` Protocol that agents implement; framework orchestrates suites against any registered runner. Trace capture wraps `charter.audit.AuditLog` so every LLM call / tool call / output write is recorded per case. Comparison reports surface drift across runs (run vs baseline, provider A vs provider B). Gate config (YAML) declares pass-rate / regression-tolerance / token-budget thresholds. CLI wires all three workflows: run, compare, gate.

**Tech stack:** Python 3.12 · Apache 2.0 · pydantic 2.9 (for typed I/O) · PyYAML · click (CLI) · pytest · `nexus-charter` (workspace dep — for `LLMProvider`, `AuditLog`, `verify_audit_log`) · `nexus-shared` (workspace dep — for `correlation_scope`, `NexusEnvelope`).

**Depends on:** F.1 (charter), Task 5.5 (fabric scaffolding), Task 8.5 (LLMProvider abstraction), Task 12 (cloud-posture placeholder runner — gets migrated here).

**Defers (Phase 2+):** distributed eval execution; real-time eval streaming; eval cases auto-generated from production traces; Meta-Harness loop integration (the framework provides the substrate; the loop itself is A.4).

**Reference template:** [F.3 — Cloud Posture](2026-05-08-f-3-cloud-posture-reference-nlah.md). This plan reuses every pattern that ADR-007 codified (async-by-default, Apache 2.0 sister of the charter package, `[project.scripts]` CLI entry point, `tests/integration/` opt-in live tests, py.typed marker, lockstep mypy strict). Don't re-derive what's already there — point at the F.3 implementation for "how" and focus this plan on "what."

---

## Execution status

```
1 → 2 → 3 → 4 → 5 → 6 → 7 → 8 → 9 → 10 → 11 → 12 → 13 → 14 → 15 → 16
```

| Task | Status  | Commit    | Notes                                                                                                  |
| ---- | ------- | --------- | ------------------------------------------------------------------------------------------------------ |
| 1    | ✅ done | `f905af0` | Bootstrap `packages/eval-framework/` (pyproject, license, py.typed, cli stub)                          |
| 2    | ✅ done | `e800fff` | Core types: EvalCase, EvalResult, SuiteResult, EvalTrace; 19 tests                                     |
| 3    | ✅ done | `7ca4150` | YAML loader: `load_case_file` + `load_cases`; loads cloud-posture suite unchanged; 11 new tests        |
| 4    | ✅ done | `2ccaab1` | `EvalRunner` Protocol (`@runtime_checkable`) + `FakeRunner` test double; 8 tests                       |
| 5    | ✅ done | `8c87e46` | Async `run_suite(cases, runner, …)` with per-case workspace + per-case timeout; 18 tests               |
| 6    | ✅ done | `1e13530` | `build_trace_from_audit_log` parser + verifier wrap + run_suite integration; 12 new tests              |
| 7    | ✅ done | `1b4d73c` | `CloudPostureEvalRunner` migrated from `_eval_local`; 10/10 shipped cases pass via `run_suite`         |
| 8    | ✅ done | `7b36e5f` | `diff_results` — case-id-keyed join, regression/improvement classification, drift markers; 13 tests    |
| 9    | ✅ done | `a8700bf` | `Gate` + `apply_gate` — pass-rate, regressions vs baseline, token-delta, p95 duration; 15 tests        |
| 10   | ✅ done | `6293dec` | Markdown renderers — suite + comparison + gate; auditor-readable; 19 new tests                         |
| 11   | ✅ done | `7aa44aa` | JSON output — `suite_to_json` / `from_json` + comparison; round-trip equality; 13 new tests            |
| 12   | ✅ done | `d756f09` | `run_across_providers` — multi-provider parity per ADR-003; drift surfaces via diff_results; 7 tests   |
| 13   | ✅ done | `916b5aa` | CLI — `eval-framework run / compare / gate` via setuptools entry-points; 10 tests via Click runner     |
| 14   | ✅ done | `6268b64` | cloud-posture migrated to framework; entry-point registered; `_eval_local` + `test_eval_local` deleted |
| 15   | ✅ done | `faf0049` | README + ADR-008 — eval-framework architecture; Apache 2.0 sister of charter; substrate-not-policy     |
| 16   | ✅ done | _next_    | Final verification — all 6 gates green; 94.93% cov; 16/16 tasks; **F.2 accepted as code-complete**     |

ADR references: [ADR-001](../../_meta/decisions/ADR-001-monorepo-bootstrap.md) (Apache 2.0 split), [ADR-003](../../_meta/decisions/ADR-003-llm-provider-strategy.md) (cross-provider parity gate), [ADR-005](../../_meta/decisions/ADR-005-async-tool-wrapper-convention.md) (async-by-default), [ADR-007](../../_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md) (template patterns the runner follows).

---

## File Structure

```
packages/eval-framework/
├── pyproject.toml                              # name=nexus-eval-framework, Apache 2.0
├── README.md
├── src/eval_framework/
│   ├── __init__.py                             # exports the public surface
│   ├── py.typed                                # mypy marker
│   ├── cases.py                                # EvalCase, load_cases, validation
│   ├── results.py                              # EvalResult, SuiteResult, ComparisonReport
│   ├── trace.py                                # EvalTrace + reader for charter audit.jsonl
│   ├── runner.py                               # EvalRunner Protocol, FakeRunner
│   ├── suite.py                                # run_suite, run_across_providers
│   ├── compare.py                              # diff_results, drift detection
│   ├── gate.py                                 # Gate config + apply_gate
│   ├── render_md.py                            # markdown renderers
│   ├── render_json.py                          # JSON serializer
│   └── cli.py                                  # `eval-framework` command group
├── tests/
│   ├── test_cases.py
│   ├── test_runner.py
│   ├── test_suite.py
│   ├── test_trace.py
│   ├── test_compare.py
│   ├── test_gate.py
│   ├── test_render_md.py
│   ├── test_render_json.py
│   ├── test_cli.py
│   └── integration/                            # opt-in (NEXUS_LIVE_OLLAMA / cross-provider)
│       └── test_provider_parity_live.py
└── examples/                                   # tutorial-grade examples (one per major feature)
    ├── 01-write-a-runner.md
    ├── 02-run-a-suite.md
    └── 03-compare-and-gate.md

packages/agents/cloud-posture/
└── src/cloud_posture/
    ├── _eval_local.py                          # DELETED in Task 14
    └── eval_runner.py                          # NEW in Task 7: CloudPostureEvalRunner
```

---

## Tasks

### Task 1: Bootstrap `packages/eval-framework/`

**Files:** Replace skeleton at `packages/eval-framework/pyproject.toml`, create `src/eval_framework/__init__.py`, `src/eval_framework/py.typed`, basic `tests/test_smoke.py`.

- [ ] **Step 1: Replace `pyproject.toml`** — name=`nexus-eval-framework`, Apache 2.0 license (`license = { file = "../../LICENSE-APACHE" }`), `requires-python = ">=3.12,<3.13"`. Required deps: `pydantic>=2.9.0`, `pyyaml>=6.0.2`, `click>=8.1.0`, `nexus-charter`, `nexus-shared`. Optional `[anthropic]` and `[openai-compatible]` extras pin the provider SDKs only when eval needs to invoke an LLM directly (most uses pass providers in from the caller, so the deps stay light). Add `[project.scripts]` entry point: `eval-framework = "eval_framework.cli:main"`. Add `[tool.uv.sources]` workspace pins for charter + shared.
- [ ] **Step 2: Empty `__init__.py`** — exports populated as later tasks land. Add `__version__ = "0.1.0"`.
- [ ] **Step 3: Add `py.typed` marker** so cross-package mypy resolves.
- [ ] **Step 4: Smoke test** — `from eval_framework import __version__` resolves; existing `test_smoke.py` keeps passing.
- [ ] **Step 5: `uv sync --all-packages --all-extras`** — confirm new package builds and the entry point is registered (`uv run eval-framework --help` works once Task 13 ships).
- [ ] **Step 6: Commit** — `feat(eval-framework): bootstrap apache-2.0 package skeleton`.

**Acceptance:** package installs, `from eval_framework import __version__` returns `"0.1.0"`, mypy strict clean over the package's source tree.

---

### Task 2: Core types — `EvalCase`, `EvalResult`, `SuiteResult`, `EvalTrace`

**Files:** `src/eval_framework/cases.py` (skeleton), `src/eval_framework/results.py`, `src/eval_framework/trace.py`, `tests/test_cases.py`, `tests/test_results.py`.

Pin the wire shapes that downstream consumers (Meta-Harness, CI gates, comparison reports) will read. Pydantic models so JSON I/O is free; `frozen=True` for hashability.

```python
# results.py
class EvalResult(BaseModel):
    case_id: str
    runner: str                  # agent name from runner.agent_name
    passed: bool
    failure_reason: str | None
    actuals: dict[str, Any]
    duration_sec: float
    trace: EvalTrace
    model_config = ConfigDict(frozen=True)


class SuiteResult(BaseModel):
    suite_id: str                # ULID minted by the suite runner
    runner: str
    started_at: datetime
    completed_at: datetime
    cases: list[EvalResult]
    provider_id: str | None      # provider_map key the suite ran against (None = deterministic)
    model_pin: str | None        # exact model pin (None = deterministic)
    metadata: dict[str, Any]     # caller-provided run labels (commit, branch, ci_id, …)

    @property
    def total(self) -> int: ...
    @property
    def passed(self) -> int: ...
    @property
    def pass_rate(self) -> float: ...
```

```python
# trace.py
class EvalTrace(BaseModel):
    audit_log_path: Path | None
    llm_calls: list[LLMCallRecord] = []  # provider_id, model_pin, input_tokens, output_tokens, stop_reason, duration_sec
    tool_calls: list[ToolCallRecord] = []
    output_writes: list[OutputWriteRecord] = []
    audit_chain_valid: bool | None       # set by Task 6 trace-capture
    model_config = ConfigDict(frozen=True)


class LLMCallRecord(BaseModel):
    provider_id: str
    model_pin: str
    input_tokens: int
    output_tokens: int
    stop_reason: str
    started_at: datetime
    duration_sec: float


class ToolCallRecord(BaseModel):
    tool: str
    version: str
    duration_sec: float
```

- [ ] **Step 1: Write failing tests** — pydantic round-trip; SuiteResult.pass_rate; immutability.
- [ ] **Step 2: Implement** the four models with frozen/ConfigDict and computed properties.
- [ ] **Step 3: Tests pass** — ≥ 8 tests.
- [ ] **Step 4: Commit** — `feat(eval-framework): typed evalcase + evalresult + suiteresult + evaltrace`.

**Acceptance:** all four types serialize to JSON and round-trip cleanly. Schema is stable enough that Meta-Harness can read `SuiteResult` without further mapping.

---

### Task 3: YAML case loader + validation

**Files:** `src/eval_framework/cases.py` (full impl), `tests/test_cases.py`.

```python
class EvalCase(BaseModel):
    case_id: str
    description: str
    fixture: dict[str, Any]
    expected: dict[str, Any]
    tags: list[str] = []
    timeout_sec: float = 60.0
    model_config = ConfigDict(frozen=True)


def load_cases(directory: Path | str) -> list[EvalCase]: ...
def load_case_file(path: Path) -> EvalCase: ...
```

- [ ] **Step 1: Write failing tests** — load lex-sorted, reject malformed YAML, reject duplicate `case_id` across files, ignore non-`.yaml` files.
- [ ] **Step 2: Implement** — pydantic does the validation (`ValidationError` for bad shapes); `case_id` uniqueness checked across the directory.
- [ ] **Step 3: Tests pass** — ≥ 6 tests.
- [ ] **Step 4: Commit** — `feat(eval-framework): yaml case loader with pydantic validation`.

**Acceptance:** the cloud-posture suite at `packages/agents/cloud-posture/eval/cases/` loads via `load_cases(...)` without modification (10 cases, no duplicates).

---

### Task 4: `EvalRunner` Protocol + `FakeRunner` test double

**Files:** `src/eval_framework/runner.py`, `tests/test_runner.py`.

```python
@runtime_checkable
class EvalRunner(Protocol):
    @property
    def agent_name(self) -> str: ...

    async def run(
        self,
        case: EvalCase,
        *,
        workspace: Path,
        llm_provider: LLMProvider | None = None,
    ) -> tuple[bool, str | None, dict[str, Any], Path | None]:
        """Return (passed, failure_reason, actuals, audit_log_path).

        The framework wraps this into a full `EvalResult` (adding case_id,
        runner name, duration, trace).
        """


class FakeRunner:
    """Configurable test double. Returns canned (passed, reason, actuals)."""
    def __init__(self, agent_name: str = "fake", *, default_passed: bool = True): ...
    def queue(self, case_id: str, *, passed: bool, failure_reason: str | None = None,
              actuals: dict[str, Any] | None = None) -> None: ...
```

- [ ] **Step 1: Write failing tests** — Protocol is `runtime_checkable`; FakeRunner satisfies it; queued responses returned in order; default fallback.
- [ ] **Step 2: Implement** — Protocol + FakeRunner with internal queue.
- [ ] **Step 3: Tests pass** — ≥ 5 tests.
- [ ] **Step 4: Commit** — `feat(eval-framework): evalrunner protocol and fakerunner test double`.

**Acceptance:** `isinstance(FakeRunner(...), EvalRunner)` is `True`. The Protocol shape matches what `CloudPostureEvalRunner` (Task 7) needs to implement.

---

### Task 5: Async `run_suite(cases, runner, …)`

**Files:** `src/eval_framework/suite.py`, `tests/test_suite.py`.

```python
async def run_suite(
    cases: list[EvalCase],
    runner: EvalRunner,
    *,
    llm_provider: LLMProvider | None = None,
    workspace_root: Path | None = None,
    suite_id: str | None = None,
    metadata: dict[str, Any] | None = None,
    max_concurrency: int = 1,           # serial by default; concurrent later
) -> SuiteResult:
    """Run every case through the runner, collect EvalResults, return SuiteResult."""
```

Per-case workspace: `workspace_root / suite_id / case_id-<uuid8>` so concurrent / re-runs don't collide. Trace capture happens here (calls into Task 6).

- [ ] **Step 1: Write failing tests using FakeRunner** — happy path emits SuiteResult with 3 cases, all passed; partial-fail SuiteResult shows mixed pass/fail; per-case duration_sec is captured; suite_id is a ULID.
- [ ] **Step 2: Implement** — sequential (concurrent comes later via TaskGroup + Semaphore in a follow-up); `asyncio.wait_for(runner.run(...), timeout=case.timeout_sec)` enforces per-case timeout; on `TimeoutError` the result is `passed=False, failure_reason="timeout"`.
- [ ] **Step 3: Tests pass** — ≥ 6 tests.
- [ ] **Step 4: Commit** — `feat(eval-framework): async run_suite over evalrunner`.

**Acceptance:** `await run_suite(load_cases(cloud_posture_cases_dir), CloudPostureEvalRunner())` returns a `SuiteResult` with 10 EvalResults — verified end-to-end after Task 7.

---

### Task 6: Trace capture from charter audit.jsonl

**Files:** `src/eval_framework/trace.py` (full impl), `tests/test_trace.py`.

```python
def build_trace_from_audit_log(audit_log_path: Path) -> EvalTrace:
    """Parse the charter audit log for a run and build an EvalTrace.

    Reads:
    - llm_call_started / llm_call_completed / llm_call_failed → LLMCallRecord
    - tool_call → ToolCallRecord
    - output_written → OutputWriteRecord
    - invocation_started / invocation_completed → start/end timestamps

    Verifies the hash chain via `charter.verifier.verify_audit_log` and
    sets EvalTrace.audit_chain_valid.
    """
```

- [ ] **Step 1: Write failing tests** — fixture audit.jsonl with N entries → trace has N-2 records, audit_chain_valid is True; tampered audit.jsonl → audit_chain_valid is False.
- [ ] **Step 2: Implement** — JSON-line parsing, pair `llm_call_started` ↔ `llm_call_completed` for token counts and duration, build records.
- [ ] **Step 3: Tests pass** — ≥ 5 tests including a malformed-line skip path.
- [ ] **Step 4: Commit** — `feat(eval-framework): trace capture from charter audit log`.

**Acceptance:** Run a real Cloud Posture eval case through `run_suite`; the resulting `EvalResult.trace` has `audit_chain_valid=True`, exactly 7 audit entries (per the Task 16 verification), and zero LLM calls (deterministic v0.1).

---

### Task 7: `CloudPostureEvalRunner` — migrate from `_eval_local`

**Files:** Create `packages/agents/cloud-posture/src/cloud_posture/eval_runner.py`. Existing `_eval_local.py` stays in place until Task 14 deletes it.

```python
class CloudPostureEvalRunner:
    @property
    def agent_name(self) -> str:
        return "cloud_posture"

    async def run(self, case, *, workspace, llm_provider=None):
        # Patch tools per fixture (same logic moved from _eval_local._run_case_async)
        # Build contract, call cloud_posture.agent.run, evaluate against expected
        # Return (passed, failure_reason, actuals, audit_log_path)
```

- [ ] **Step 1: Write failing tests** — runner satisfies Protocol; runs an empty fixture → 0 findings; runs the no-MFA fixture → 1 high finding.
- [ ] **Step 2: Implement** — cleanly extract the patch + contract-build + evaluate logic from `_eval_local`. **Do not delete `_eval_local` yet** — keep it working until Task 14 migrates the 10 cases.
- [ ] **Step 3: Tests pass** — ≥ 5 tests.
- [ ] **Step 4: Run all 10 shipped cases through the new runner** — `await run_suite(load_cases(cloud_posture_cases_dir), CloudPostureEvalRunner())` → 10/10 passed.
- [ ] **Step 5: Commit** — `feat(cloud-posture): cloudpostureevalrunner against the eval-framework`.

**Acceptance:** the new runner produces the same pass/fail outcome on all 10 shipped cases as the placeholder runner. Test-suite cardinality keeps pace (no regressions).

---

### Task 8: Comparison — `diff_results(baseline, candidate)`

**Files:** `src/eval_framework/compare.py`, `tests/test_compare.py`.

```python
class CaseDiff(BaseModel):
    case_id: str
    baseline_passed: bool
    candidate_passed: bool
    status: Literal["unchanged_pass", "unchanged_fail", "newly_failing", "newly_passing"]
    actuals_changed: bool
    token_delta: int | None              # candidate.total_tokens - baseline.total_tokens
    duration_delta_sec: float


class ComparisonReport(BaseModel):
    baseline_suite_id: str
    candidate_suite_id: str
    baseline_provider_id: str | None
    candidate_provider_id: str | None
    case_diffs: list[CaseDiff]
    summary: ComparisonSummary           # pass_rate_delta, regressions_count, …


def diff_results(baseline: SuiteResult, candidate: SuiteResult) -> ComparisonReport: ...
```

- [ ] **Step 1: Write failing tests** — same pass-rate, no regressions; baseline 10/10 → candidate 9/10 → `regressions_count=1`; provider drift surfaces token deltas.
- [ ] **Step 2: Implement** — case-id-keyed join; classify each case; aggregate.
- [ ] **Step 3: Tests pass** — ≥ 6 tests.
- [ ] **Step 4: Commit** — `feat(eval-framework): diff_results comparison report`.

**Acceptance:** `diff_results(suite_a, suite_b)` for two runs of the same Cloud Posture suite (deterministic) returns zero regressions and zero actuals-changed. Future: Meta-Harness uses this to block NLAH rewrites that regress.

---

### Task 9: Gates — `Gate` config + `apply_gate(suite_result)`

**Files:** `src/eval_framework/gate.py`, `tests/test_gate.py`.

```python
class Gate(BaseModel):
    min_pass_rate: float = 1.0           # 100% by default
    no_regressions_vs_baseline: bool = True
    max_token_delta_pct: float | None = None
    max_p95_duration_sec: float | None = None


class GateResult(BaseModel):
    passed: bool
    failures: list[str]                  # human-readable reasons


def apply_gate(suite: SuiteResult, gate: Gate, *, baseline: SuiteResult | None = None) -> GateResult: ...
```

- [ ] **Step 1: Write failing tests** — gate with `min_pass_rate=1.0` passes on 10/10; gate with `min_pass_rate=1.0` fails on 9/10 with explanation; gate with `no_regressions_vs_baseline=True` and a baseline catches single-case regression; gate with `max_p95_duration_sec=5` fails when one case takes 6s.
- [ ] **Step 2: Implement**.
- [ ] **Step 3: Tests pass** — ≥ 6 tests.
- [ ] **Step 4: Commit** — `feat(eval-framework): configurable gates with explainable failures`.

**Acceptance:** `apply_gate(...)` exits non-zero from the CLI (Task 13) when any gate fails. Gate failures must be human-readable so a CI log tells you which threshold blew.

---

### Task 10: Markdown report renderers

**Files:** `src/eval_framework/render_md.py`, `tests/test_render_md.py`.

```python
def render_suite_md(suite: SuiteResult) -> str: ...
def render_comparison_md(report: ComparisonReport) -> str: ...
def render_gate_md(gate_result: GateResult, suite: SuiteResult) -> str: ...
```

Suite report opens with the SuiteResult metadata (provider, model_pin, ci labels), then per-severity counts (if the runner emits them), then a per-case table (case_id, status, duration, token use). Comparison report puts the diff first ("3 newly failing, 2 actuals_changed"), then the per-case diff table.

- [ ] **Step 1: Write failing tests** — empty suite renders cleanly; suite with 10 passes → "10/10 passed"; comparison with regressions surfaces them in the first line; gate failures appear in render_gate_md output.
- [ ] **Step 2: Implement**.
- [ ] **Step 3: Tests pass** — ≥ 6 tests.
- [ ] **Step 4: Commit** — `feat(eval-framework): markdown renderers for suite, comparison, gate`.

**Acceptance:** the renderers produce auditor-readable reports that an SRE can scan in 30 seconds. No stack-traces for malformed input — render anything `pydantic` accepts.

---

### Task 11: JSON output (machine-readable, schema-stable)

**Files:** `src/eval_framework/render_json.py`, `tests/test_render_json.py`.

```python
def suite_to_json(suite: SuiteResult, *, indent: int | None = 2) -> str: ...
def comparison_to_json(report: ComparisonReport, *, indent: int | None = 2) -> str: ...
def suite_from_json(payload: str | bytes) -> SuiteResult: ...
def comparison_from_json(payload: str | bytes) -> ComparisonReport: ...
```

Use pydantic's `model_dump_json` / `model_validate_json` directly. The wire format becomes a stable contract for Meta-Harness consumption.

- [ ] **Step 1: Write failing tests** — round-trip preserves equality; output validates against `pydantic` re-load.
- [ ] **Step 2: Implement** — thin wrappers; ensure indent control + UTC datetimes.
- [ ] **Step 3: Tests pass** — ≥ 4 tests.
- [ ] **Step 4: Commit** — `feat(eval-framework): json serialization stable for meta-harness consumption`.

**Acceptance:** `suite_from_json(suite_to_json(s)) == s` for any `SuiteResult` produced by Task 5.

---

### Task 12: Provider-parity helper — `run_across_providers`

**Files:** Append to `src/eval_framework/suite.py`. `tests/test_provider_parity.py`.

```python
async def run_across_providers(
    cases: list[EvalCase],
    runner: EvalRunner,
    providers: dict[str, LLMProvider],
    *,
    workspace_root: Path | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, SuiteResult]:
    """Run the same suite against every provider in `providers`. Returns a
    map of provider_label → SuiteResult. Use `diff_results(...)` between
    pairs to surface drift."""
```

Sequential by default (parallelizing across providers is fine but not required for v0.1).

- [ ] **Step 1: Write failing tests using FakeRunner** — three providers (`fake-a`, `fake-b`, `fake-c`) each return identical results → `diff_results` reports zero drift; one provider returns drift → `diff_results` surfaces it.
- [ ] **Step 2: Implement**.
- [ ] **Step 3: Tests pass** — ≥ 3 tests.
- [ ] **Step 4: Commit** — `feat(eval-framework): run_across_providers for adr-003 parity gate`.

**Acceptance:** the helper is the substrate for ADR-003's eval-parity gate ("a workhorse swap must be proven on the per-agent eval suite before customer rollout").

---

### Task 13: CLI — `eval-framework run / compare / gate`

**Files:** `src/eval_framework/cli.py`, `tests/test_cli.py`.

```bash
# Run a suite with one runner (registered by name)
eval-framework run --runner cloud_posture --cases packages/agents/cloud-posture/eval/cases \
                   --output suite.json [--provider ollama] [--model qwen3:4b]

# Compare two saved suites
eval-framework compare baseline.json candidate.json --output report.md

# Apply a gate
eval-framework gate suite.json --config gate.yaml [--baseline baseline.json]
```

Runner registration: a small `eval_framework.runners` registry; agents register via setuptools entry-point group `nexus_eval_runners` so `eval-framework run --runner cloud_posture` resolves to `cloud_posture.eval_runner:CloudPostureEvalRunner` without import gymnastics.

- [ ] **Step 1: Write failing tests via Click's `CliRunner`** — `--help` lists subcommands; `run` against a registered fake runner produces a JSON output; `compare` between identical suites reports no drift; `gate` exits non-zero on a failing suite.
- [ ] **Step 2: Implement**.
- [ ] **Step 3: Tests pass** — ≥ 6 tests.
- [ ] **Step 4: Commit** — `feat(eval-framework): cli with run / compare / gate subcommands`.

**Acceptance:** `uv run eval-framework run --runner cloud_posture --cases packages/agents/cloud-posture/eval/cases --output /tmp/suite.json` prints `10/10 passed` and writes a valid SuiteResult JSON.

---

### Task 14: Migrate cloud-posture's 10 cases; delete `_eval_local`

**Files:** Add `cloud-posture` runner to the entry-point group; replace [`packages/agents/cloud-posture/tests/test_eval_local.py`](../../../packages/agents/cloud-posture/tests/test_eval_local.py) regression-guard test with one that uses `eval_framework.run_suite(...)`. **Delete** `cloud_posture._eval_local`.

- [ ] **Step 1: Wire entry point** — `[project.entry-points."nexus_eval_runners"]` in cloud-posture pyproject pins `cloud_posture = "cloud_posture.eval_runner:CloudPostureEvalRunner"`.
- [ ] **Step 2: Replace `test_eval_local.py`** with `test_eval_against_framework.py` — same regression-guard semantics but using the framework directly (`run_suite(load_cases(...), CloudPostureEvalRunner())`).
- [ ] **Step 3: Delete `_eval_local.py`** + the obsolete `test_eval_local.py`.
- [ ] **Step 4: Run the full repo** — every previous test path keeps working; the YAML cases didn't change so the regression guard still asserts 10/10.
- [ ] **Step 5: Commit** — `refactor(cloud-posture): migrate eval suite to nexus-eval-framework; delete _eval_local`.

**Acceptance:** `uv run cloud-posture eval packages/agents/cloud-posture/eval/cases` continues to print `10/10 passed` (the cloud-posture CLI remains a thin wrapper around the framework now). The repo's coverage dial keeps showing the same numbers; nothing regressed.

---

### Task 15: README + ADR-008

**Files:** `packages/eval-framework/README.md`, `docs/_meta/decisions/ADR-008-eval-framework.md`.

README mirrors the F.3 README pattern: what it does, quick start, three commands (`run` / `compare` / `gate`), case schema, the runner-registration pattern, license (Apache 2.0 like the charter), see-also links to the charter + ADR-007 + the cloud-posture migration.

ADR-008 codifies:

- Why a generic runner Protocol instead of agent-coupled framework.
- Why pydantic for typed wire formats (Meta-Harness consumption + JSON stability).
- Why SetUpTools entry-point registration for runners (no imports cycle, clean plugin pattern).
- Why CLI subcommands (`run`, `compare`, `gate`) match the three real-world workflows: pre-merge pass-check, NLAH-rewrite drift detection, CI gating.
- Why we ship as Apache 2.0 alongside the charter (per ADR-001 OSS split).
- Where this fits in the larger Meta-Harness loop (A.4): A.4 is the loop that _writes_ eval cases + reads SuiteResult to decide whether to deploy an NLAH change; F.2 is the substrate.

- [ ] **Step 1:** Write README.
- [ ] **Step 2:** Write ADR-008.
- [ ] **Step 3:** Update `docs/_meta/version-history.md`.
- [ ] **Step 4: Commit** — `docs(eval-framework): readme + adr-008 (eval framework architecture)`.

**Acceptance:** ADR-008 cross-references ADR-001 (OSS split), ADR-003 (provider-parity gate), ADR-007 (template patterns), and the F.2 plan itself.

---

### Task 16: Final verification

Same gate set as F.3's Task 16, adapted:

1. `uv run pytest packages/eval-framework/ --cov=eval_framework --cov-report=term-missing --cov-fail-under=80` — expect ≥ 80%.
2. `uv run ruff check packages/eval-framework/` + `uv run ruff format --check packages/eval-framework/` + `uv run mypy packages/eval-framework/src` — all clean.
3. `uv run eval-framework run --runner cloud_posture --cases packages/agents/cloud-posture/eval/cases --output /tmp/eval-smoke.json` — expect `10/10 passed`.
4. `uv run eval-framework compare /tmp/eval-smoke.json /tmp/eval-smoke.json` — expect zero drift (suite vs itself).
5. `uv run eval-framework gate /tmp/eval-smoke.json --config <(echo 'min_pass_rate: 1.0')` — expect exit 0.
6. **Suite-on-suite:** run the framework's own unit-test suite; assert framework tests aren't an eval suite themselves (no inception). The framework's tests use `FakeRunner`, not real LLMs.

Capture the verification record at `docs/_meta/f2-verification-<date>.md` mirroring the F.3 record's shape.

- [ ] **Step 1:** Run the six gates; capture output.
- [ ] **Step 2:** Write the verification record.
- [ ] **Step 3:** Re-issue `system-readiness.md` (rotate prior to dated archive; new snapshot reflects F.2 done).
- [ ] **Step 4: Commit** — `docs(f2): final verification record + readiness re-issue`.

---

## Self-Review

**Spec coverage** (every promise from the build-roadmap entry "case format, runner, gates, traces, comparison reports"):

- ✓ **case format** — Tasks 2 + 3 (typed `EvalCase` + YAML loader + per-runner fixture interpretation).
- ✓ **runner** — Task 4 (Protocol) + Task 5 (suite runner) + Task 7 (cloud-posture migration).
- ✓ **gates** — Task 9.
- ✓ **traces** — Task 6 (parsed from charter audit log into typed `EvalTrace`).
- ✓ **comparison reports** — Task 8 (`diff_results`) + Task 10 (markdown rendering) + Task 11 (JSON serialization).

**Plus** — provider-parity matrix (Task 12), CLI (Task 13), entry-point registration so adding a new agent's eval runner is a one-line pyproject change (Task 14 demonstrates).

**Type / name consistency:**

- `EvalRunner.run(...) -> tuple[bool, str | None, dict, Path | None]` (Task 4) → wrapped by `run_suite` (Task 5) into `EvalResult` (Task 2). The framework owns case_id / runner-name / duration / trace; the runner owns passed / reason / actuals / audit-path.
- Trace records (Task 2) are exactly what Task 6 emits and Task 10 renders.
- CLI subcommands (Task 13) consume the I/O formats from Tasks 11 (JSON) and 10 (markdown). No double-binding.

**Gaps / explicit deferrals (acceptable for v0.1):**

- **Concurrent suite execution** — the runner is sequential. Adding `max_concurrency > 1` is a single TaskGroup change; deferring keeps the trace-capture story simple.
- **Real-time eval streaming** — no progress events / web UI. Phase 2.
- **Auto-generated cases from production traces** — Meta-Harness territory (A.4); needs a redaction layer that doesn't exist yet.
- **Eval cases authored by an LLM** — eval-framework consumes cases; case authoring is a separate workflow (NLAH-driven) that A.4 may end up owning.

**Risks during execution:**

1. **Trace capture may surface the same `BudgetSpec` positive-required gotcha we hit in the F.3 smoke runbook.** Test fixtures should mirror what cloud-posture's `_eval_local._build_contract` sets (positive llm_calls/tokens even for deterministic runs). Worth a heads-up in Task 7's testing.
2. **Mypy strict + pydantic dataclasses** can interact weirdly with `Path | None`. The F.3 schemas refactor (Task 6.5) hit this; the workaround pattern (typed accessors over a raw dict, `model_config = ConfigDict(frozen=True)`) carried us through. Reuse here.
3. **Entry-point registration in Task 13** requires a `uv sync` after the cloud-posture pyproject change before the runner is discoverable. The F.3 CLI commits had the same gotcha — we discovered it took a fresh `uv sync` for the entry-point to register. Document in Task 14.
4. **A pristine `cloud-posture eval` keeps working post-migration** is a hard constraint (Task 14 acceptance). If it doesn't, back out and fix; do not ship.

**Recommended write order** (matches the dependency DAG above):

```
1 → 2 → 3 → 4 → 5 → 6 → 7 → 8 → 9 → 10 → 11 → 12 → 13 → 14 → 15 → 16
```

Tasks 8 / 9 / 10 / 11 can each ship independently after Task 5; the order above interleaves them with the cloud-posture migration so the regression-guard stays green throughout.

---

## Phase 1a context

F.2 ships into Phase 1a alongside F.4 (auth), F.5 (memory), F.6 (audit agent). The Phase 1a exit gate is "one end-to-end agent invocation against AWS dev account, eval suite passing, SOC 2 Type I scoping started." F.2 supplies the eval gate.

After F.2:

- **D.1 Vulnerability Agent** can be built to the [ADR-007](../../_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md) template AND graded against an eval suite from day one.
- **Meta-Harness Agent (A.4)** has its substrate; the loop itself is Phase 1c work.
- **Cross-provider eval-parity gate** ([ADR-003](../../_meta/decisions/ADR-003-llm-provider-strategy.md) consequence) becomes runnable: switching agent #N from `claude-sonnet-4-5` to `qwen3:4b-via-vllm` is a config change followed by `eval-framework run` against both, then `compare`, then `gate` — block the swap if drift exceeds tolerance.

The build-roadmap's Phase 1 success criterion "Eval suites ≥ 100 cases per agent" is a downstream of F.2 + each agent populating cases.

---

## References

- Build roadmap entry: [F.2](2026-05-08-build-roadmap.md) (3 wks, AI/Agent Eng, parallel-with F.1).
- Existing placeholder being extracted: [`packages/agents/cloud-posture/src/cloud_posture/_eval_local.py`](../../../packages/agents/cloud-posture/src/cloud_posture/_eval_local.py).
- Reference template (every pattern is the same): [F.3 plan](2026-05-08-f-3-cloud-posture-reference-nlah.md), [ADR-007](../../_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md).
- Provider-parity context: [ADR-003 — LLM provider strategy](../../_meta/decisions/ADR-003-llm-provider-strategy.md), [ADR-006 — OpenAI-compatible provider](../../_meta/decisions/ADR-006-openai-compatible-provider.md).
- Apache 2.0 + OSS split rationale: [ADR-001](../../_meta/decisions/ADR-001-monorepo-bootstrap.md).
- System readiness flagging F.2 as the highest-leverage next move: [system-readiness.md](../../_meta/system-readiness.md) recommendation #1.
