# F.2 — Eval Framework v0.1: Final Verification Record

|                  |                                                                                                                              |
| ---------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| **Date**         | 2026-05-10                                                                                                                   |
| **Plan**         | [`docs/superpowers/plans/2026-05-10-f-2-eval-framework-v0.1.md`](../superpowers/plans/2026-05-10-f-2-eval-framework-v0.1.md) |
| **Final commit** | `4256bc2` (head of `main` at start of verification)                                                                          |
| **Verifier**     | Task 16 of the F.2 plan                                                                                                      |
| **Outcome**      | ✅ **F.2 accepted as code-complete** — all six verification gates green                                                      |

## Gate-by-gate result

### ✅ Step 1 — Coverage ≥ 80% on `eval_framework`

```
$ uv run pytest packages/eval-framework/ \
      --cov=eval_framework --cov-report=term-missing --cov-fail-under=80
```

Result: **146 passed, 0 failed, 94.93% coverage** — gate was ≥ 80%.

Per-module coverage:

| Module           |   Stmts |   Miss |      Cover |
| ---------------- | ------: | -----: | ---------: |
| `__init__.py`    |       1 |      0 |       100% |
| `cases.py`       |      40 |      1 |        98% |
| `cli.py`         |      97 |     22 |        77% |
| `compare.py`     |      59 |      1 |        98% |
| `gate.py`        |      54 |      3 |        94% |
| `render_json.py` |      12 |      0 |       100% |
| `render_md.py`   |     116 |      1 |        99% |
| `results.py`     |      35 |      0 |       100% |
| `runner.py`      |      39 |      0 |       100% |
| `suite.py`       |      43 |      1 |        98% |
| `trace.py`       |      76 |      0 |       100% |
| **TOTAL**        | **572** | **29** | **94.93%** |

`cli.py` is the lowest-covered file at 77% — the missing lines are the live-provider branches (`OpenAICompatibleProvider.for_ollama()`, `AnthropicProvider(...)`) which require real provider SDKs in the test process. Tests use `patch("eval_framework.cli._resolve_runner")` to short-circuit the entry-point lookup, which is sufficient for the CLI's surface.

### ✅ Step 2 — Lint + format + mypy strict

```
$ uv run ruff check packages/eval-framework/          # All checks passed!
$ uv run ruff format --check packages/eval-framework/ # 23 files already formatted
$ uv run mypy packages/eval-framework/src             # Success: no issues found in 11 source files
```

All three clean.

### ✅ Step 3 — CLI smoke run against the cloud-posture suite

```
$ uv run eval-framework run \
      --runner cloud_posture \
      --cases packages/agents/cloud-posture/eval/cases \
      --output /tmp/eval-smoke.json
10/10 passed (100.0%)
wrote suite → /tmp/eval-smoke.json
```

The `cloud_posture` runner resolves through the `nexus_eval_runners` setuptools entry-point group registered in cloud-posture's `pyproject.toml` (Task 14). Output JSON is a valid `SuiteResult`.

### ✅ Step 4 — `compare` reports zero drift on suite vs itself

```
$ uv run eval-framework compare /tmp/eval-smoke.json /tmp/eval-smoke.json \
      --output /tmp/eval-compare.md
0 regression(s), 0 improvement(s) across 10 case(s)
wrote markdown → /tmp/eval-compare.md
```

Identity diff is the determinism check — same suite must compare zero-drift.

### ✅ Step 5 — `gate` exits 0 on passing suite

```
$ printf 'min_pass_rate: 1.0\nno_regressions_vs_baseline: true\n' > /tmp/eval-gate.yaml
$ uv run eval-framework gate /tmp/eval-smoke.json --config /tmp/eval-gate.yaml
# Gate passed ✅
- Suite: 01KR94YGJP274EHRN5B3TY4F8H
- Runner: cloud_posture
- Cases: 10/10
- Pass rate: 100.0%
All gate thresholds satisfied.
$ echo $?
0
```

Strict gate (`min_pass_rate=1.0, no_regressions_vs_baseline=true`) accepts a 10/10 suite with no baseline supplied. The regression check is silently skipped when no baseline is provided — the caller's contract.

### ✅ Step 6 — Suite-on-suite (no inception)

The framework's own pytest suite (146 tests across `test_cases / test_cli / test_compare / test_gate / test_provider_parity / test_render_json / test_render_md / test_results / test_runner / test_smoke / test_suite / test_trace`) uses `FakeRunner` for orchestration tests and `FakeLLMProvider` for parity tests. No real LLM calls in CI; no eval-suite-on-eval-suite recursion.

```
$ uv run pytest 2>&1 | tail -3
348 passed, 5 skipped in 3.96s
```

Full repo green.

## Numbers (verifiable from `git log` + `pytest`)

| Metric                                    | Value                       |
| ----------------------------------------- | --------------------------- |
| Plan tasks completed                      | **16 of 16**                |
| Eval-framework source files (mypy strict) | 11                          |
| Eval-framework test files                 | 12                          |
| Eval-framework tests passing              | **146 / 146**               |
| Eval-framework coverage                   | **94.93%**                  |
| Full repo tests passing                   | 348 + 5 skipped             |
| ADRs added in F.2                         | 1 (ADR-008)                 |
| Framework lines added                     | ~3,400 (src + tests + docs) |

## What landed (commit list)

| Task | Commit                       | Notes                                                                                  |
| ---- | ---------------------------- | -------------------------------------------------------------------------------------- |
| 1    | `f905af0`                    | Bootstrap apache-2.0 package skeleton                                                  |
| 2    | `e800fff`                    | Typed pydantic models — EvalCase / EvalResult / SuiteResult / EvalTrace                |
| 3    | `7ca4150`                    | YAML loader (`load_case_file` + `load_cases`)                                          |
| 4    | `2ccaab1`                    | EvalRunner Protocol + FakeRunner test double                                           |
| 5    | `8c87e46`                    | Async `run_suite()` with per-case workspace + per-case timeout                         |
| 6    | `1e13530`                    | `build_trace_from_audit_log` parser + verifier wrap                                    |
| 7    | `1b4d73c`                    | `CloudPostureEvalRunner` migrated from `_eval_local`; 10/10 cases pass via `run_suite` |
| 8    | `7b36e5f`                    | `diff_results` ComparisonReport — case-id-keyed join                                   |
| 9    | `a8700bf`                    | `Gate` + `apply_gate` — pass-rate, regressions, token-delta, p95 duration              |
| 10   | `6293dec`                    | Markdown renderers (suite + comparison + gate)                                         |
| 11   | `7aa44aa`                    | JSON serialization — schema-stable wire format                                         |
| 12   | `d756f09`                    | `run_across_providers` — multi-provider parity per ADR-003                             |
| 13   | `916b5aa`                    | CLI — `eval-framework run / compare / gate`                                            |
| 14   | `6268b64`                    | cloud-posture migrated to framework; entry-point registered; `_eval_local` deleted     |
| 15   | `faf0049`                    | README + ADR-008                                                                       |
| 16   | _(this verification record)_ | Final verification — 6/6 gates green                                                   |

## What this enables

- **Open-source release pair (per [ADR-001](decisions/ADR-001-monorepo-bootstrap.md)).** Apache 2.0 charter + eval-framework are now both code-complete. The pair is ready for tagging when [O.6](../superpowers/plans/2026-05-08-build-roadmap.md) ships.
- **Reference NLAH parity gate (per [ADR-003](decisions/ADR-003-llm-provider-strategy.md)).** `run_across_providers` + `diff_results` is the substrate of the workhorse-swap eval-parity gate. The Anthropic ↔ Ollama ↔ vLLM ↔ OpenAI swap is a config change with a measurable gate, not a rebuild.
- **D-track agent template (per [ADR-007](decisions/ADR-007-cloud-posture-as-reference-agent.md)).** Every Track-D agent (Vulnerability, Identity, Runtime Threat, ...) registers its eval runner via the `nexus_eval_runners` entry-point group. The pattern is one-line `pyproject.toml`.
- **Meta-Harness (A.4) landing pad (per [ADR-008](decisions/ADR-008-eval-framework.md) D6).** `SuiteResult` JSON is the stable wire format A.4 will read. Comparison-over-time tooling can join across runs by `case_id` without parsing free-form text.

## Verification rerun command

```bash
# Six gates in one run
cd /path/to/nexus-cyber-os
uv run pytest packages/eval-framework/ --cov=eval_framework --cov-fail-under=80 \
  && uv run ruff check packages/eval-framework/ \
  && uv run ruff format --check packages/eval-framework/ \
  && uv run mypy packages/eval-framework/src \
  && uv run eval-framework run --runner cloud_posture \
       --cases packages/agents/cloud-posture/eval/cases \
       --output /tmp/eval-smoke.json \
  && uv run eval-framework compare /tmp/eval-smoke.json /tmp/eval-smoke.json \
       --output /tmp/eval-compare.md \
  && printf 'min_pass_rate: 1.0\nno_regressions_vs_baseline: true\n' > /tmp/eval-gate.yaml \
  && uv run eval-framework gate /tmp/eval-smoke.json --config /tmp/eval-gate.yaml \
  && uv run pytest
```

If every command exits 0, F.2 still verifies.

## References

- [F.2 plan with execution status](../superpowers/plans/2026-05-10-f-2-eval-framework-v0.1.md) — code-complete
- [F.3 verification record](f3-verification-2026-05-10.md) — sister doc; same gate-set shape
- [ADR-001](decisions/ADR-001-monorepo-bootstrap.md) · [ADR-003](decisions/ADR-003-llm-provider-strategy.md) · [ADR-007](decisions/ADR-007-cloud-posture-as-reference-agent.md) · [ADR-008](decisions/ADR-008-eval-framework.md)
