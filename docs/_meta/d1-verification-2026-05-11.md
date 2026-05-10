# D.1 — Vulnerability Agent: Final Verification Record

|                  |                                                                                                                              |
| ---------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| **Date**         | 2026-05-11                                                                                                                   |
| **Plan**         | [`docs/superpowers/plans/2026-05-10-d-1-vulnerability-agent.md`](../superpowers/plans/2026-05-10-d-1-vulnerability-agent.md) |
| **Final commit** | `dd72f0c` (head of `main` at start of verification)                                                                          |
| **Verifier**     | Task 16 of the D.1 plan                                                                                                      |
| **Outcome**      | ✅ **D.1 accepted as code-complete** — all 6 verification gates green; **ADR-007 validated with 1 amendment**                |

## Strategic outcome

D.1 is the **risk-down moment for [ADR-007](decisions/ADR-007-cloud-posture-as-reference-agent.md)** — the first agent built to the Cloud Posture reference template. The verdict:

- **10 of 10 ADR-007 patterns generalize** to a domain (vulnerability scanning) that shares no tooling with Cloud Posture (no Prowler, no boto3, no AWS at all).
- **One amendment recommended:** hoist `vulnerability/llm.py` and `cloud_posture/llm.py` into `charter.llm_adapter`. Diff between the two is exactly 1 line — pure duplication.
- **One new convention introduced:** the HTTP-wrapper convention (Task 4: OSV) extending ADR-005's async-by-default discipline to httpx-driven tools. Validated in Tasks 5 (KEV) and 6 (NVD/EPSS) by inheritance.

This is the strongest evidence ADR-007 will get in Phase 1a. Eleven more Track-D agents adopt the canon next; the amendment lands first via a small charter PR.

## Gate-by-gate result

### ✅ Gate 1 — Coverage ≥ 80% on `vulnerability`

```
$ uv run pytest packages/agents/vulnerability/ \
      --cov=vulnerability --cov-report=term-missing --cov-fail-under=80
```

Result: **130 passed, 0 failed, 96.84% coverage** — gate was ≥ 80%.

Per-module coverage:

| Module              |   Stmts |   Miss |      Cover |
| ------------------- | ------: | -----: | ---------: |
| `__init__.py`       |       2 |      0 |       100% |
| `agent.py`          |      48 |      0 |       100% |
| `cli.py`            |      48 |      1 |        98% |
| `eval_runner.py`    |      68 |      0 |       100% |
| `llm.py`            |      56 |      0 |       100% |
| `nlah_loader.py`    |      25 |      0 |       100% |
| `normalizer.py`     |      62 |      5 |        92% |
| `schemas.py`        |     138 |      3 |        98% |
| `summarizer.py`     |      40 |      0 |       100% |
| `tools/__init__.py` |       0 |      0 |       100% |
| `tools/kev.py`      |      40 |      3 |        92% |
| `tools/nvd.py`      |      86 |      9 |        90% |
| `tools/osv.py`      |      40 |      1 |        98% |
| `tools/trivy.py`    |      44 |      0 |       100% |
| **TOTAL**           | **697** | **22** | **96.84%** |

The lowest-covered files are `tools/nvd.py` (90%) and `tools/kev.py` (92%) — the missing lines are HTTP-error edge cases that the public-API rate limits make hard to reproduce in CI without flaky network tests. Both files are covered well above the gate.

### ✅ Gate 2 — Lint + format + mypy strict

```
$ uv run ruff check packages/agents/vulnerability/          # All checks passed!
$ uv run ruff format --check packages/agents/vulnerability/ # 27 files already formatted
$ uv run mypy packages/agents/vulnerability/src             # Success: no issues found in 14 source files
```

All three clean.

### ✅ Gate 3 — `vuln-agent eval` CLI smoke

```
$ uv run vuln-agent eval packages/agents/vulnerability/eval/cases
10/10 passed
```

The agent's own CLI runs the local suite and reports 10/10.

### ✅ Gate 4 — eval-framework via entry-point group

```
$ uv run eval-framework run \
      --runner vulnerability \
      --cases packages/agents/vulnerability/eval/cases \
      --output /tmp/vuln_suite_d1.json
10/10 passed (100.0%)
wrote suite → /tmp/vuln_suite_d1.json

$ python -c "import json; ..." /tmp/vuln_suite_d1.json
runner= vulnerability pass_rate= 10 / 10
```

The `nexus_eval_runners` entry-point group resolves `--runner vulnerability` to `vulnerability.eval_runner:VulnerabilityEvalRunner` at CLI invocation time (no in-process patching). This is the F.2 promise — one line in pyproject + one EvalRunner class is the entire integration surface. **Promise validated.**

### ✅ Gate 5 — strict gate exits 0 on passing suite

```
$ printf 'min_pass_rate: 1.0\nno_regressions_vs_baseline: true\n' > /tmp/d1-gate.yaml
$ uv run eval-framework gate /tmp/vuln_suite_d1.json --config /tmp/d1-gate.yaml
# Gate passed ✅
- Suite: 01KR9M7YABFFD7GWY5KZ0F9WN3
- Runner: vulnerability
- Cases: 10/10
- Pass rate: 100.0%
All gate thresholds satisfied.
$ echo $?
0
```

### ✅ Gate 6 — full repo

```
$ uv run pytest 2>&1 | tail -3
478 passed, 5 skipped in 5.23s
```

Full repo green. No regressions in any other package from the D.1 changes.

## ADR-007 conformance review (the strategic deliverable)

| #   | Pattern                                          | Where validated | Verdict                                           |
| --- | ------------------------------------------------ | --------------- | ------------------------------------------------- |
| 1   | Schema-as-typing-layer (OCSF wire format)        | Task 2          | ✅ generalizes verbatim                           |
| 2   | Async-by-default subprocess wrapper              | Task 3          | ✅ generalizes verbatim                           |
| 3   | HTTP-wrapper convention (NEW + 2× inherited)     | Tasks 4, 5, 6   | ✅ established + 2× inherited cleanly             |
| 4   | Concurrent TaskGroup enrichment                  | Task 7          | ✅ generalizes verbatim                           |
| 5   | Markdown summarizer (top-down severity layout)   | Task 8          | ✅ generalizes verbatim                           |
| 6   | NLAH layout (3-file structure)                   | Task 9          | ✅ generalizes verbatim                           |
| 7   | LLM adapter consuming charter.llm                | Task 10         | 🟡 **flagged for hoist** to `charter.llm_adapter` |
| 8   | Charter context manager + agent.run signature    | Task 11         | ✅ generalizes verbatim                           |
| 9   | Eval-runner via `nexus_eval_runners` entry-point | Task 13         | ✅ generalizes verbatim                           |
| 10  | CLI subcommand pattern (`eval` + `run`)          | Task 14         | ✅ generalizes verbatim                           |

**Single recommended amendment:** the LLM adapter (Task 10) is verbatim copy-with-rename of cloud-posture's. Diff is exactly 1 line (the docstring header). Recommendation: hoist `vulnerability/llm.py` + `cloud_posture/llm.py` into `charter.llm_adapter` so all 18 agents `from charter.llm_adapter import config_from_env, make_provider` instead of duplicating. **Action item:** open a small charter PR before D.2 (Identity Agent) starts to avoid a third copy.

## Numbers (verifiable from `git log` + `pytest`)

| Metric                                   | Value                                          |
| ---------------------------------------- | ---------------------------------------------- |
| Plan tasks completed                     | **16 of 16**                                   |
| Vulnerability source files (mypy strict) | 14                                             |
| Vulnerability test files                 | 11                                             |
| Vulnerability tests passing              | **130 / 130**                                  |
| Vulnerability coverage                   | **96.84%**                                     |
| Full repo tests passing                  | 478 + 5 skipped                                |
| ADRs added in D.1                        | 0 (1 amendment recommended)                    |
| ADR-007 patterns validated               | **10 of 10**                                   |
| Source LOC added                         | ~2,300 (src + tests + nlah + runbook + README) |

## What landed (commit list)

| Task | Commit                       | Notes                                                                                          |
| ---- | ---------------------------- | ---------------------------------------------------------------------------------------------- |
| 1    | `4f6fa05`                    | Bootstrap package skeleton                                                                     |
| 2    | `8c57c6b`                    | OCSF v1.3 Vulnerability Finding schema (`class_uid 2002`)                                      |
| 3    | `42129d3`                    | `trivy_image_scan` async subprocess wrapper                                                    |
| 4    | `b994eb5`                    | `osv_query` httpx async client — establishes HTTP-wrapper convention                           |
| 5    | `5aa3f8b`                    | `kev_catalog` + `is_kev` (CISA KEV)                                                            |
| 6    | `8ca9282`                    | `nvd_enrich` — bundled NVD CVSS + EPSS                                                         |
| 7    | `0bab391`                    | Trivy → OCSF normalizer with concurrent TaskGroup enrichment                                   |
| 8    | `13ed7f2`                    | Findings → markdown summarizer with KEV section pinned at top                                  |
| 9    | `5971632`                    | NLAH (README + tools.md + 2 OCSF examples) + loader                                            |
| 10   | `d171b72`                    | LLM adapter — verbatim copy of cloud-posture's; **flagged for hoist**                          |
| 11   | `d341fd6`                    | Agent driver — async run() wires charter + concurrent Trivy + normalizer + summarizer          |
| 12   | `31d08f5`                    | 10 representative eval cases (KEV + severity + fix variants + clean image)                     |
| 13   | `31d08f5`                    | `VulnerabilityEvalRunner` + entry-point; 10/10 via `eval-framework run --runner vulnerability` |
| 14   | `c1c331a`                    | CLI — `vuln-agent eval` + `vuln-agent run --contract --image`                                  |
| 15   | `3528b77`                    | Package README (with ADR-007 conformance addendum) + scan-image runbook                        |
| 16   | _(this verification record)_ | Final verification — 6/6 gates green                                                           |

## What this enables

- **D.2 through D.13 can adopt the canon with confidence.** ADR-007 is no longer "the cloud-posture template"; it's "a generalized template tested across two domains." The remaining 11 Track-D agents inherit a verified pattern set.
- **The first ADR-007 amendment is queued.** Hoisting `llm.py` into `charter.llm_adapter` is a small, well-scoped charter PR that retires the only piece of duplication D.1 surfaced.
- **CSPM + Vulnerability is the first capability pair.** Weighted Wiz coverage moves from ~6.7% → ~10–12% (rough estimate; verified in the next system-readiness re-issue). The trajectory math from the platform completion report holds.

## Verification rerun command

```bash
# Six gates in one run
cd /path/to/nexus-cyber-os
uv run pytest packages/agents/vulnerability/ \
      --cov=vulnerability --cov-fail-under=80 \
  && uv run ruff check packages/agents/vulnerability/ \
  && uv run ruff format --check packages/agents/vulnerability/ \
  && uv run mypy packages/agents/vulnerability/src \
  && uv run vuln-agent eval packages/agents/vulnerability/eval/cases \
  && uv run eval-framework run --runner vulnerability \
       --cases packages/agents/vulnerability/eval/cases \
       --output /tmp/vuln_suite_d1.json \
  && printf 'min_pass_rate: 1.0\nno_regressions_vs_baseline: true\n' > /tmp/d1-gate.yaml \
  && uv run eval-framework gate /tmp/vuln_suite_d1.json --config /tmp/d1-gate.yaml \
  && uv run pytest
```

If every command exits 0, D.1 still verifies.

## References

- [D.1 plan with execution status](../superpowers/plans/2026-05-10-d-1-vulnerability-agent.md) — 16/16 tasks complete
- [F.2 verification record](f2-verification-2026-05-10.md) — sister doc for the eval framework
- [F.3 verification record](f3-verification-2026-05-10.md) — sister doc for the reference NLAH
- [ADR-001](decisions/ADR-001-monorepo-bootstrap.md) · [ADR-002](decisions/ADR-002-charter-as-context-manager.md) · [ADR-003](decisions/ADR-003-llm-provider-strategy.md) · [ADR-004](decisions/ADR-004-fabric-layer.md) · [ADR-005](decisions/ADR-005-async-tool-wrapper-convention.md) · [ADR-006](decisions/ADR-006-openai-compatible-provider.md) · [ADR-007](decisions/ADR-007-cloud-posture-as-reference-agent.md) · [ADR-008](decisions/ADR-008-eval-framework.md)
