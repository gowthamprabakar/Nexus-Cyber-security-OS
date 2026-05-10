# `nexus-eval-framework`

The eval substrate for every Nexus agent — **Apache 2.0**, vendor-SDK-optional, ships alongside the [runtime charter](../charter/) per [ADR-001](../../docs/_meta/decisions/ADR-001-monorepo-bootstrap.md).

## What it does

Runs eval suites for any agent that implements a small `EvalRunner` Protocol, captures a typed trace of what happened (LLM calls, tool calls, output writes, audit-chain validity), compares runs against baselines, gates CI on configurable thresholds, and emits both human-readable markdown reports and schema-stable JSON for downstream tools (Meta-Harness, comparison-over-time dashboards). Cloud Posture (the [reference NLAH per ADR-007](../../docs/_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md)) is the first agent on it; the other 17 inherit the pattern.

## Quick start

```bash
# 1. Run a suite for a registered agent runner
uv run eval-framework run \
    --runner cloud_posture \
    --cases packages/agents/cloud-posture/eval/cases \
    --output /tmp/cp_suite.json
# → "10/10 passed (100.0%)" + a SuiteResult JSON on disk.

# 2. Compare two saved suites
uv run eval-framework compare /tmp/baseline.json /tmp/candidate.json \
    --output /tmp/report.md \
    --json-output /tmp/report.json

# 3. Gate the candidate against a YAML config (exits non-zero on failure)
uv run eval-framework gate /tmp/cp_suite.json \
    --config /tmp/gate.yaml \
    --baseline /tmp/baseline.json
```

A minimal `gate.yaml`:

```yaml
min_pass_rate: 1.0
no_regressions_vs_baseline: true
max_token_delta_pct: 0.20 # optional: candidate may not grow tokens > 20%
max_p95_duration_sec: 60.0 # optional: 95th-percentile case duration ceiling
```

## Case schema

YAML files in a directory; framework owns the schema, individual agents own the keys inside `fixture` and `expected`.

```yaml
case_id: 001_public_s3_bucket
description: Public S3 bucket should produce one high-severity finding
tags: [cspm, s3] # optional
timeout_sec: 60.0 # optional, default 60
fixture:
  prowler_findings: # cloud-posture key — agents define their own
    - CheckID: s3_bucket_public_access
      Severity: high
      Status: FAIL
      ResourceArn: arn:aws:s3:::acme-public
expected:
  finding_count: 1
  has_severity:
    high: 1
```

## Writing a runner

Any class with the right shape satisfies the `EvalRunner` Protocol — no inheritance required:

```python
from pathlib import Path
from charter.llm import LLMProvider
from eval_framework.cases import EvalCase
from eval_framework.runner import RunOutcome


class MyAgentEvalRunner:
    @property
    def agent_name(self) -> str:
        return "my_agent"

    async def run(
        self,
        case: EvalCase,
        *,
        workspace: Path,
        llm_provider: LLMProvider | None = None,
    ) -> RunOutcome:
        # ... patch tools per fixture, build a contract, call your agent ...
        return passed, failure_reason, actuals, audit_log_path
```

Register it in your agent's `pyproject.toml` so the CLI can resolve it by name:

```toml
[project.entry-points."nexus_eval_runners"]
my_agent = "my_agent.eval_runner:MyAgentEvalRunner"
```

The framework treats `actuals` as opaque per agent, but two well-known keys feed the renderers and gates:

- `finding_count: int` — surfaces in suite report headlines.
- `by_severity: {critical: N, high: N, ...}` — populates the per-severity rollup section in `render_suite_md`.

## Three real-world workflows

| Workflow                            | Command                                                                | What it answers                                               |
| ----------------------------------- | ---------------------------------------------------------------------- | ------------------------------------------------------------- |
| **Pre-merge pass-check**            | `eval-framework run --runner X --cases dir --output suite.json`        | "Did my change keep all cases passing?"                       |
| **NLAH-rewrite drift detection**    | `eval-framework compare baseline.json candidate.json --output diff.md` | "Did this NLAH rewrite introduce regressions or token drift?" |
| **CI gate**                         | `eval-framework gate suite.json --config gate.yaml`                    | "Should this build merge / deploy?"                           |
| **Cross-provider parity (ADR-003)** | `run_across_providers(...)` (Python API) → pair runs with `compare`    | "Does the workhorse-tier swap from Anthropic to local pass?"  |

## Public surface

```python
from eval_framework.cases import EvalCase, load_case_file, load_cases
from eval_framework.results import EvalResult, SuiteResult
from eval_framework.trace import (
    EvalTrace,
    LLMCallRecord,
    ToolCallRecord,
    OutputWriteRecord,
    build_trace_from_audit_log,
)
from eval_framework.runner import EvalRunner, FakeRunner, RunOutcome
from eval_framework.suite import run_suite, run_across_providers
from eval_framework.compare import (
    CaseDiff,
    ComparisonReport,
    ComparisonSummary,
    diff_results,
)
from eval_framework.gate import Gate, GateResult, apply_gate
from eval_framework.render_md import (
    render_suite_md,
    render_comparison_md,
    render_gate_md,
)
from eval_framework.render_json import (
    suite_to_json,
    suite_from_json,
    comparison_to_json,
    comparison_from_json,
)
```

All result / trace / comparison / gate models are pydantic + frozen, so JSON round-trip and structural equality are guaranteed.

## Trace capture

When an `EvalRunner` returns an `audit_log_path`, the framework parses it via `build_trace_from_audit_log` and populates the `EvalTrace`:

- `tool_call` audit entries → `ToolCallRecord`
- `output_written` → `OutputWriteRecord`
- Paired `llm_call_started` / `llm_call_completed` → `LLMCallRecord` with token counts and a duration computed from the timestamp delta. Unpaired starts (crash mid-call or `llm_call_failed`) are dropped — they have no token accounting.
- The hash chain is verified via `charter.verifier.verify_audit_log`. Tampered or malformed logs degrade gracefully to `audit_chain_valid=False` rather than raising.

## Cross-provider parity (ADR-003)

The substrate of the eval-parity gate ("a workhorse swap must be proven on the per-agent eval suite before customer rollout"):

```python
from charter.llm_anthropic import AnthropicProvider
from charter.llm_openai_compat import OpenAICompatibleProvider
from eval_framework.compare import diff_results
from eval_framework.suite import run_across_providers

results = await run_across_providers(
    cases=load_cases("packages/agents/cloud-posture/eval/cases"),
    runner=CloudPostureEvalRunner(),
    providers={
        "anthropic": AnthropicProvider(model_class=ModelTier.WORKHORSE),
        "ollama":    OpenAICompatibleProvider.for_ollama(),
    },
)

# Surface drift between providers.
report = diff_results(results["anthropic"], results["ollama"])
print(f"{report.summary.regressions_count} regression(s)")
```

## License

Apache 2.0 — same as `nexus-charter`. Per [ADR-001](../../docs/_meta/decisions/ADR-001-monorepo-bootstrap.md), the runtime substrate is open-source so the broader agentic-systems community can build on it; agent-specific code (Cloud Posture, Vulnerability, ...) ships under BSL 1.1 to preserve commercial position on the detection layer.

## See also

- [`nexus-charter`](../charter/) — execution contracts, budget envelope, tool registry, hash-chained audit (the substrate this framework builds on).
- [Cloud Posture Agent](../agents/cloud-posture/) — the reference NLAH ([ADR-007](../../docs/_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md)).
- [F.2 plan](../../docs/superpowers/plans/2026-05-10-f-2-eval-framework-v0.1.md) — the implementation plan (16 tasks, all green at v0.1).
- [ADR-008](../../docs/_meta/decisions/ADR-008-eval-framework.md) — eval-framework architecture decisions.
