# ADR-008 — Eval Framework Architecture (`nexus-eval-framework` v0.1)

- **Status:** accepted
- **Date:** 2026-05-10
- **Authors:** F.2
- **Stakeholders:** AI/Agent Eng, Detection Eng, Compliance Eng, future Meta-Harness Agent (A.4) author

## Context

[F.2](../../superpowers/plans/2026-05-10-f-2-eval-framework-v0.1.md) ships the standalone `nexus-eval-framework` package — the substrate every Nexus agent's eval suite runs on. This ADR captures the architectural decisions that shape it:

- **Why a separate package** instead of folding eval into each agent. We will operate ~18 agents; without a shared eval substrate, every agent reinvents case schemas, runner orchestration, and CI gating, and the Meta-Harness Agent ([A.4]) has no stable surface to read traces from.
- **What contract** binds the framework and the agents that use it. Wrong choice here means either tight coupling (agents must inherit a base class) or no contract at all (every agent's runner is a snowflake).
- **What wire format** the framework emits. Wrong choice here means Meta-Harness has to interpret raw audit-log JSON instead of a typed shape, or downstream tools (CI dashboards, comparison-over-time) parse free-form text.
- **What CI surfaces** the framework exposes. Wrong choice here means the same machinery has to be reinvented per agent, per CI pipeline.
- **Where this fits** alongside the future Meta-Harness Agent. Wrong scoping means F.2 either does too little (Meta-Harness still has nowhere to land) or too much (the framework starts making policy decisions that belong to A.4).

The cloud-posture placeholder runner ([`_eval_local`](../../../packages/agents/cloud-posture/src/cloud_posture/_eval_local.py), F.3) was always declared a stand-in. F.2 is the real version.

## Decision

The framework is structured around six load-bearing decisions:

### D1 — Generic `EvalRunner` Protocol, not an inheritance hierarchy

Every agent's eval runner satisfies a tiny [`@runtime_checkable` `Protocol`](../../../packages/eval-framework/src/eval_framework/runner.py):

```python
class EvalRunner(Protocol):
    @property
    def agent_name(self) -> str: ...

    async def run(
        self, case: EvalCase, *, workspace: Path,
        llm_provider: LLMProvider | None = None,
    ) -> RunOutcome: ...
```

The framework owns case schema, orchestration, trace capture, comparison, and gating. Agents own everything inside `fixture` and `expected`. There is no base class to inherit, no init-time registration call, no decorator. The contract is the Protocol's two members.

### D2 — Pydantic for typed wire formats

Every result / trace / comparison / gate model is a pydantic `BaseModel` with `frozen=True`. Reasons:

- JSON I/O is free (`model_dump_json` / `model_validate_json` round-trip).
- Equality and hashing are structural; Meta-Harness can cache by `SuiteResult` value.
- Field validation is at the boundary, not scattered through code.
- The wire format becomes a stable contract — top-level keys are the model field set, full stop.

### D3 — Setuptools entry-point group `nexus_eval_runners` for runner registration

Agents register their runner in their own `pyproject.toml`:

```toml
[project.entry-points."nexus_eval_runners"]
cloud_posture = "cloud_posture.eval_runner:CloudPostureEvalRunner"
```

The CLI looks up `--runner cloud_posture` against `importlib.metadata.entry_points(group="nexus_eval_runners")`. Reasons:

- No import cycle: framework never imports agents; agents never import the framework's CLI.
- No global registry mutation at import time.
- Discoverable: `entry_points(group=...)` lists every registered runner on the Python path.
- Plugin-friendly: third-party runners (e.g., for future customer-built agents) install the same way.

### D4 — Three CLI subcommands match three real workflows

`eval-framework run`, `eval-framework compare`, `eval-framework gate`. Each maps directly to a workflow that already exists in our build:

| Workflow                        | Subcommand                                       | Today's caller                                |
| ------------------------------- | ------------------------------------------------ | --------------------------------------------- |
| Pre-merge pass-check            | `run`                                            | Local `make eval`, GitHub Actions PR check    |
| NLAH-rewrite drift detection    | `compare`                                        | The Meta-Harness propose → eval → deploy loop |
| CI / merge gate                 | `gate`                                           | GitHub Actions branch protection              |
| Cross-provider parity (ADR-003) | `run_across_providers` API → pair with `compare` | The eval-parity gate before a workhorse swap  |

`run` does not exit non-zero on failures — that is `gate`'s job. This separation lets a CI script decide policy (do we fail on regression? on token-delta? on p95 duration?) declaratively in YAML rather than through argparse flag soup.

### D5 — Apache 2.0, sister of `nexus-charter`

Per [ADR-001](ADR-001-monorepo-bootstrap.md), the runtime substrate is open-source. `nexus-eval-framework` ships under Apache 2.0 the same as `nexus-charter`. Reasons:

- The eval substrate isn't where competitive position lives; the agent-specific detection logic (cloud-posture, vulnerability, identity, ...) is, and that ships under BSL 1.1.
- Open-sourcing the eval substrate makes building on top of it (third-party runners, comparison dashboards, Meta-Harness research) frictionless.
- The OSS releases compound recruiting and trust. We expect customers and candidates to read this code; pushing it to a public GitHub repo with tagged versions is the move per [ADR-001](ADR-001-monorepo-bootstrap.md).

### D6 — Substrate, not policy — where this fits with Meta-Harness (A.4)

`nexus-eval-framework` provides:

- **The eval substrate**: case schema, runner Protocol, suite orchestration, trace capture, comparison, gates, renderers, JSON.
- **The reference EvalRunner pattern**: `CloudPostureEvalRunner` (and the documentation that says "your runner looks like this").

The future Meta-Harness Agent (A.4) provides:

- **The loop**: `propose NLAH change → run eval → diff vs baseline → deploy if no regression → otherwise discard`.
- **The case-generation policy**: pulling representative production traces and compiling them into `EvalCase` YAML.
- **The deploy gate**: deciding what counts as "no regression" for a given agent.

This split keeps F.2 focused on shapes + orchestration; A.4 focuses on policy. Future ADRs will pin A.4's policy decisions; this ADR pins only what the substrate provides.

## Consequences

### Positive

- **One contract, eighteen agents.** Every Track-D agent (Vulnerability, Identity, Runtime Threat, ...) plugs into the framework via the same Protocol. The reference template ([ADR-007](ADR-007-cloud-posture-as-reference-agent.md)) names the eval runner pattern explicitly; new agents inherit it without extra work.
- **Stable wire format.** `SuiteResult` JSON is the contract Meta-Harness can rely on; round-trip equality is guaranteed by pydantic frozen models. Comparison-over-time tooling can join across runs by `case_id` without wrangling free-form text.
- **CI surface ships in v0.1.** Every team gets `run / compare / gate` on day zero; no team writes its own regression-tracking shell script.
- **Apache 2.0 release-ready.** Per ADR-001, the framework is one of the two OSS packages that ship together. F.2 is now ready to release alongside the charter when O.6 lands.
- **Cross-provider parity is buildable today.** `run_across_providers` plus `diff_results` is the substrate of the ADR-003 eval-parity gate. No more "we'll figure it out when we swap providers" — the swap is a config change with a measurable gate.

### Negative

- **Pydantic dependency on the wire-format edge.** Anyone consuming SuiteResult JSON outside Python has to model the schema themselves. Mitigation: the schema is published in the README + ADR; `model_json_schema()` is one call away from emitting JSON Schema if a downstream language wants to validate.
- **Setuptools entry-point registration requires a real install.** Editable installs (`uv sync`) do this transparently; an in-tree script that bypasses the install path won't see registered runners. Mitigation: documented in the README; tests use `patch("eval_framework.cli._resolve_runner")` to short-circuit.
- **Trace capture is one-shot per case.** A case that crashes mid-run produces a partial audit log; the framework parses what it can and marks `audit_chain_valid=False`. We do not surface partial traces with a recovery hint. Mitigation: cases that crash are already gate-failures; the renderer prints the failure_reason verbatim, which is the diagnostic surface.
- **Tool-call duration is a `0.0` placeholder until charter emits per-call duration.** Ditto for output-write timing. Mitigation: tracked as a future enhancement; no current consumer (gate, comparison, renderer) needs it.

### Neutral / unknown

- **The exact set of `actuals` keys** is per-agent. Today cloud-posture emits `{finding_count, by_severity}`. We chose not to lock the keys — different agents will surface different shapes (Vulnerability: `{cve_count, kev_count, exploitable_count}`; Identity: `{policy_count, mfa_gap_count}`). The renderers display whatever is there; gates and comparisons treat actuals as opaque dicts. We may add a "well-known actuals" registry if cross-agent consumers (Synthesis, Curiosity) need it.
- **Sequential suite execution.** `run_suite` runs cases serially today. `max_concurrency > 1` is reserved for a future task. We chose serial to keep semantics simple in v0.1; cross-case isolation already works via per-case workspaces, so the upgrade is mechanical when needed.

## Alternatives considered

### Alt 1: agent-coupled framework (each agent owns its eval pipeline)

- Why rejected: We will run ~18 agents. Each one inventing its own case schema, runner, comparison, and CI gating wastes engineering time on plumbing that should be solved once. Worse, Meta-Harness (A.4) becomes 18 different integrations instead of one.

### Alt 2: ABC base class instead of Protocol

- Why rejected: Tight coupling. Agents would have to import `from eval_framework import BaseEvalRunner` at import time, creating a dependency cycle when the framework's CLI then tries to load the runner via entry points. The Protocol shape is enforced by `@runtime_checkable` `isinstance` and by mypy strict — both verified in tests.

### Alt 3: dataclasses or attrs instead of pydantic

- Why rejected: We get JSON serialization, validation, frozen-ness, and field defaults from one library. Reaching for `dataclasses.asdict` + `json.dump` + manual validation re-implements ~80% of pydantic for no architectural gain. The wire-format-as-contract argument (D2) requires pydantic-grade structural validation at the parse boundary.

### Alt 4: eval cases in JSON instead of YAML

- Why rejected: cloud-posture's [10 shipped cases](../../../packages/agents/cloud-posture/eval/cases/) are already YAML; humans read and write the cases (compliance engineers, threat-intel analysts) and YAML's lightness wins for that audience. JSON would require quote-escaping, lose comments, and gain nothing on the parse side because pydantic validates the shape after parsing regardless.

### Alt 5: heavy CI runner (Argo, Tekton, Temporal) instead of a Click CLI + entry-points

- Why rejected: We are at scale 1 (one agent, one engineer running suites). A heavyweight runner solves a problem we don't have. The Click CLI exits non-zero on `gate` failure; that's the entire CI integration. When we need parallelism or distributed execution, the substrate already supports it (`run_suite` is async, `run_across_providers` is sequential-but-trivially-parallelizable), and the migration is a lift inside one function.

## References

- [F.2 plan](../../superpowers/plans/2026-05-10-f-2-eval-framework-v0.1.md) — the implementation plan with 16 numbered tasks, every commit hash pinned.
- [ADR-001](ADR-001-monorepo-bootstrap.md) — Apache 2.0 / BSL 1.1 split; charter + eval-framework are the OSS pair.
- [ADR-003](ADR-003-llm-provider-strategy.md) — tiered LLMProvider; eval-framework's `run_across_providers` is the substrate for the parity gate.
- [ADR-007](ADR-007-cloud-posture-as-reference-agent.md) — Cloud Posture as the reference NLAH; the eval-runner pattern (Protocol + entry-point registration) is one of the ten patterns codified there.
- [Cloud Posture eval runner](../../../packages/agents/cloud-posture/src/cloud_posture/eval_runner.py) — the canonical implementation of `EvalRunner` for the framework's first user.
- [Eval framework README](../../../packages/eval-framework/README.md) — public surface + quick start.
