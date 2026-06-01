# Nexus Meta-Harness Agent (A.4)

**Status:** v0.1 — 15/16 tasks merged; final closure (verification record) is Task 16.

The first agent in the Nexus fleet that **reads other agents**. Runs cross-agent batch eval, A/B-compares NLAH variants, tracks scorecard deltas, flags regressions. **Producer of operator-facing diagnostics; ruthlessly read-only in v0.1.**

A.4 is the 16th agent shipped under [ADR-007](../../../docs/_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md) (the 12th to use ADR-007 v1.2's 21-LOC NLAH-loader shim) and the 6th of 7 unbuilt agents under the [Path-B-breadth-first operating rule](../../../docs/superpowers/sketches/2026-05-20-agent-version-roadmaps.md). Supervisor (#0) is the seventh and last.

## v0.1 surface (5 capabilities)

1. **Cross-agent batch evaluation** — runs every registered `nexus_eval_runners` entry-point's eval suite in a single batch (`BatchEvalRunner`).
2. **A/B comparison runner** — two NLAH variants of the same agent, same eval cases, deterministic byte-equal diff under stub-LLM mode (`ab_compare`).
3. **Agent introspection primitives** — parses NLAH directories per ADR-007 v1.2 (read-only; `parse_nlah_dir`).
4. **Scorecard delta tracking** — persists `agent_scorecard` entities in `SemanticStore`; compares each run to the prior run (`compute_batch_deltas`).
5. **Markdown report output** — `meta_harness_report.md` summarizing batch eval results, regressions flagged (≥5% drop), A/B comparison, watch-list section.

## Architecture (6-stage pipeline)

```
ExecutionContract / CLI args
        │
        ▼
┌──────────────────────────────────────────────────────────────────┐
│ Meta-Harness Agent driver (meta_harness.agent.run)               │
│                                                                  │
│  Stage 1: INTROSPECT      — parse all agents' NLAH dirs          │
│  Stage 2: BATCH_EVAL      — run each agent's eval suite          │
│  Stage 3: AB_COMPARE      — optional; only when --ab subcommand  │
│  Stage 4: DELTA           — diff scorecards vs previous run      │
│  Stage 5: REPORT          — assemble MetaHarnessReport           │
│  Stage 6: HANDOFF         — meta_harness_report.md + KG opt-in   │
└─────────┬────────────────────────────────────────────────────────┘
          │
          ▼
┌──────────────────────────────────────────────────────────────────┐
│ Tools (per-stage)                                                │
│  tools/nlah_parser.py     ─→ AgentManifest per agent (read-only) │
│  eval/batch.py            ─→ BatchEvalRunner (agent-local)       │
│  tools/ab_compare.py      ─→ ABComparison (single-agent A/B)     │
│  tools/scorecard_delta.py ─→ per-agent delta vs prev scorecard   │
│  tools/regression_flagger ─→ ≥5% drop flagged                    │
│  reporter.py              ─→ meta_harness_report.md              │
│  kg_writer.py             ─→ SemanticStore (entity_type=         │
│                              "agent_scorecard" +                 │
│                              "ab_comparison_result"; opt-in)     │
└──────────────────────────────────────────────────────────────────┘
```

## Smoke runbook (3 steps)

These are the three commands a maintainer runs to verify a clean local check-out of A.4. Each step is independent and idempotent. Run them in order from the repository root.

### 1. Unit tests + gates

```sh
uv run pytest packages/agents/meta-harness/tests/ -q
uv run ruff check packages/agents/meta-harness/
uv run ruff format --check packages/agents/meta-harness/
uv run mypy --strict packages/agents/meta-harness/src
```

Expected: `214 passed`; `ruff check`/`format` clean; `mypy --strict` 0 errors across 16 source files. (Counts grow over time — the load-bearing assertion is "no failures.")

### 2. Eval suite (10 bundled cases)

```sh
uv run meta-harness eval
```

Expected: `10/10 passed`. Each case exercises a distinct behavior (clean batch / regressions / A/B byte-equal / A/B divergent / per-agent failure tolerated / first-run baseline / watch-list / introspection / KG no-op). All 10 also pass the WI-3 byte-equal-across-reruns probe (`tests/test_stub_llm_harness.py`).

### 3. Batch-run against the real shipped fleet

```sh
uv run meta-harness run --customer-id smoke --run-id smoke-$(date +%s)
```

Expected: a one-line digest like `evaluated 16 agent(s); N successful; M regression(s) flagged` plus a `meta_harness_report.md` in the current directory. A.4 evaluates every registered `nexus_eval_runners` entry point (16 today: cloud_posture / vulnerability / identity / runtime_threat / audit / investigation / network_threat / multi_cloud_posture / k8s_posture / remediation / data_security / threat_intel / compliance / synthesis / curiosity / meta_harness).

The first run against any environment establishes the **baseline** — no regressions flag because there's no prior scorecard to compare against. Subsequent runs (once `--semantic-store-dsn` is wired post-SET-LOCAL-fix) surface real deltas.

## CLI

Three subcommands; full surface documented in [docs/superpowers/plans/2026-05-21-a-4-meta-harness-v0-1.md](../../../docs/superpowers/plans/2026-05-21-a-4-meta-harness-v0-1.md):

```sh
meta-harness eval [CASES_DIR]                          # default: bundled eval/cases
meta-harness run --customer-id ID --run-id ID          # 6-stage pipeline end-to-end
meta-harness ab-compare AGENT_ID                       # single-agent A/B
    --variant-a PATH/to/nlah
    --variant-b PATH/to/nlah/.proposed
```

## Q-ARCH deferrals (v0.2+ surface — explicitly NOT in v0.1)

These three architectural deferrals are load-bearing — A.4 v0.2's plan author MUST review them before re-introducing the corresponding surface.

### Q-ARCH-1: subscriber-ACL fence ([ADR-012](../../../docs/_meta/decisions/ADR-012-claims-subject-namespace.md))

**v0.1:** A.4 reads, evaluates, reports. No write to NLAH directories. No bus publish. No remediation. The ADR-012 forbidden-subscriptions fence does not apply.

**v0.2 carry-forward (WI-5):** When A.4 v0.2 adds auto-deploy of NLAH changes (per deferral #2), A.4 **becomes an auto-acting agent** and MUST be added to the forbidden-subscriptions registry. The verification record carries this verbatim so the v0.2 plan author can't miss the constraint.

### Q-ARCH-2: new fabric subject

**v0.1:** workspace markdown + SemanticStore entity is sufficient. Operators read the report; no real-time consumer exists today.

**v0.2 (conditional):** if A.4 v0.2 introduces real-time proposal emission (e.g., for operator notification when a regression detects), a new subject ADR modeled on ADR-012's shape lands at that point. Do NOT pre-commit the subject namespace in v0.1.

### Q-ARCH-3: eval-framework substrate extensions

**v0.1:** package-local first. The `BatchEvalRunner` lives under `meta_harness/eval/batch.py`, not under `packages/eval-framework/`. Per ADR-007's 3rd-consumer hoist rule.

**Future:** if Supervisor (#0) v0.1 plan or any future agent becomes the 3rd consumer, hoist to `packages/eval-framework/` at that point with a one-paragraph rationale in the hoist PR description.

## Watch-items (carried to verification record)

- **WI-1:** substrate sealed — `git diff --stat packages/charter/ packages/shared/` empty across all 16 tasks.
- **WI-2:** single-tenant default — `semantic_store=None` opt-in throughout; no cross-tenant reads.
- **WI-3:** stub-LLM determinism — per-case `responses.json`; byte-equal across reruns (10/10 cases pass the probe).
- **WI-4:** no NLAH writes — read-only enforced by `tests/test_tools_nlah_parser.py::test_wi4_parser_never_opens_in_write_mode`, which patches `Path.open` + `builtins.open` and asserts every observed mode is read-only.
- **WI-5:** Q-ARCH-1 carry-forward — verification record explicitly names "A.4 v0.2 plan MUST include subscriber-ACL review per ADR-012" so the v0.2 plan author can't miss the constraint.

## Out of scope (v0.1) — explicit version-named deferrals

1. **NO autonomous skill creation.** Deferred to A.4 v0.2.
2. **NO auto-deploy of NLAH changes.** A.4 v0.1 may propose in the report markdown (operator review only). Deferred to A.4 v0.3.
3. **NO new fabric subject.** Workspace + KG only. Deferred to A.4 v0.2 (conditional).
4. **NO autonomous Curator behavior.** Deferred to A.4 v0.3.
5. **NO multi-tenant production.** Blocks on future `SET LOCAL $1` tenant-RLS substrate-fix.
6. **NO eval-framework substrate hoist UNLESS demonstrably required by 2+ consumers.**
7. **NO cross-agent A/B.** Single-agent A/B only. Deferred to v0.2.

## Conformance pointers

- [ADR-001](../../../docs/_meta/decisions/ADR-001-monorepo-bootstrap.md) — monorepo
- [ADR-005](../../../docs/_meta/decisions/ADR-005-async-tool-wrapper-convention.md) — async tool wrappers
- [ADR-006](../../../docs/_meta/decisions/ADR-006-llm-adapter.md) — LLM adapter
- [ADR-007 v1.1 + v1.2](../../../docs/_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md) — reference NLAH agent
- [ADR-008](../../../docs/_meta/decisions/ADR-008-eval-framework.md) — eval framework
- [ADR-010](../../../docs/_meta/decisions/ADR-010-within-agent-version-extension.md) — within-agent version extension (additive audit-action vocabulary)
- [ADR-011](../../../docs/_meta/decisions/ADR-011-pr-flow-and-branch-protection-discipline.md) — PR flow + branch protection
- [ADR-012](../../../docs/_meta/decisions/ADR-012-claims-subject-namespace.md) — `claims.>` subject namespace + subscriber ACL (the WI-5 carry-forward target)

## Plan + verification

- Plan: [docs/superpowers/plans/2026-05-21-a-4-meta-harness-v0-1.md](../../../docs/superpowers/plans/2026-05-21-a-4-meta-harness-v0-1.md)
- Verification record (lands in Task 16): `docs/_meta/a-4-meta-harness-v0-1-verification-2026-05-21.md`

## Optional: DSPy + GEPA skill optimization (v0.2.5)

The v0.2.5 skill-optimization layer (DSPy + GEPA) installs via the `[dspy]`
optional-dependency group — kept optional so substrate and non-A.4 agents do
not inherit its ~40-package footprint:

```sh
uv pip install -e packages/agents/meta-harness[dspy]
```

Without the extra, `import meta_harness` works normally; DSPy-backed
compilation paths (Tasks 4+) are wired behind lazy imports.
