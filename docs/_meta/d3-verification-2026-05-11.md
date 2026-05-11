# D.3 verification record — 2026-05-11

Final-verification gate for **D.3 Runtime Threat Agent (CWPP)**. Fourth agent shipped to the [F.3 / ADR-007 reference template](decisions/ADR-007-cloud-posture-as-reference-agent.md). First agent built end-to-end against the **post-v1.2 canon** (NLAH-loader hoist).

All sixteen tasks are committed; every pinned hash is in the [D.3 plan](../superpowers/plans/2026-05-11-d-3-runtime-threat-agent.md)'s execution-status table.

---

## Gate results

| Gate                                                   | Threshold                                                           | Result                         |
| ------------------------------------------------------ | ------------------------------------------------------------------- | ------------------------------ |
| `pytest --cov=runtime_threat --cov-fail-under=80`      | ≥ 80%                                                               | **94.97%** (181 tests passing) |
| `ruff check`                                           | clean                                                               | ✅                             |
| `ruff format --check`                                  | clean                                                               | ✅                             |
| `mypy --strict`                                        | clean (13 source files)                                             | ✅                             |
| `runtime-threat-agent eval`                            | 10/10                                                               | ✅                             |
| `eval-framework run --runner runtime_threat`           | 10/10 (100.0%)                                                      | ✅                             |
| `eval-framework gate suite --config min_pass_rate=1.0` | exit 0                                                              | ✅                             |
| **ADR-007 v1.1 conformance**                           | no `runtime_threat/llm.py`; `charter.llm_adapter` consumed directly | ✅                             |
| **ADR-007 v1.2 conformance**                           | 25-line `nlah_loader.py` shim; delegates to `charter.nlah_loader`   | ✅                             |

### Repo-wide sanity check

`uv run pytest -q` → **921 passed, 5 skipped** (skips are opt-in LocalStack / Ollama integration tests). +236 tests vs. the D.2/F.4 verification baseline; no regressions.

---

## ADR-007 v1.2 conformance review

D.3 is the fourth agent built to the reference template, and the **first** to consume both amendments (v1.1 + v1.2) from day one. Per-pattern verdicts:

| Pattern                                       | Verdict                            | Notes                                                                                                                                                                      |
| --------------------------------------------- | ---------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Schema-as-typing-layer (OCSF wire format)     | ✅ generalizes                     | `class_uid 2004` Detection Finding (shared with D.2); five-bucket FindingType enum (PROCESS / FILE / NETWORK / SYSCALL / OSQUERY)                                          |
| Async-by-default tool wrappers                | ✅ generalizes                     | Three new flavors: filesystem-JSONL (Falco, Tracee) + subprocess-with-timeout (OSQuery). Same async-via-`asyncio.to_thread` and `asyncio.create_subprocess_exec` patterns. |
| HTTP-wrapper convention                       | n/a                                | Runtime Threat is filesystem + subprocess at the tool layer; no HTTP.                                                                                                      |
| Concurrent `asyncio.TaskGroup` enrichment     | ✅ generalizes                     | 3-feed fan-out; each feed independently skippable. Pattern carries from D.2's IAM-listing + Access-Analyzer 2-fold.                                                        |
| Markdown summarizer (top-down severity)       | ✅ generalizes                     | One delta: "Critical runtime alerts" section pinned above per-severity (mirrors D.1 KEV / D.2 high-risk-principals)                                                        |
| NLAH layout (README + tools.md + examples/)   | ✅ **v1.2-validated from scratch** | `nlah_loader.py` is **25 LOC** (vs D.1's pre-hoist 55 LOC). The shim diff is the visible savings the v1.2 hoist was supposed to buy.                                       |
| LLM adapter via `charter.llm_adapter`         | ✅ **thrice-validated**            | Anti-pattern guard test (`test_no_per_agent_llm_module`) is green; `find packages/agents/runtime-threat -name 'llm.py'` returns empty.                                     |
| Charter context + `agent.run` signature shape | ✅ generalizes                     | Fourth agent with `(contract, *, llm_provider=None, ...)` shape. Convergence is now a discipline, not a coincidence.                                                       |
| Eval-runner via entry-point group             | ✅ generalizes                     | `nexus_eval_runners: runtime_threat → runtime_threat.eval_runner:RuntimeThreatEvalRunner`; 10/10 via the framework CLI.                                                    |
| CLI subcommand pattern (`eval` + `run`)       | ✅ generalizes                     | Click group; same shape as D.2.                                                                                                                                            |

**v1.2 twice-validated.** Three retrofitted agents (cloud-posture / vulnerability / identity, post-hoist) all run on the shim; D.3 is the first agent to ship with the shim from day one. **No new amendment required from D.3.**

### v1.3 candidate flagged

Severity normalization across heterogeneous sensors (Falco priority strings + Tracee int + caller-supplied OSQuery) currently lives at `runtime_threat.severity`. If **D.4 Network Threat Agent's** pcap classifier ships a third native severity scale, this becomes duplicate #3 and per ADR-007 v1.1's "amend on the third duplicate" rule should hoist into `charter.severity` before D.5 ships. Logged here so the v1.3 trigger is unmissable.

---

## Per-task surface

| Surface                                                       | Commit          |   Tests | Notes                                                                                      |
| ------------------------------------------------------------- | --------------- | ------: | :----------------------------------------------------------------------------------------- |
| Bootstrap (pyproject, BSL, py.typed, README stub, smoke gate) | `27c04a3`       |       4 | First smoke includes the v1.2 import gate (`test_charter_nlah_loader_import_works`)        |
| OCSF v1.3 Detection Finding schema + 5-bucket FindingType     | `2a3ffd6`       |      41 | **Q1 resolved**: `class_uid 2004` shared with D.2                                          |
| `falco_alerts_read` async wrapper                             | `2a3ffd6`       |      12 | Tolerates malformed lines                                                                  |
| `tracee_alerts_read` async wrapper                            | `e5b5843`       |      11 | ns timestamp + args-list flatten + k8s lift                                                |
| `osquery_run` subprocess wrapper                              | `e5b5843`       |      10 | **Q2 resolved**: all three feeds ship in v0.1                                              |
| Severity normalizer (3 native scales → internal Severity)     | `f97ded0`       |      25 | Full parametrized matrix                                                                   |
| Findings normalizer (5-family dispatch)                       | `f97ded0`       |      20 | No v0.1 dedup — Q3 deferred to D.7 Investigation                                           |
| Markdown summarizer with critical-alerts pin                  | `b785b4a`       |      14 | Layout: severity breakdown → finding-type breakdown → Critical pin → per-severity sections |
| NLAH bundle + 25-line shim                                    | `b785b4a`       |       8 | **First agent shipped natively on v1.2**                                                   |
| `charter.llm_adapter` consumption                             | `b785b4a`       | (smoke) | **v1.1 thrice-validated**; anti-pattern guard green                                        |
| Agent driver `run()`                                          | `b84fe5c`       |      13 | TaskGroup multi-feed fan-out; each feed optional                                           |
| 10 representative YAML eval cases                             | `b84fe5c`       |  (data) | 5-family coverage + multi-feed overlap + clean-cluster baseline                            |
| `RuntimeThreatEvalRunner` + entry-point + 10/10 acceptance    | `b84fe5c`       |      15 | Verified end-to-end via `eval-framework run --runner runtime_threat`                       |
| CLI (`runtime-threat-agent eval` / `run`)                     | _(this commit)_ |       8 | Real end-to-end Falco-feed test included                                                   |
| README + runbook + ADR-007 v1.2 conformance addendum          | _(this commit)_ |       — | Operator runbook walks through Falco / Tracee / OSQuery staging                            |
| Final verification                                            | _(this commit)_ |       — | This record                                                                                |

**Test count breakdown:** 4 + 41 + 12 + 11 + 10 + 25 + 20 + 14 + 8 + (smoke covers Task 10) + 13 + 15 + 8 = **181 package tests passing**.

---

## Wiz weighted coverage delta

Per the [system-readiness recommendation](system-readiness-2026-05-11-1647ist.md) the Wiz-equivalent weight for CWPP is approximately 0.10. D.3 ships with ~50% domain coverage in v0.1 (Falco + Tracee alert ingestion + OSQuery point-in-time queries; deferring live-stream, Kubernetes DaemonSet wiring, and Windows sensors).

| Product family              | Wiz weight | Pre-D.3 contribution | D.3 contribution       | New estimate |
| --------------------------- | ---------: | -------------------: | ---------------------- | -----------: |
| CSPM (F.3 + D.1)            |       0.40 |                   8% | —                      |           8% |
| Vulnerability (D.1)         |       0.15 |                   3% | —                      |           3% |
| CIEM (D.2)                  |       0.10 |                  3pp | —                      |           3% |
| **CWPP (D.3)**              |   **0.10** |                  0pp | **+5pp** (~50% × 0.10) |       **5%** |
| Other Wiz products          |       0.25 |                 0.8% | —                      |         0.8% |
| **Total weighted coverage** |   **1.00** |           **~14.8%** | **+5pp from D.3**      |   **~19.8%** |

The +5pp jump is larger than D.2's +3pp because CWPP's Phase 1 surface is narrower (alert consumption, not active probing). The same Wiz weight applied at higher per-agent coverage produces a bigger jump.

---

## Sub-plan completion delta

Closed in this run:

- D.3 Runtime Threat Agent (16/16) — +1 agent (#4 of 18).

**Phase-1a foundation status:** F.1 ✓ · F.2 ✓ · F.3 ✓ · F.4 ✓ · **F.5 ⬜ (next plan to write)** · F.6 ⬜.
**Track-D agent status:** D.1 ✓ · D.2 ✓ · **D.3 ✓ (this run)** · D.4+ pending.

Four agents now ship to the reference template. ADR-007 has been amended twice and is twice-validated for each amendment. The pattern fitness coefficient is the strongest signal in the repo: each Track-D agent shipped within ~1 day's work of starting, and the substrate quality (coverage, mypy strict, test count) keeps rising in lockstep with surface growth.

---

## Carried-forward risks (none new from D.3)

The risk dashboard from the [system-readiness snapshot at 16:47 IST](system-readiness-2026-05-11-1647ist.md) carries forward unchanged. Specifically:

1. **Frontend zero LOC** (Tracks S.1-S.4) — unchanged.
2. **Edge plane zero LOC** (Tracks E.1-E.3, Go runtime) — unchanged.
3. **Three-tier remediation (Track A) zero LOC** — unchanged.
4. **F.5 memory engines architectural decision** — collapse to Postgres+JSONB+pgvector for Phase 1a per F.4 Q1 resolution; F.5 plan inherits.
5. **Eval cases capped at 10/agent** (target 100/agent at GA) — unchanged; parallelizable.
6. **v1.3 ADR-007 candidate** — severity normalization, watch for D.4 to crystallize.

No risks added by D.3 closing.

---

## Sign-off

D.3 Runtime Threat Agent is **production-ready for v0.1 deterministic flows**. ADR-007 amendments v1.1 and v1.2 are both twice-validated; the canon is locked. Substrate is locked; the remaining 14 Track-D agents are pure pattern application against `charter.{llm_adapter,nlah_loader}` + the canonical eval-runner shape.

**Recommended next plan to write: F.5 — Memory engines.** Per the system-readiness recommendation, collapse to PostgreSQL + JSONB + pgvector for Phase 1a; defer TimescaleDB (episodic) and Neo4j Aura (semantic/KG) to Phase 1b/2. F.5 unblocks D.7 Investigation Agent's knowledge-graph needs and the multi-feed cross-correlation pass that v0.1 D.3 explicitly defers.

— recorded 2026-05-11
