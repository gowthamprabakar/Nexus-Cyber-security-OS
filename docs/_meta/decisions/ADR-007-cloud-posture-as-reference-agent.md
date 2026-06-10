# ADR-007 — Cloud Posture is the reference NLAH

- **Status:** accepted (v1.6 — amended 2026-05-31 with DSPy programs as the canonical prompt shape; see [§v1.6 amendment](#v16-amendment-2026-05-31---dspy-programs-as-the-canonical-prompt-shape) · prior v1.5 added G1 effectiveness-scoring canonical patterns · prior v1.4 added progressive-disclosure NLAH loader · prior v1.3 added the always-on agent class · prior v1.2 hoisted the NLAH loader · prior v1.1 hoisted the LLM adapter)
- **Date:** 2026-05-10 (v1.0); 2026-05-11 (v1.1); 2026-05-11 (v1.2); 2026-05-12 (v1.3); 2026-05-22 (v1.4); 2026-05-25 (v1.5); 2026-05-31 (v1.6)
- **Authors:** AI/Agent Eng, Detection Eng
- **Stakeholders:** every agent author; PM (capacity planning); compliance (audit-chain consistency across agents)

## Context

Phase 1 ships **18 agents**. Building each one from scratch wastes effort, produces shape drift across the suite, and makes the audit-chain / OCSF / charter-context invariants drift agent-by-agent. Compliance reviewers need to find one canonical implementation and trust that the other 17 follow the same rules.

Three plausible candidates for "first agent":

1. **Cloud Posture (CSPM)** — Prowler-driven misconfiguration scanner.
2. **Vulnerability (CVE)** — Trivy-driven vuln scanner.
3. **Identity (CIEM)** — custom permission simulator.

We had to pick one to ship F.3 against, then derive the other 17.

## Decision

**Cloud Posture is the reference NLAH.** The implementation in [`packages/agents/cloud-posture/`](../../../packages/agents/cloud-posture/) is the template. The other 17 agents follow this template; deltas from the template are recorded in per-agent ADRs.

## What "reference" means concretely

The Cloud Posture agent is canonical for these patterns. Other agents diverge only with explicit ADR justification.

| Pattern                                                                                                                   | Reference implementation                                                                                                                                                    | Lives in                                                                                                        |
| ------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| **Charter-wrapped invocation**                                                                                            | `with Charter(contract, tools=registry) as ctx: ...` (or async variant)                                                                                                     | [`agent.py`](../../../packages/agents/cloud-posture/src/cloud_posture/agent.py)                                 |
| **Async tool wrappers** ([ADR-005](ADR-005-async-tool-wrapper-convention.md))                                             | `asyncio.create_subprocess_exec` for binaries; `asyncio.to_thread(boto3...)` for sync SDKs; `httpx.AsyncClient` for HTTP                                                    | [`tools/`](../../../packages/agents/cloud-posture/src/cloud_posture/tools/)                                     |
| **OCSF wire format** ([ADR-004](ADR-004-fabric-layer.md))                                                                 | `build_finding(...)` constructs OCSF v1.3 Compliance Finding (`class_uid 2003`); `CloudPostureFinding` is a typed accessor over the wrapped dict                            | [`schemas.py`](../../../packages/agents/cloud-posture/src/cloud_posture/schemas.py)                             |
| **NexusEnvelope** (per finding)                                                                                           | `correlation_id`, `tenant_id`, `agent_id`, `nlah_version`, `model_pin`, `charter_invocation_id`                                                                             | [`shared.fabric.envelope`](../../../packages/shared/src/shared/fabric/envelope.py)                              |
| **NLAH directory shape**                                                                                                  | `nlah/README.md` (canonical brain) + `nlah/tools.md` (tool index) + `nlah/examples/*.md` (few-shot, OCSF-shaped) — packaged inside the importable wheel                     | [`nlah/`](../../../packages/agents/cloud-posture/src/cloud_posture/nlah/)                                       |
| **NLAH loader**                                                                                                           | `load_system_prompt(nlah_dir)` + `default_nlah_dir(package_file)` — **shared** in `charter.nlah_loader` (per ADR-007 v1.2); agents ship a 25-line `__file__`-binding shim   | [`charter.nlah_loader`](../../../packages/charter/src/charter/nlah_loader.py)                                   |
| **LLM provider plumbing** ([ADR-003](ADR-003-llm-provider-strategy.md), [ADR-006](ADR-006-openai-compatible-provider.md)) | Driver accepts `Optional[LLMProvider]`; the **shared** `make_provider(LLMConfig)` selects Anthropic / OpenAI / vLLM / Ollama from `NEXUS_LLM_*` env vars (per ADR-007 v1.1) | [`charter.llm_adapter`](../../../packages/charter/src/charter/llm_adapter.py)                                   |
| **Eval shape**                                                                                                            | YAML cases with `fixture` (mocked tool outputs) + `expected` (finding count + per-severity counts); placeholder runner until F.2 eval-framework lands                       | [`eval/`](../../../packages/agents/cloud-posture/eval/)                                                         |
| **CLI surface**                                                                                                           | `cloud-posture eval CASES_DIR` + `cloud-posture run --contract path.yaml` via `[project.scripts]` entry point                                                               | [`cli.py`](../../../packages/agents/cloud-posture/src/cloud_posture/cli.py)                                     |
| **Test layout**                                                                                                           | `tests/test_*.py` for unit + `tests/integration/` for opt-in live tests gated by `NEXUS_LIVE_*` env vars                                                                    | [`tests/`](../../../packages/agents/cloud-posture/tests/)                                                       |
| **Smoke runbook**                                                                                                         | `runbooks/<environment>_smoke.md` with read-only-confirmation gate, contract-validate gate, CloudTrail review, failure protocol with regression-eval requirement            | [`runbooks/aws_dev_account_smoke.md`](../../../packages/agents/cloud-posture/runbooks/aws_dev_account_smoke.md) |

## Why Cloud Posture and not the alternatives

### Positive (why this works as the template)

- **Smallest tool surface** (~7 tools) — agent authors learn the pattern without fighting domain complexity.
- **Highest-value Day-1** — every customer in every vertical needs CSPM. The reference agent is the one customers actually want to run first.
- **Mature OSS foundation** — Prowler is battle-tested with stable JSON-OCSF output. The integration risk is in our wiring, not in the upstream tool.
- **Vertical-agnostic** — cloud misconfigurations look the same in tech, healthcare, finance, defense. The template doesn't accidentally encode tech-vertical assumptions.
- **OCSF natively** — Prowler emits OCSF JSON. The mapping from Prowler-OCSF to Nexus-OCSF (with `nexus_envelope`) is a clean translation, not a structural transformation. Validates [ADR-004](ADR-004-fabric-layer.md) on a real upstream.
- **Deterministic in v0.1** — no LLM in the loop yet. The flow is testable end-to-end with mocks (10 eval cases pass, integration tests against LocalStack pass, live qwen3:4b proves the LLM seam separately). New agent authors don't have to debug both their domain logic AND non-determinism on day one.

### Negative (where the template won't generalize 1:1)

- **Investigation Agent** ([D.7](../../superpowers/plans/2026-05-08-build-roadmap.md)) needs sub-agent orchestration (depth ≤ 3, parallel ≤ 5) — the Cloud Posture template assumes single-process, single-driver. Mitigation: Investigation gets its own ADR documenting the orchestration pattern that extends the template.
- **Curiosity Agent** ([D.12](../../superpowers/plans/2026-05-08-build-roadmap.md)) is _reactive_, not heartbeat-scheduled — runs in idle slack rather than on contract. Mitigation: Curiosity ADR describes the trigger semantics; the rest of the template (charter context, OCSF, NexusEnvelope) still applies unchanged.
- **AI Security Agent** ([D.11](../../superpowers/plans/2026-05-08-build-roadmap.md)) and **Synthesis Agent** ([D.13](../../superpowers/plans/2026-05-08-build-roadmap.md)) are LLM-first by nature; the deterministic-in-v0.1 stance doesn't apply to them. Mitigation: their ADRs document required LLM tier (frontier vs workhorse) and any new audit-event types beyond `llm_call_started/completed/failed`.

### Neutral

- The 10-case eval suite is a starting point. Phase 1 target is **≥ 100 cases per agent** ([build-roadmap.md success criteria](../../superpowers/plans/2026-05-08-build-roadmap.md)). Adding cases is incremental work in the same YAML structure — no infrastructure change required.
- The reference uses AWS only. Azure / GCP support is the same code path with different cloud SDKs in the tool layer; the template doesn't change.

## Alternatives considered

### Alt 1: Vulnerability Agent first

- Why rejected: requires a working asset graph + EPSS feed + image scanning + IaC scanning before the pattern is stable. Three integrations on day one, not one. We'd be debugging the integration layer instead of validating the template.

### Alt 2: Identity Agent (CIEM) first

- Why rejected: a custom permission simulator is significant Phase 1 work in its own right. Building it as the reference would entangle "what's the agent template?" with "what's the right CIEM design?" — two questions whose answers shouldn't compromise each other.

### Alt 3: Audit Agent first

- Why rejected: the Audit Agent ([F.6](../../superpowers/plans/2026-05-08-build-roadmap.md)) is plumbing — it doesn't have customer-facing detection logic. Templating off plumbing produces a template that doesn't generalize to detection agents.

### Alt 4: No reference agent — every agent author writes from scratch

- Why rejected: this is what the document started by warning against. The result is shape drift, audit-chain inconsistency, and 18 different OCSF dialects.

## What this ADR commits us to

1. The Cloud Posture implementation is treated as **load-bearing for the suite** — breaking changes to it cascade to template-following agents and require their ADRs to update in lockstep.
2. **Each new agent ships a per-agent ADR** that either declares "follows the Cloud Posture template" or itemizes deviations with justification.
3. **Agent reviewers** check the ten template patterns above (charter context, async tools, OCSF, NexusEnvelope, NLAH layout, LLM plumbing, eval shape, CLI surface, test layout, smoke runbook) before accepting any new agent. A new agent that drifts on a pattern needs an ADR before it merges, not after.
4. The Cloud Posture eval suite is the **regression substrate** for the template itself. If a charter / schema / fabric change breaks a Cloud Posture eval case, that's a template breakage and demands a co-ordinated fix across template-following agents.

## References

- F.3 build plan with execution status: [`docs/superpowers/plans/2026-05-08-f-3-cloud-posture-reference-nlah.md`](../../superpowers/plans/2026-05-08-f-3-cloud-posture-reference-nlah.md)
- Reference implementation: [`packages/agents/cloud-posture/`](../../../packages/agents/cloud-posture/)
- Sister ADRs (define rules this template enforces):
  - [ADR-002 — charter as context manager](ADR-002-charter-as-context-manager.md)
  - [ADR-003 — LLM provider strategy](ADR-003-llm-provider-strategy.md)
  - [ADR-004 — fabric layer + OCSF wire format](ADR-004-fabric-layer.md)
  - [ADR-005 — async tool wrapper convention](ADR-005-async-tool-wrapper-convention.md)
  - [ADR-006 — OpenAI-compatible provider](ADR-006-openai-compatible-provider.md)
- Build roadmap: [`docs/superpowers/plans/2026-05-08-build-roadmap.md`](../../superpowers/plans/2026-05-08-build-roadmap.md)
- System readiness snapshot: [`docs/_meta/system-readiness.md`](../system-readiness.md)

---

## v1.1 amendment (2026-05-11) — LLM-adapter hoist

### Trigger

D.1 (Vulnerability Agent) was the first agent built to ADR-007 v1.0. Its [verification record](../d1-verification-2026-05-11.md) validated **10 of 10** patterns and surfaced **one** that needed amendment: the LLM provider plumbing.

### What changed

Cloud Posture's `cloud_posture/llm.py` and Vulnerability's `vulnerability/llm.py` were **byte-for-byte identical** modulo the docstring header (literally a 1-line diff). Nothing in the LLM-adapter logic is agent-specific — it reads `NEXUS_LLM_*` env vars and selects from {Anthropic, OpenAI, OpenAI-compatible, vLLM, Ollama}. Per-agent duplication had zero design value and would have grown to 18 copies as Track-D filled out.

The amendment:

1. **Hoist** the LLM adapter into `nexus-charter` as `charter.llm_adapter`. The module is now a peer of `charter.llm` (the Protocol), `charter.llm_anthropic` (Anthropic provider), `charter.llm_openai_compat` (OpenAI-compatible provider).
2. **Delete** `cloud_posture/llm.py` and `vulnerability/llm.py`. Each agent's runtime code didn't import them in v0.1 anyway (deterministic flow).
3. **Move** `test_llm.py` from each agent into a single canonical `packages/charter/tests/test_llm_adapter.py`. 19 tests cover the full surface; deleting the two per-agent copies removed 38 redundant tests.
4. **Update the reference table above** — the LLM-provider-plumbing row now points at `charter.llm_adapter` instead of `cloud_posture/llm.py`.

### Future agents

All 18 agents (and any third-party agent built on Nexus) do:

```python
from charter.llm_adapter import LLMConfig, make_provider, config_from_env

config = config_from_env()  # reads NEXUS_LLM_*
provider = make_provider(config)
# pass into agent.run(contract, llm_provider=provider, ...)
```

No per-agent `llm.py`. Any future divergence (e.g., a custom provider that no other agent needs) goes into a separate per-agent module rather than a copy of the adapter.

### What this validates

- **ADR-007 v1.0 was right at the policy level** (one canonical reference, others follow), even though one specific item was at the wrong **scope** (per-agent copy where shared was correct).
- The risk-down review pattern works: D.1 caught this before D.2–D.13 multiplied the duplication. Amendment via a small charter PR before the next agent starts.
- Future risk-down reviews (e.g., D.2's pattern check, A.4's Meta-Harness conformance review) follow the same shape — surface deltas, queue ADR amendments, land before the next agent.

### Cross-package blast radius

| Change                                             | Files affected                              |
| -------------------------------------------------- | ------------------------------------------- |
| New module `charter/llm_adapter.py`                | 1 file (~165 LOC, copy with updated doc)    |
| Canonical test `charter/tests/test_llm_adapter.py` | 1 file (19 tests; from cloud-posture)       |
| Deleted `cloud_posture/llm.py`                     | -1 file                                     |
| Deleted `vulnerability/llm.py`                     | -1 file                                     |
| Deleted `cloud_posture/tests/test_llm.py`          | -1 file                                     |
| Deleted `vulnerability/tests/test_llm.py`          | -1 file                                     |
| Net source LOC                                     | ~unchanged (1 canonical file replaces 2)    |
| Net test LOC                                       | -1 redundant copy                           |
| Repo tests after amendment                         | 459 passed / 5 skipped (was 478; -19 dupes) |

---

## v1.2 amendment (2026-05-11) — NLAH-loader hoist

### Trigger

D.2 (Identity Agent) was the second agent built to ADR-007 v1.1. Its [verification record](../d2-f4-verification-2026-05-11.md) confirmed the v1.1 LLM-adapter hoist twice over and surfaced **one** new candidate for hoisting: the NLAH loader.

After D.2 landed, three agents (cloud-posture, vulnerability, identity) were each shipping a near-identical `nlah_loader.py` — a ~55 LOC module that walks `nlah/README.md` + `nlah/tools.md` + `nlah/examples/*.md` and concatenates them into a system prompt. The implementations differed only in docstring wording. Per v1.1's "**amend on the third duplicate**" discipline, this is the right moment — before D.3 inherits a fourth copy.

### What changed

1. **Hoist** the canonical loader into `nexus-charter` as `charter.nlah_loader`. It now sits next to `charter.llm_adapter` and `charter.audit` as a shared substrate primitive.
2. **API shift:** the legacy zero-argument `default_nlah_dir()` becomes `default_nlah_dir(package_file)` — callers thread their own `__file__` so the shared module can locate each agent's adjacent `nlah/` directory.
3. **Each agent keeps a 25-line shim** (`identity/nlah_loader.py`, `vulnerability/nlah_loader.py`, `cloud_posture/nlah_loader.py`) that binds `__file__` and re-exports `default_nlah_dir()` + `load_system_prompt()` with the legacy zero-argument signatures. Tests, agent code, and downstream consumers see no API change.
4. **Canonical tests** land at `packages/charter/tests/test_nlah_loader.py` (10 tests covering `default_nlah_dir`, the four sections of `load_system_prompt`, and both error paths). The three per-agent test files keep passing unchanged against the shim — they exercise the same logic end-to-end.

### Future agents

A new agent ships a one-time shim (~25 lines) and never re-implements the load logic:

```python
# packages/agents/<new-agent>/src/<new_agent>/nlah_loader.py
from pathlib import Path
from charter.nlah_loader import default_nlah_dir as _resolve_default_dir
from charter.nlah_loader import load_system_prompt as _load


def default_nlah_dir() -> Path:
    return _resolve_default_dir(__file__)


def load_system_prompt(nlah_dir: Path | str | None = None) -> str:
    return _load(nlah_dir if nlah_dir is not None else default_nlah_dir())
```

Any improvement to the loader (e.g., supporting tenant-specific NLAH overrides in Phase 1b) lands once in `charter.nlah_loader` and every agent inherits it automatically.

### What this validates

- The "amend on the third duplicate" rule is now a confirmed habit, not a slogan. v1.1 caught one pattern at duplicate #2 (LLM adapter); v1.2 catches the next at duplicate #3 (NLAH loader). Both amendments landed before the next agent inherits the duplication.
- ADR-007 + risk-down reviews are the right shape for keeping 18 agents from drifting into local copies of substrate logic.

### Cross-package blast radius

| Change                                             | Files affected                                                        |
| -------------------------------------------------- | --------------------------------------------------------------------- |
| New module `charter/nlah_loader.py`                | 1 file (~75 LOC, canonical)                                           |
| Canonical test `charter/tests/test_nlah_loader.py` | 1 file (10 tests)                                                     |
| Cloud Posture `nlah_loader.py` collapsed to shim   | -30 LOC                                                               |
| Vulnerability `nlah_loader.py` collapsed to shim   | -30 LOC                                                               |
| Identity `nlah_loader.py` collapsed to shim        | -35 LOC                                                               |
| Per-agent test files (`test_nlah_loader.py` x 3)   | unchanged — they exercise the shim end-to-end                         |
| Net source LOC                                     | small net win (~-20 LOC) plus one logical home for future loader work |
| Repo tests after amendment                         | 740 passed / 5 skipped (was 730; +10 from charter canon, 0 lost)      |

---

## v1.3 amendment (2026-05-12) — Always-on agent class

**Triggered by:** F.6 Audit Agent. Per the glossary, the Audit Agent is **"the only agent the others cannot disable"** — its job is to record what happened, and a misconfigured caller must not be able to stop it. But the v1.0 / v1.1 / v1.2 reference template (Cloud Posture / D.1 / D.2 / D.3) honours **every** `BudgetSpec` axis: a `BudgetExhausted` on any of `llm_calls`, `tokens`, `wall_clock_sec`, `cloud_api_calls`, or `mb_written` raises and halts the run. For an audit-recording agent, that's wrong: a token-budget overrun on a chain-verification query is **less acceptable** than logging a warning and proceeding, because failing to record is the worse outcome than slightly exceeding a budget.

### The decision

We introduce an **always-on agent class** with one member in v0.1 (F.6 Audit Agent). An always-on agent honours **only `wall_clock_sec`** from its `BudgetSpec`. Every other budget axis catches `BudgetExhausted`, logs a structlog warning, and proceeds. `wall_clock_sec` still raises so a runaway query is killable.

The policy is **locked into the agent driver**, not the `BudgetEnvelope` itself. Other agents' `consume()` calls keep their hard stops. Only an always-on agent's driver wraps the consume in the catch-and-warn helper (`audit.agent._enforce_always_on`).

The allowlist of always-on agents is **explicit**. In v0.1 the only member is `audit_agent`. Adding a new always-on agent requires:

1. An ADR justifying why this agent can't be stoppable by a budget overrun.
2. A code-side opt-in via `_enforce_always_on` (or its successor).
3. The agent's driver carrying its own test that exercises the warning-not-raise path for every non-`wall_clock_sec` axis.

### Why not change `BudgetEnvelope` itself?

Three reasons:

1. **Blast radius.** Changing `BudgetEnvelope.consume` to never raise would affect every agent. The reference template's hard-stop behaviour is load-bearing for cost discipline on the 17 budget-bounded agents.
2. **Test surface.** Every agent's `test_agent.py` asserts `BudgetExhausted` raises for over-limit calls. Changing the envelope changes 17 test files at once.
3. **Explicit policy.** Catching `BudgetExhausted` in the driver makes the **policy choice visible at the agent's seam**. Reading `audit/agent.py` shows the warning-not-raise path immediately; reading another agent's `agent.py` makes the absence of that path obvious. Implicit "every agent that uses this envelope is always-on" would invert that and make the policy invisible.

### What this validates

- ADR-007 v1.0 said "deltas from the template are recorded in per-agent ADRs". F.6 is the first agent to deviate from the reference, and it lands here with the deviation justified and tested.
- The "amend on the third duplicate" rule still holds — but this is a different kind of amendment. v1.1 + v1.2 generalised patterns (duplicate code → shared substrate). v1.3 admits a controlled exception (one agent, one budget axis, one explicit allowlist). Both kinds belong in ADR-007.

### Pattern: how a future always-on agent opts in

```python
from charter.exceptions import BudgetExhausted

def _enforce_always_on(exc: BudgetExhausted) -> None:
    """ADR-007 v1.3 always-on policy. Only `wall_clock_sec` raises."""
    if exc.dimension == "wall_clock_sec":
        raise exc
    _LOG.warning(
        "always-on: budget axis %s exhausted (limit=%s, used=%s); proceeding",
        exc.dimension, exc.limit, exc.used,
    )
```

The driver wraps every `consume()` call site with the helper. Tests cover:

- A `BudgetExhausted` on `wall_clock_sec` raises out of the driver.
- A `BudgetExhausted` on `llm_calls`, `tokens`, `cloud_api_calls`, or `mb_written` logs a warning and the agent proceeds.
- The warning surfaces the dimension + limit + used so an operator can size the budget appropriately next time.

### What this does NOT change

- **Charter context manager.** `with Charter(contract, tools=registry) as ctx: ...` shape is unchanged. The always-on policy lives inside the `with` block, not around it.
- **Audit log.** Every action still emits a chained audit entry. The always-on policy is about budgets, not auditability — auditability is non-negotiable.
- **OCSF wire format.** Still 6003 (API Activity) for F.6; the always-on flag is a runtime behaviour, not a schema field.

### Cross-package blast radius

| Change                                              | Files affected                                                          |
| --------------------------------------------------- | ----------------------------------------------------------------------- |
| New helper `_enforce_always_on` in `audit/agent.py` | 1 file (~10 LOC)                                                        |
| Test that exercises both paths (`test_agent.py`)    | 2 new tests (raise on wall_clock; warn-not-raise on every other axis)   |
| No changes to `charter.budget`                      | 0 files — policy lives in the agent driver, not the envelope            |
| No changes to other agents' drivers                 | 0 files — only opted-in members of the always-on class touch the helper |
| Repo tests after amendment                          | 1168 passed / 11 skipped (was 1133; +35 from F.6 task work, 0 lost)     |

### v1.4 candidate flagged — REASSIGNED to v1.5 (2026-05-22)

If a future agent (e.g. D.7 Investigation when it consumes the audit chain at scale) needs the same exception, **promote `_enforce_always_on` to `charter.audit`** as a public helper. The pattern is duplicated at #2 → hoist at #3 per the established rule.

**Note (2026-05-25):** the v1.4 slot was reassigned to the progressive-disclosure NLAH loader extension (A.4 Meta-Harness v0.2). v1.5 was then taken by G1 effectiveness-scoring canonical patterns. The `_enforce_always_on` hoist is now deferred to v1.6 if/when the third consumer arrives.

---

## v1.4 amendment (2026-05-22) — Progressive-disclosure NLAH-loader extension

> **v1.4-slot reassignment note.** v1.4 was originally flagged as a candidate slot for hoisting `_enforce_always_on` to `charter.audit` when the pattern reached its third consumer. That candidate is now deferred to a future v1.5 amendment. v1.4 lands the progressive-disclosure NLAH loader extension instead — a more architecturally urgent amendment driven by A.4 Meta-Harness v0.2 (Phase 1 / Wave 0).

### Trigger

A.4 Meta-Harness v0.2 / Phase 1 / Wave 0 (per the [Hermes-pattern absorption doc](../hermes-pattern-absorption-2026-05-22.md) §6 landing map) absorbs nectar items **N1** (progressive-disclosure NLAH) + **N2** (autonomous skill creation) + **N5** (agentskills.io open format). The skill-loading machinery applies to all 17 v0.1 agents' NLAH directories, not just A.4's. Hoisting the progressive-disclosure loader into `charter.nlah_loader` keeps every agent's runtime aligned with the v1.2 surface — they continue to call into `charter.nlah_loader` for any NLAH read.

### The decision

Add four new public functions + one frozen dataclass + one error class to `charter.nlah_loader`, **strictly additive** to the v1.2 surface. The existing `default_nlah_dir` and `load_system_prompt` are unchanged; v1.2 callers (every 17 agents at v0.1) continue to work identically.

New surface:

- **`default_skills_dir(package_file)`** — sibling helper to `default_nlah_dir`. Returns `<package_dir>/nlah/skills`.
- **`SkillMetadataEntry`** — frozen dataclass carrying `(skill_id, name, description, version, category, target_agent, platforms, source)`. Level 0 metadata only; no markdown body. `source ∈ {"bundled", "overlay"}` distinguishes shipped skills from candidate-shadow-path skills.
- **`load_skill_metadata_index(nlah_dir, *, skills_overlay=None) -> tuple[SkillMetadataEntry, ...]`** — Level 0; walks `<nlah_dir>/skills/<category>/<skill-name>/SKILL.md` (+ optional overlay). Overlay entries take precedence over bundled entries with the same `skill_id`. Returns empty tuple when the skills dir doesn't exist (backwards-compat per WI-4 of A.4 v0.2).
- **`load_skill(nlah_dir, skill_id, *, skills_overlay=None) -> str`** — Level 1; returns the full SKILL.md text. Charter doesn't parse the body — agents pass the text into their own typed parser (e.g. `meta_harness.skill_format.parse_skill_md_content`). Overlay first, then bundled.
- **`load_skill_reference(nlah_dir, skill_id, ref_filename, *, skills_overlay=None) -> str`** — Level 2; one reference file under the skill's `references/` subdir. Overlay first, then bundled.
- **`SkillLoaderError`** — raised only when a SKILL.md file is _present_ but malformed (missing frontmatter, missing required keys, malformed YAML). Missing files raise `FileNotFoundError` per the v1.2 convention.

### The `skill_id` shape

`skill_id` is the relative path from the skills dir to the skill's parent directory: `<category>/<skill-name>`. Example: `iam-privesc/aws-assumed-role-chain`. The `(target_agent, category)` pair forms the first-of-class registry key consumed by A.4 v0.2's `skill_registry` (Task 9).

### The `provenance` frontmatter shape

Per drift #7 of A.4 v0.2's brainstorm, the `provenance` field on each SKILL.md's YAML frontmatter is `list[list[audit_log_path: str, entry_hash: str]]` — a list of 2-item pairs. YAML serialises tuples as lists, so the on-disk shape is:

```yaml
provenance:
  - [audit/r_eval.jsonl, deadbeefcafebabe]
  - [audit/r_another.jsonl, cafef00dcafef00d]
```

Charter's loader does not parse this field structurally — it surfaces the raw frontmatter at Level 1 and the agent's typed parser (e.g. `meta_harness.schemas.Skill`) interprets the pairs.

### Required SKILL.md frontmatter keys

Per agentskills.io + Nexus extensions (Q2 of the A.4 v0.2 plan):

- `name`, `description`, `version`, `platforms` (agentskills.io required).
- `target_agent`, `category` (Nexus required for routing the skill to a specific agent + first-of-class key).
- `created_by`, `provenance`, `eval_gate_status`, `deployment_status` (Nexus extensions; consumed by A.4's typed parser, not by charter).

A SKILL.md missing any of the first 6 keys raises `SkillLoaderError` at metadata-index parse time. The last 4 are validated by the per-agent typed parser, not charter.

### Why not a separate `charter.skills` module?

Three reasons:

1. **Surface cohesion.** Skills are loaded _alongside_ the rest of an NLAH (README + tools + examples). Putting them in `charter.nlah_loader` keeps the per-agent loader shim simple — one import, one entry-point for all NLAH-related I/O.
2. **No second hoist surface.** Per ADR-007's 3rd-consumer hoist rule, splitting skills into a new module would invite each agent to either depend on a second charter package or duplicate skill-loading code. The hoist-once-when-third-consumer-arrives rule says: hoist into the existing module.
3. **Backwards-compat is structural.** Adding to `nlah_loader.py` keeps the v1.2 import path stable; every v0.1 agent that already imports `charter.nlah_loader` gets the new surface without code changes.

### Cross-package blast radius

| Change                                                                                                                                                                               | Files affected                                                        |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------- |
| Additive functions in `charter/nlah_loader.py` (`default_skills_dir`, `load_skill_metadata_index`, `load_skill`, `load_skill_reference`) + `SkillMetadataEntry` + `SkillLoaderError` | 1 file (~200 LOC added)                                               |
| Tests covering the v1.4 surface in `packages/charter/tests/test_nlah_loader.py`                                                                                                      | 1 file (~14 new tests; existing tests untouched)                      |
| No changes to `default_nlah_dir` or `load_system_prompt`                                                                                                                             | 0 lines modified in the v1.2 surface — backwards-compat is structural |
| No changes to any agent's NLAH shim                                                                                                                                                  | 0 files — agents continue to use the v1.2 surface unchanged           |
| New `pyyaml` dependency on `packages/charter/pyproject.toml`? **No** — already present transitively via existing eval-framework path                                                 | 0 dependency additions                                                |

### What this validates

- ADR-007 v1.1's "hoist on the 3rd duplicate" rule extends naturally: the progressive-disclosure pattern would have been duplicated 17 times if each agent grew its own skills loader. Hoisting on Wave 0 (before any agent grows the duplication) is the equivalent move ADR-007 v1.2 made for the basic NLAH loader after the third per-agent copy.
- The v1.2 → v1.4 path is structurally additive — adding capability without breaking the existing surface. Same shape as v1.1 + v1.2 amendments.

### Future agents

When any v0.2+ agent ships its first `nlah/skills/` directory:

1. The agent's `nlah_loader.py` shim already calls `charter.nlah_loader`; no change needed.
2. The agent's runtime calls `load_skill_metadata_index(default_nlah_dir(__file__))` for Level 0 + `load_skill(...)` for Level 1 + `load_skill_reference(...)` for Level 2 as needed.
3. The agent's eval suite can opt-in to the skills overlay via `with_candidate_skill_overlay` (A.4 v0.2 Task 8's `BatchEvalRunner` extension) — eval-gate runs against the candidate without touching the canonical tree.

### Pattern: how a v0.2+ agent opts in

```python
from charter.nlah_loader import default_nlah_dir, load_skill_metadata_index, load_skill

NLAH_DIR = default_nlah_dir(__file__)

# Level 0 — pick a skill by description-match.
metadata = load_skill_metadata_index(NLAH_DIR)
chosen = next((m for m in metadata if "S3 policy" in m.description), None)

# Level 1 — load the full SKILL.md content.
if chosen is not None:
    skill_text = load_skill(NLAH_DIR, chosen.skill_id)
    # ... thread into the LLM system prompt, or parse via
    # meta_harness.skill_format.parse_skill_md_content if typed.
```

### What this does NOT change

- **v1.2 NLAH-loader contract.** `default_nlah_dir(__file__)` returns the same path; `load_system_prompt(nlah_dir)` returns the same concatenated text. Zero behavioural diff for existing agents.
- **Per-agent 21-LOC shim.** Each agent's `nlah_loader.py` shim is unchanged. Agents can choose to wrap the new v1.4 functions in their own typed surface (as A.4 v0.2 will via `meta_harness.skill_format`) or call charter directly.
- **F.5 SemanticStore.** Skills are file-backed in `nlah/skills/`; no SemanticStore entity persistence. Multi-tenant skill libraries remain post-SET-LOCAL-fix territory.
- **Audit chain.** Skill loading is read-only and produces no audit-chain entries on its own. A.4's skill-lifecycle entries (Task 12: `skill.candidate_emitted`, etc.) are the only F.6 surface here.

---

## v1.5 amendment (2026-05-25) — G1 effectiveness-scoring canonical patterns

### Trigger

A.4 Meta-Harness v0.2.5 shipped G1 effectiveness scoring ([ADR-011](../../adr/011-g1-effectiveness-scoring.md)): a confidence-weighted composite score for every deployed skill, computed from three axes — adoption (load frequency), outcome (run success correlation), and feedback (operator ratings). The implementation spans 12 tasks across 10 modules in `packages/agents/meta-harness/src/meta_harness/`, plus a 6-action audit-event vocabulary in `packages/shared/src/shared/skill_telemetry.py`.

G1 established five patterns that any future agent consuming or producing effectiveness telemetry must follow. These are now canonical — same status as the ten reference-template patterns in the table above.

### The five canonical patterns

#### Pattern 1: Effectiveness scoring is the canonical post-deployment telemetry layer

**What it is:** `meta_harness.skill_effectiveness.compute_effectiveness_score(skill_id, agent_id, *, audit_log, workspace_root, tenant_id="default")` returns an `EffectivenessScore` with `global_score` (0–1 float), `confidence` (0–1 float), per-axis breakdown, and a `reason` enum. The composite formula is confidence-weighted: axes with zero confidence drop out; denominator is the sum of remaining weights (adoption=0.25, outcome=0.35, feedback=0.40). `global_score` is `None` when all three axes have zero confidence (no data anywhere).

**Why it's canonical:** v0.2.5 GEPA compilation consumes `EffectivenessScore.global_score` as its `metric=` callable input for prompt optimization. Any future agent that deploys skills and wants GEPA to optimize those skills' prompts MUST produce scores through this interface. Per-skill scores are persisted to `<workspace>/.nexus/deployed-skills/<agent_id>/<skill_id>/effectiveness.json` — the workspace-scoped sidecar that mirrors the v1.4 candidate-sidecar pattern.

**Future agents:** call `compute_effectiveness_score` from their telemetry path (or rely on A.4's CLI `score-effectiveness` command). The function signature requires `audit_log` (CF #2 fix-pattern) and `workspace_root` (sidecar location). No agent should compute its own ad-hoc effectiveness formula — the composite weights and confidence curves are locked here.

#### Pattern 2: The 6 G1 audit actions are the canonical effectiveness-event vocabulary

**What it is:** Six audit-action constants defined in `shared.skill_telemetry`:

| Action                                     | Emitter                                        | Destination                      | Purpose                               |
| ------------------------------------------ | ---------------------------------------------- | -------------------------------- | ------------------------------------- |
| `agent.skill.loaded`                       | Agent runtime (via `meta_harness.audit_emit`)  | Sidecar `run-events.jsonl`       | Skill activated at run start          |
| `agent.skill.contributed`                  | Agent runtime (via `meta_harness.audit_emit`)  | Sidecar `run-events.jsonl`       | Skill outcome recorded at run end     |
| `agent.skill.outcome_correlated`           | A.4 aggregator (`compute_outcome_correlation`) | Audit chain                      | Outcome-axis correlation computed     |
| `agent.skill.operator_rated`               | CLI (`rate-skill` command)                     | Audit chain + sidecar projection | Operator feedback recorded            |
| `meta_harness.skill.effectiveness_updated` | A.4 store (`write_effectiveness_score`)        | Audit chain                      | Composite score changed               |
| `meta_harness.skill.effectiveness_error`   | G1 error paths (CF #2)                         | Audit chain                      | Any effectiveness computation failure |

**Why it's canonical:** Future agents that emit skill-lifecycle events MUST use these constants — not invent their own `agent.skill.activated` or `skill.run.completed`. The vocabulary is closed; extending it requires an ADR amendment. Audit-chain consumers (GEPA v0.2.5, D.6 Compliance Agent) walk these specific action strings. A divergent action name silently breaks downstream consumers.

**Future agents:** import directly from `shared.skill_telemetry`:

```python
from shared.skill_telemetry import (
    ACTION_AGENT_SKILL_LOADED,
    ACTION_AGENT_SKILL_CONTRIBUTED,
)
```

For emission, use the `meta_harness.audit_emit` wrappers (`emit_skill_loaded`, `emit_skill_contributed`) which handle sidecar path resolution and error emission. Do not call `audit_log.append` directly for lifecycle events — the wrappers enforce the G1-Q8-C split (raw telemetry → sidecar; state transitions → audit chain).

#### Pattern 3: Leaf-module discipline (Q6) is a canonical constraint for telemetry-consumer modules

**What it is:** Telemetry-consumer modules that read sidecar data and produce effectiveness scores MUST NOT be imported by lifecycle modules. Specifically:

- **Allowed imports (leaf modules):** `meta_harness.schemas`, `charter.audit`, stdlib, pydantic, `shared.skill_telemetry`, and peer telemetry-consumer modules within the G1 family (e.g., `skill_outcome` may import from `skill_adoption`).
- **Forbidden imports (upward):** `skill_lifecycle`, `skill_writer`, `skill_eval_gate`, `skill_approval`, `skill_format`, `skill_candidate_store`, `skill_registry`, `skill_triggers`, `skill_discovery`, `audit_emit`.

**Why it's canonical:** The lifecycle modules import from the telemetry modules at runtime (e.g., `skill_lifecycle` calls `compute_effectiveness_score` during deployment decisions). If a telemetry module imports back upward, it creates a circular dependency at Python import time. This isn't theoretical — the v0.2 codebase hit this during A.4 v0.2 integration and resolved it with the leaf-module rule. Breaking this rule produces `ImportError` at agent startup.

**Future agents:** when adding a new telemetry module that reads effectiveness data, check the import graph first. The test is: "can this module be imported without any lifecycle module on `sys.modules`?" If no → it's a leaf module. If yes → it's a lifecycle module and must not be imported by leaf modules.

#### Pattern 4: CF #2 fix-pattern (audit-emit on error, not silent-swallow) is canonical

**What it is:** Every error path in a telemetry computation emits `meta_harness.skill.effectiveness_error` to the audit chain — never a bare `_LOG.warning`. The audit payload carries `error_type` (a machine-readable slug like `"unknown_outcome_value"` or `"outcome_correlated_audit_emission_failure"`), `skill_id`, `agent_id`, `tenant_id`, `stack_trace`, and an optional `exception_message`.

The pattern has two tiers:

1. **Fatal errors** (e.g., sidecar read failure during outcome computation): emit `effectiveness_error`, then **re-raise**. The caller (CLI or agent driver) handles the raised exception. The audit chain records what failed and why.
2. **Recoverable errors** (e.g., audit-chain append fails during success-path emission): emit `effectiveness_error` if possible, log a warning if the error emission itself fails, then **continue** returning the computed result. Don't lose a valid computation because the audit chain is unavailable.

**Why it's canonical:** A.4 v0.2's verification record (PR #194) identified silent error swallowing as a systemic risk — a telemetry failure that logs only a warning is invisible to operators walking the audit chain. The CF #2 pattern makes every failure auditable. G1 proved the pattern across 10 modules (Tasks 5–12); every module enforces it.

**Future agents:** any code path that reads G1 telemetry or produces effectiveness data must follow the same two-tier pattern. The `_emit_effectiveness_error` helper in each G1 module is the reference implementation. Do not `try: ... except: pass` or `_LOG.warning(...)` without a corresponding audit-chain emission.

#### Pattern 5: Audit-chain + sidecar projection pattern (Q8 + CF #6) is canonical for decision-level events

**What it is:** Decision-level events (state transitions: correlation computed, operator rated, score updated, error occurred) go to the **audit chain** with full hash-chain linkage. Raw telemetry events (per-run loaded/contributed records) go to **sidecar JSONL** (`run-events.jsonl` and `operator-ratings.jsonl`) as append-only performance projections. The audit chain is the source of truth; the sidecar is a cross-run cache that avoids re-scanning the full audit history on every computation.

This split follows the A.4 v0.2 verification record CF #6 pattern: "decision in chain, detail in cached JSON."

| Event type                                                                             | Destination                                             | Rationale                                                                    |
| -------------------------------------------------------------------------------------- | ------------------------------------------------------- | ---------------------------------------------------------------------------- |
| `loaded`, `contributed`                                                                | Sidecar only                                            | High-frequency per-run records; auditing every one would flood the chain     |
| `outcome_correlated`, `operator_rated`, `effectiveness_updated`, `effectiveness_error` | Audit chain (+ sidecar projection for `operator_rated`) | State transitions; downstream consumers (GEPA, D.6) walk the chain for these |

**Why it's canonical:** Mixing raw telemetry into the audit chain would produce unbounded chain growth (one `loaded` + one `contributed` per skill per run). Mixing decision events into sidecar-only would lose hash-chain linkage and make the audit trail non-verifiable. The split is load-bearing for both performance and compliance.

**Future agents:** when designing a new telemetry event, classify it first: is this a per-run record (→ sidecar) or a state transition (→ audit chain)? If the latter, does it carry enough context for a downstream consumer to act on it without reading the sidecar? The audit-chain entry should be self-contained — skill_id, agent_id, tenant_id, and the decision payload.

### What this validates

- ADR-007's pattern-hoisting discipline extends beyond code to **architectural patterns**. G1 established five patterns that any effectiveness-telemetry producer or consumer must follow. Codifying them here prevents future agents from re-litigating the same design questions.
- The "amend on the third consumer" rule (v1.1, v1.2) now has a corollary for patterns: **codify when the pattern is proven, not when the third consumer arrives.** G1 proved all five patterns across 12 tasks and 10 modules; waiting for three agents to trip over the same gap would be wasteful.
- The relationship between ADR-007 (reference agent template) and ADR-011 (G1 architecture) is now explicit: ADR-011 defines the scoring mechanism; ADR-007 v1.5 declares it canonical for all future agents.

### Cross-references

- [ADR-011 — G1 effectiveness scoring](../../adr/011-g1-effectiveness-scoring.md) — full architecture decision for the scoring mechanism
- [G1 plan doc](../../superpowers/plans/2026-05-24-g1-effectiveness-scoring.md) — 16-task implementation plan with Q&A resolutions
- [G1 agent migration runbook](../../_meta/g1-agent-migration-runbook.md) — 2-line opt-in for Wave 1+ agents
- [A.4 v0.2 verification record](../../_meta/a4-v0.2-verification-2026-05-22.md) — CF #2, CF #6, CF #9 origin
- Implementation: `packages/agents/meta-harness/src/meta_harness/skill_effectiveness.py` (composite score), `skill_outcome.py` (outcome axis), `skill_adoption.py` (adoption axis), `skill_feedback.py` (feedback axis), `effectiveness_store.py` (persistence), `effectiveness_compat.py` (backwards-compat), `audit_emit.py` (agent-side emitters), `cli.py` (score-effectiveness + rate-skill commands)
- Audit-action vocabulary: `packages/shared/src/shared/skill_telemetry.py`

### What this does NOT change

- **Existing ten reference-template patterns.** The table in the main body is unchanged. Effectiveness scoring is an additional layer that agents opt into; it doesn't replace any existing pattern.
- **v0.1 agents.** Agents built before G1 (Wave 0) that don't emit lifecycle events are handled by the backwards-compat layer (`effectiveness_compat.apply_backwards_compat_reason`): they get `confidence=0.0` with `reason="agent_not_emitting_events"`. They don't need code changes.
- **Charter substrate.** No changes to `charter.audit`, `charter.nlah_loader`, or any other charter module. G1 is pure meta-harness — it consumes the audit chain, it doesn't modify it.
- **Per-agent NLAH shim.** The v1.4 progressive-disclosure loader is unchanged. Skills are loaded the same way; effectiveness scoring is a post-deployment layer on top.
- **The `_enforce_always_on` hoist.** Still deferred to v1.6. v1.5 is exclusively the G1 effectiveness-scoring canonical patterns.

## v1.6 amendment (2026-05-31) — DSPy programs as the canonical prompt shape

### Trigger

A.4 Meta-Harness **v0.2.5** introduces DSPy + GEPA prompt optimization (per the [DSPy+GEPA strategic doc §4.4](../dspy-gepa-prompt-optimization-2026-05-22.md) and [v0.2.5 brainstorm Q3](../../superpowers/brainstorms/2026-05-30-v0-2-5-skill-optimization-brainstorm.md)). The compilation seam landed as `charter.dspy_compiler` (v0.2.5 Task 2), and **Stage 7 SKILL_CREATE** becomes the first agent surface to run as a DSPy module alongside the legacy single-LLM-call composer. This raises an architectural question every future agent will face: _should hand-written NLAH prompts migrate to DSPy programs?_ This amendment answers it canonically.

### What changed — the canonical principle

**Agent prompts that consume LLMs should migrate, over time, to DSPy Signatures + Modules** — declarative programs the GEPA optimizer can compile against an effectiveness metric (per [§v1.5](#v15-amendment-2026-05-25---g1-effectiveness-scoring-canonical-patterns)), rather than static hand-tuned strings. DSPy programs are the **canonical prompt shape** for new LLM-consuming surfaces going forward.

The principle, stated precisely:

- **New LLM-consuming surfaces** (a new agent stage, a new reasoning step) **should be authored as DSPy Signatures/Modules** when GEPA optimization is wanted for them.
- **DSPy programs are compiled through `charter.dspy_compiler`** (provider-agnostic per [ADR-006](ADR-006-openai-compatible-provider.md)), with the effectiveness `metric=` from [§v1.5](#v15-amendment-2026-05-25---g1-effectiveness-scoring-canonical-patterns).
- **Hand-written NLAH prompts remain valid** — they are the bootstrap input to compilation and the graceful-degradation fallback when compilation is unavailable or fails (the Stage-7 legacy path).

### This is a CANONICAL PATTERN reference, NOT a forcing function

Critically — and consistent with v1.1/v1.2's "amend when proven, don't retrofit blindly":

- **v0.1 / Wave 0 agents are NOT required to migrate.** Their hand-written NLAH prompts keep working unchanged. There is no deadline and no breakage.
- **The pattern is opt-in per agent**, adopted when an agent's prompts are worth optimizing (enough deployed skills / effectiveness signal to make GEPA compilation worthwhile).
- **Wave 1+ agents adopt DSPy programs as part of their v0.2 task list** — the migration is a line item in each agent's v0.2 plan, not a separate cross-fleet sweep. F.3 Cloud Posture v0.2 (the first Wave 1 agent, and this ADR's reference agent) is the first to carry it.

### Why this is canonical (not just one cycle's choice)

GEPA can only optimize what is expressed as a compilable program. Codifying "DSPy program as the canonical shape" here means future agent authors don't re-litigate prompt architecture per agent — they inherit the decision the same way they inherit the NLAH loader (v1.2) and the effectiveness interface (v1.5). It closes the loop: v1.4 made skills loadable, v1.5 made them measurable, v1.6 makes the prompts that use them **optimizable**.

### What this does NOT change

- **The ten reference-template patterns** and the v1.1–v1.5 amendments are unchanged. DSPy programs are an additional authoring shape, not a replacement for the NLAH loader, the LLM adapter, or the effectiveness interface.
- **v0.1 agents and the NLAH loader.** The progressive-disclosure loader (v1.4) and per-agent NLAH shim are untouched; DSPy adoption sits on top.
- **Charter substrate beyond the Task-2 seam.** Only `charter.dspy_compiler` was added (its own SAFETY-CRITICAL PR); no other charter module changed.
- **The `_enforce_always_on` hoist.** Still deferred (now to a future v1.7 if/when a third consumer arrives) — it was never claimed by v1.5 or this v1.6.

### Cross-references

- [v0.2.5 brainstorm Q3](../../superpowers/brainstorms/2026-05-30-v0-2-5-skill-optimization-brainstorm.md) — Stage 7 parallel-composer resolution (DSPy alongside legacy)
- [DSPy+GEPA strategic analysis §4.4](../dspy-gepa-prompt-optimization-2026-05-22.md) — "DSPy program as canonical prompt shape" rationale + per-agent migration path
- [Hermes self-evolution adoption doc](../hermes-self-evolution-adoption-2026-05-23.md) — G1 → G2 → v0.2.5 → Wave 1 sequencing
- [v0.2.5 plan doc](../../superpowers/plans/2026-05-31-a-4-meta-harness-v0-2-5.md) — Task 3 (this amendment), Task 5 (Stage-7 parallel composer)
- [`charter.dspy_compiler`](../../../packages/charter/src/charter/dspy_compiler.py) — the compilation seam (v0.2.5 Task 2)
- [§v1.5 amendment](#v15-amendment-2026-05-25---g1-effectiveness-scoring-canonical-patterns) — the effectiveness metric GEPA optimizes against

---

## v1.7 amendment (2026-06-10) — universal compliance checklist (objective rubric)

### Trigger

The [NLAH framework audit (#316)](../nlah-framework-audit-2026-06-09.md) found that the five-layer
standard lived as _documented intent_, not enforced reality: the literal Layer-1 structure was used
by no agent, Layer-3 file artifacts by none, Layer-4 thresholds by 2/17, and `permitted_tools` was an
opt-in convention three agents bypassed. The operator opened the **NLAH Full Backfill cycle** to make
the standard structural. Milestone 1 ([ADR-016](ADR-016-tool-proxy-hard-boundary.md)) made the tool
boundary hard; Milestone 2 reconciles the spec ([§0 of the agent spec](../../agents/agent_specification_with_harness.md#section-0--as-built-convention-vs-original-spec))
and codifies — here — the **objective compliance bar every agent is graded against** in M3/M4.

This amendment supersedes the ad-hoc per-agent grading of the audit with a single, repeatable rubric.
(The long-deferred `_enforce_always_on` hoist mentioned in v1.6 is **not** this amendment; it remains
deferred to a later version if/when a third always-on consumer arrives.)

### The compliance checklist

An agent is **compliant (grade A)** when every applicable item below holds. Each item is objective —
present/absent or pass/fail — so two reviewers reach the same grade. Items tagged _(role-scoped)_ are
N/A for the by-design deviators (see "Deviation profiles").

**Layer 1 — NLAH (`nlah/` directory; the Hybrid standard).** The `nlah/README.md` need not use the
literal ALLCAPS section names, but it MUST cover, under clear headers, the semantic content of all of:

1. Backend infrastructure — the tools/SDKs/binaries the agent depends on.
2. Charter participation — privileges, budget posture, what audit writes occur, inter-agent rules.
3. Role / mission statement.
4. Expertise — the domain knowledge the agent encodes.
5. Decision heuristics — the numbered rules the agent reasons by (H1, H2, …).
6. Stages — the numbered pipeline (Stage 1 → N), matching the code.
7. Failure taxonomy — enumerated failure modes + handling (F1, F2, …).
8. Contracts you require — preconditions/inputs the agent depends on.
9. What you never do — the explicit constraint/guardrail list.
10. **Self-evolution criteria with numeric thresholds** (Layer 4) — e.g. "FP rate > 15% over rolling 500".
11. **Pattern declaration** (Layer 5) — the canonical pattern(s) the agent uses.
12. `nlah/tools.md` is **accurate** — every charter-registered tool listed and labelled gated; no
    false "routes through the charter" claims; pure helpers and unwired/reserved tools marked as such.
13. `nlah/examples/` contains ≥1 worked example.

**Layer 2 — Execution contract & tool calling.**

14. `run()` consumes an `ExecutionContract`; budget is honored (raises `BudgetExhausted` on overrun
    unless the agent is the always-on class, v1.3). _(role-scoped: supervisor constructs contracts;
    meta-harness operates above them.)_
15. The agent runs inside `with Charter(contract, tools=registry) as ctx:`. _(role-scoped)_
16. **Every registered tool is invoked only via `ctx.call_tool(...)`** — never called directly. This is
    enforced structurally by the tool proxy ([ADR-016](ADR-016-tool-proxy-hard-boundary.md)) and the
    CI guard `packages/charter/tests/test_tool_import_guard.py`. Pure helpers (no I/O, no external
    state) are **not** registered and may be called directly.
17. `ctx.assert_complete()` is called before the run returns, so missing required outputs fail the run.
18. `forbidden_tools`, when used, does not overlap `permitted_tools` (validator-enforced).

**Layer 3 — workspace state (as-built).**

19. Outputs are written via `ctx.write_output(...)`; the charter's `audit.jsonl` is the trace of record.
    (The spec's `task.yaml`/`reasoning_trace.md`/`output.yaml` are **not** required — see spec §0;
    raw-trace persistence is a v0.3 item.)

**Layers 4–5 — pattern fidelity & tests.**

20. The declared pattern (item 11) matches the implemented control flow; no agent over-claims.
21. An eval suite exists with documented expectations; the agent is registered under
    `nexus_eval_runners`; cross-agent OCSF wire-shape regressions stay green.

### Deviation profiles (compliant-by-role)

Three agents are A-compliant under a reduced item set, each with a one-paragraph deviation note in its
own NLAH (authored in M3):

- **Supervisor (#0)** — router/dispatcher. **Constructs** delegation contracts rather than receiving
  one; no `ToolRegistry`; no charter-gated tools. Items 14–18 are N/A; items 1–13, 20–21 apply.
- **Meta-Harness (A.4)** — self-evolution orchestrator. Operates on eval scorecards, imports internal
  functions directly (not charter-gated tools), emits scorecards/reports not OCSF findings. Items
  14–19 are role-scoped; it IS the Layer-4 engine.
- **Audit (F.6)** — always-on class (v1.3). Its registered read tools are invoked directly **by
  design** (intentionally outside the budget gate); this is the single standing `BY_DESIGN_EXEMPT`
  entry in the CI guard. Item 16 is satisfied by that documented exemption.

### Grading

Grade per the audit's scale — A (all applicable items) · B (one minor gap) · C (partial) · D (missing
a layer) · F (a hard-boundary violation, i.e. item 16). **M3 brings every agent to A** against this
list; **M4** re-runs it as the compliance certification. The reference agent (cloud-posture) is the
worked example of an A.

### What this does NOT change

- The ten reference-template patterns and the v1.1–v1.6 amendments stand. v1.7 is the _acceptance
  rubric_ over them, not a new capability.
- The hard tool boundary is owned by ADR-016; v1.7 references it as item 16, it does not redefine it.
- The always-on `_enforce_always_on` hoist remains deferred.

### Cross-references

- [NLAH framework audit (#316)](../nlah-framework-audit-2026-06-09.md) — the gaps this rubric closes
- [ADR-016](ADR-016-tool-proxy-hard-boundary.md) — the hard tool boundary (item 16)
- [Agent spec §0](../../agents/agent_specification_with_harness.md#section-0--as-built-convention-vs-original-spec) — as-built reconciliation this rubric assumes
- ADR-017 (v0.2 cycle quality gate) — applies this checklist as a per-cycle gate so the standard cannot drift again
