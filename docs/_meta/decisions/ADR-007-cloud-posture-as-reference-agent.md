# ADR-007 — Cloud Posture is the reference NLAH

- **Status:** accepted (v1.1 — amended 2026-05-11 with the LLM-adapter hoist; see [§v1.1 amendment](#v11-amendment-2026-05-11---llm-adapter-hoist))
- **Date:** 2026-05-10 (v1.0); 2026-05-11 (v1.1)
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
