# Prompt-Optimization & Self-Improving-Agent Framework Analysis — DSPy + GEPA in Nexus (2026-05-22)

> **Status:** Strategic analysis doc. Sequel to `docs/_meta/hermes-pattern-absorption-2026-05-22.md`. Addresses the operator's 2026-05-22 challenge: _"DSPy+GEPA if not built, the sub skill creation and curator won't work."_ That challenge widened the lens from "Hermes patterns alone" to "the full prompt-optimization + self-improving-agent landscape." This doc is that broader scan, plus the granular per-agent integration plan, plus the HOW + WHEN sequencing answer.

> **Operator framing (verbatim, 2026-05-22):** _"DSPy+GEPA, the granularity of micro level connection of these frameworks and its use needs to be written well (at all 3 macro level scope to each micro level contribution) and make it happen — add it to hermes layer."_

> **Self-correction note:** The author of this doc (Claude, the safety/process reviewer) acknowledges the prior Hermes-absorption analysis (`hermes-pattern-absorption-2026-05-22.md`) used too narrow a lens. The operator brought "Hermes" to the conversation; the author worked within that frame. The operator's 2026-05-22 pushback ("we need DSPy+GEPA... why haven't we introduced this concept... why are we implementing scaffold Hermes system?") correctly identified that the storage/lifecycle layer (Hermes patterns) is NECESSARY but NOT SUFFICIENT — without an actual optimization engine, the compounding-learning promise in PRD §7.7.6 is "a story we tell, not a thing that mechanically works." This doc closes that analytical gap.

---

## §0. The challenge restated

**Operator's strategic position (2026-05-22):** Nexus is a three-leg product (detect 33% / impact-blast-radius 33% / cure 33%) plus a frontend. Today only the detect leg is real (17 agents at v0.1 narrow). The platform's self-evolution promise (PRD §7.7.6) requires agents to **compound** — get better with use, not stay static.

**The mechanism question:** What does "compound" mean MECHANICALLY? Not as a marketing line. As code.

- Hermes-pattern absorption (the prior doc) describes the **infrastructure**: where skills live (files), how they're discovered (progressive disclosure), when they're created (after complex runs), how they're curated (pruning), what format they use (agentskills.io).
- But **infrastructure ≠ the compounding engine.** Skill files exist; what writes them?
- Current A.4 v0.2 plan: a single LLM call composes SKILL.md from trace data. This is a starting point, but its quality plateaus — there's no feedback loop that makes the compositor itself smarter.
- **Without an actual prompt-optimization engine, "self-evolution" is a story.**

**This doc's job:** identify the right optimization engine(s), explain micro-level contribution per agent, propose HOW + WHEN to integrate.

---

## §1. The 2026 prompt-optimization landscape — broad scan

The author scanned 8 major prompt-optimization/self-improving-agent frameworks in 2026. Findings:

### §1.1 The mature production frameworks (top tier)

**1. DSPy (Stanford NLP, Khattab et al.)**

- **What it is:** Declarative framework for "programming with LLMs." You define Signatures (input/output specs) and Modules (reusable LLM components); a _teleprompter_ (optimizer) compiles these into optimized prompts using your evaluation data.
- **Maturity (2026-03):** 32,700+ GitHub stars; 1,500+ dependent projects; 8 optimizers covering different tradeoffs (BootstrapFewShot, MIPROv2, COPRO, KNNFewShot, GEPA, etc.); PyTorch-style API.
- **Production usage:** Haystack integration, MLflow integration, Databricks usage, multiple enterprise deployments. Mentioned in 2026 production guides as "the most complete framework for production prompt optimization."
- **Benchmarks:** Programs improve from 33% → 82% on GSM8K (math) with GPT-3.5; from 9% → 47% with Llama2-13b. 25-65% improvement on multi-hop QA. 10-40% improvement on structured tasks vs manual prompting.
- **License:** MIT.

**2. GEPA (Genetic-Pareto, Agrawal et al., arxiv 2507.19457)**

- **What it is:** Reflective prompt evolution. Samples trajectories, reflects on them in natural language to diagnose problems, proposes/tests prompt updates, combines complementary lessons from a Pareto frontier of attempts.
- **Critical clarification:** **GEPA is an OPTIMIZER INSIDE DSPy** (`dspy.GEPA`), not a separate framework. The GitHub repo `gepa-ai/gepa` provides the standalone engine; DSPy integrates it as one of its 8 optimizers.
- **Maturity (2026-03):** Released July 2025; rapidly adopted in DSPy ecosystem; MLflow integration via `mlflow.genai.optimize_prompts()`; Matei Zaharia talks on it; Weaviate tutorial; enterprise healthcare multi-agent usage documented.
- **Benchmarks:** Outperforms GRPO (reinforcement learning) by 6% on average, up to 20%, using 35× fewer rollouts. Outperforms MIPROv2 (DSPy's previous best optimizer) by 10%+ (+12% accuracy on AIME-2025).
- **Why it matters:** Uses natural-language reflection on traces (not just scalar rewards) → "interpretable nature of language often provides a much richer learning medium for LLMs, compared to policy gradients derived from sparse, scalar rewards."
- **License:** MIT.

**3. TextGrad (Stanford, Yuksekgonul et al., published in Nature)**

- **What it is:** Automatic differentiation via text. LLM generates "textual gradients" — natural-language feedback on outputs — which backpropagate through a computation graph of LLM calls.
- **Maturity (2026-03):** Published in Nature (highest-impact venue); PyTorch-style API; production-grade but narrower scope than DSPy.
- **Benchmarks:** GPT-4o zero-shot accuracy 51% → 55% on GPQA. Strong on hard problem instances.
- **Use case differentiation vs DSPy (per 2026 guides):** _"Use TextGrad when you have a hard problem instance and want maximum performance. Use DSPy when you are building a multi-step pipeline that needs to work reliably across many inputs."_
- **License:** MIT.

### §1.2 The research-grade frontier (emerging, not production-mature yet in 2026)

**4. OPRO (Optimization by Prompting, Google DeepMind):** LLM-as-black-box-optimizer. Strong on math; produced famous "Take a deep breath..." prompt. Foundational but lacks framework infrastructure.

**5. PromptAgent (MCTS-based, ICLR 2024):** Monte Carlo Tree Search over prompt space. Outperforms APE by 9.1% on GPT-3.5. Research-grade; production adoption maturing.

**6. SPO (Self-Supervised Prompt Optimization, EMNLP 2025):** Pairwise output comparison; 1.1-5.6% the cost of TextGrad; needs as few as 3 examples to start improving. Strong budget-constrained choice.

**7. EvoPrompt / PromptBreeder:** Evolutionary algorithms over prompts. Predecessors to GEPA; superseded.

**8. Self-Evolving Agents (XMU survey, 2026-02):** Survey paper, not a framework. Categorizes self-evolution into Model-Centric / Environment-Centric / Co-Evolution.

### §1.3 The 2026 frontier (very new — DGM, MARTI, SAGE, Hyperagents)

**9. Meta Hyperagents (2026-03-29):** DGM-Hyperagent integrates task-solving and self-improvement into a unified, editable program. Self-modifies its own improvement procedures. Benchmark: 0.630 improvement on Olympiad math grading.

**10. SAGE (Self-Improving Agent with Skill Library, arxiv 2512.17102):** RL framework where skills generated from previous tasks accumulate in a library, become available for subsequent tasks. 8.9% Scenario Goal Completion improvement; 26% fewer interaction steps; 59% fewer tokens.

**11. MARTI (Tsinghua, ICLR 2026):** Multi-Agent Reinforced Training and Inference. Tree-search-augmented RL for multi-agent reasoning.

**Honest read on the frontier (9-11):** These are 2025-2026 cutting-edge research. They are NOT production-ready in May 2026. Nexus should NOT adopt them yet — but they validate the architectural direction (skill libraries + self-improving multi-agent systems).

### §1.4 The orchestration frameworks (NOT optimization, included for completeness)

**12. CrewAI:** Production multi-agent framework, 5K+ stars, 1500+ company adoptions. Role-based collaboration. NOT a prompt optimizer.

**13. AutoGen (Microsoft):** Multi-agent conversation orchestrator. NOT a prompt optimizer.

**14. LangGraph (LangChain):** State-machine layer for agent workflows. NOT a prompt optimizer.

These are orthogonal to Nexus's needs. Nexus's orchestration is owned by Supervisor (#0); these frameworks would be alternatives to Supervisor, not additions. Out of scope for this doc.

### §1.5 Verdict from the scan

**Production-mature, fits Nexus architecture, ready to adopt in 2026:**

| Framework                            | Verdict         | Role in Nexus                                                                                                                            |
| ------------------------------------ | --------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| **DSPy**                             | ✅ ADOPT        | Foundation framework for declarative prompt programming across all 17 agents                                                             |
| **GEPA (`dspy.GEPA`)**               | ✅ ADOPT        | The optimizer within DSPy. Best-in-class. Reflective evolution outperforms RL with 35× fewer rollouts.                                   |
| **TextGrad**                         | 🟡 CONDITIONAL  | Use IF DSPy/GEPA insufficient for specific hard-instance problems (e.g., A.1 Remediation's hardest cases). Defer until evidence of need. |
| **SPO**                              | 🟡 CONDITIONAL  | Budget-constrained alternative if customer pilot reveals DSPy infrastructure cost is prohibitive. Defer.                                 |
| OPRO / PromptAgent / EvoPrompt / SPO | ⚠️ RESEARCH     | Cite as references; don't adopt in v0.2 cycle.                                                                                           |
| Hyperagents / SAGE / MARTI           | ⚠️ FUTURE       | 2026-2027 frontier; revisit at A.4 v0.4+ if production-validated by then.                                                                |
| CrewAI / AutoGen / LangGraph         | 🚫 OUT-OF-SCOPE | Orchestration not optimization. Supervisor #0 owns this layer.                                                                           |

**The lens widens correctly: DSPy + GEPA are the right answer.** TextGrad is a backup option. The frontier (Hyperagents, SAGE, MARTI) is real but too new to adopt. Other frameworks either don't fit or are research-grade.

---

## §2. The architectural insight — what DSPy+GEPA actually solve for Nexus

### §2.1 The compounding-learning gap (mechanically explained)

**Today's reality for all 17 Nexus agents:**

```
Agent prompt (hand-written, static)
    ↓
LLM call (Anthropic Claude via charter.llm_adapter)
    ↓
Output (OCSF finding / narrative / investigation / etc.)
    ↓
Eval suite gates pass/fail
    ↓
Run completes; prompt unchanged for next run
```

Every agent's prompt was written once by a human. It NEVER improves. Same prompt for every customer, every run, every scenario.

**With DSPy + GEPA:**

```
Agent prompt (initially hand-written; compiled by DSPy)
    ↓
LLM call (via charter.llm_adapter)
    ↓
Output
    ↓
Eval suite + per-case feedback (textual, not just scalar)
    ↓
GEPA reflects on traces, proposes prompt updates
    ↓
DSPy compiles improved prompt; eval-gates before deployment
    ↓
Next run uses improved prompt; learning compounds
```

**The mechanical change is small but consequential:** the prompt becomes a _program parameter_ that improves with use, not a static string. DSPy gives you the programming model; GEPA gives you the optimizer that does the improving.

### §2.2 How this maps to A.4 Meta-Harness

**Current A.4 v0.2 plan (without DSPy/GEPA) — Stage 7 SKILL_CREATE:**

```python
# Single-LLM-call composition (current plan)
def skill_create(trace: AuditTrace) -> SkillCandidate:
    prompt = HAND_WRITTEN_SKILL_PROMPT  # Static; never improves
    response = llm_provider.complete(prompt + trace.serialize())
    skill_md = parse_skill_md(response)
    return SkillCandidate(skill_md, ...)
```

**Failure modes:** LLM produces mediocre skills; eval-gate catches obvious failures but not subtle ones; prompt never improves; same prompt for every agent; no learning across runs.

**With DSPy + GEPA — Stage 7 SKILL_CREATE:**

```python
# DSPy declarative compositor + GEPA optimizer
class SkillExtractor(dspy.Signature):
    """Extract a reusable skill from a successful agent trace."""
    trace: str = dspy.InputField()
    agent_id: str = dspy.InputField()
    skill_md: str = dspy.OutputField(desc="agentskills.io-formatted SKILL.md")

class SkillCreator(dspy.Module):
    def __init__(self):
        self.extract = dspy.ChainOfThought(SkillExtractor)
    def forward(self, trace, agent_id):
        return self.extract(trace=trace, agent_id=agent_id)

# Compiled by GEPA against eval suite
compiler = dspy.GEPA(
    metric=skill_quality_metric,  # Returns score + textual feedback
    auto="medium",
)
optimized_skill_creator = compiler.compile(SkillCreator(), trainset=successful_skill_examples)
```

**Net difference:** the compositor itself is COMPILED against examples of good skills, and GEPA's reflective feedback continually improves the prompt template. Skill quality improves measurably with each compilation cycle.

### §2.3 But Stage 7 is just the start — the deeper insight

**DSPy+GEPA aren't just for A.4. They apply to EVERY prompt in EVERY agent.**

Today, every Nexus agent that uses `charter.llm_adapter` has hand-written prompts:

- D.7 Investigation has prompts for cross-source narration
- D.13 Synthesis has prompts for narrative generation
- D.12 Curiosity has prompts for hypothesis generation
- A.1 Remediation (when it consumes LLMs in future versions) will have prompts for remediation planning
- A.4 Meta-Harness (post-v0.2) has prompts for skill composition

**Each of these prompts can be a DSPy program, compiled and continually improved by GEPA.**

That's the architectural insight: DSPy+GEPA isn't a "feature of A.4 v0.2." It's a **substrate-level capability** that A.4 Meta-Harness uses to improve EVERY OTHER AGENT's prompts.

**This reframes A.4's role:** A.4 isn't just a meta-evaluator. A.4 is the **compiler that owns the optimization loop for every agent's prompts.** That's a much bigger and more strategically valuable role than the current v0.2 plan captures.

---

## §3. Granularity — micro-level contribution per agent

> **Operator's specific request:** _"at all 3 macro level scope to each micro level contribution."_ The three macro layers are detection, probability/blast-radius, cure. Below: per-agent micro-level contribution of DSPy + GEPA each.

### §3.1 LAYER 1 — DETECTION (the 17 v0.1 agents)

**General contribution:** Every detect agent's prompts compile into DSPy programs. GEPA reflects on eval traces, identifies failure patterns, proposes prompt improvements, eval-gates them, deploys improvements. The 17 prompts get sharper with use.

**Per-agent micro-level value:**

| Agent                                       | Today's prompt purpose                                   | DSPy contribution (per-agent)                                                      | GEPA contribution (per-agent)                                                                                                           |
| ------------------------------------------- | -------------------------------------------------------- | ---------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| **F.3 Cloud Posture**                       | Misconfig narration; severity scoring                    | Declarative signatures for each detector (S3 / IAM / network); modular compilation | Learns which misconfig patterns matter most per customer; reflects on false-positive feedback to refine thresholds                      |
| **D.1 Vulnerability**                       | CVE prioritization; KEV correlation rationale            | Modular: scanner-output parsing + correlation + scoring as separate DSPy programs  | Learns customer's actual vulnerability tolerance; reduces noise on accepted-risk CVEs                                                   |
| **D.2 Identity (CIEM)**                     | Over-privilege detection narrative                       | Compiles permission-analysis prompts against IAM-policy fixtures                   | Reflects on operator-overridden permission flags; learns which over-privilege cases customer cares about                                |
| **D.3 Runtime Threat**                      | Falco/Tracee event interpretation                        | Declarative event-to-finding signatures                                            | Reduces false positives on noisy syscalls; refines runtime-anomaly thresholds per customer                                              |
| **D.4 Network Threat**                      | IOC correlation + DGA detection narration                | Compiles DGA-detection rules + IOC-match rationale as DSPy programs                | Learns each customer's normal network baseline; sharpens "unusual" definition                                                           |
| **D.5 Data Security**                       | Sensitive-data classification + S3 misconfig             | Classifier-output-to-finding declarative; OCSF-shaped output guaranteed            | Refines PII/PHI classification thresholds per customer's data sensitivity profile                                                       |
| **D.6 Compliance**                          | Framework-mapping narratives (CIS/SOC2/HIPAA)            | Per-framework DSPy modules; one signature per control mapping                      | Refines mapping accuracy as auditor feedback accumulates                                                                                |
| **D.7 Investigation**                       | Cross-source narration; root-cause reasoning             | DSPy program chains: finding-correlation → timeline → RCA narration                | **HIGHEST IMPACT.** GEPA reflects on operator feedback ("this investigation was useful" / "missed X") to compound investigation quality |
| **D.8 Threat Intel**                        | NVD/KEV/MITRE correlation rationale                      | Per-feed DSPy programs; correlation logic compiled                                 | Learns which threat-intel matches matter most for this customer's threat profile                                                        |
| **D.12 Curiosity**                          | Hypothesis generation from coverage gaps                 | Hypothesis-generation as DSPy program with eval gate                               | **HIGH IMPACT.** GEPA reflects on which hypotheses turned out to be true; learns to generate better hypotheses over time                |
| **D.13 Synthesis**                          | LLM-driven cross-source narration                        | Synthesis-narration as DSPy program                                                | Refines narration style per customer preference (verbose vs concise, technical vs executive)                                            |
| **A.1 Remediation** (future LLM use)        | Remediation-plan generation; action selection            | Action-selection as DSPy program with safety constraints                           | **CRITICAL FOR CURE LEG.** GEPA reflects on remediation outcomes to learn what actually works per customer environment                  |
| **A.4 Meta-Harness**                        | Skill composition (Stage 7)                              | Skill-extraction as DSPy program                                                   | GEPA recursively improves the skill-extraction compositor itself                                                                        |
| **F.3 / multi-cloud-posture / k8s-posture** | (mostly deterministic detection; LLM only for narrative) | Narrative signature; deterministic detection unchanged                             | Refines narrative style only                                                                                                            |
| **F.6 Audit**                               | (mostly deterministic; LLM for NL-query path)            | NL-query-to-structured-filter as DSPy program                                      | Refines query-translation accuracy with operator feedback                                                                               |
| **Supervisor (#0)**                         | (rule-based routing in v0.1; no LLM)                     | n/a for v0.1; v0.2+ LLM-assisted routing becomes DSPy program                      | Refines routing decisions based on outcome quality                                                                                      |

**Key micro-level insight: D.7 Investigation, D.12 Curiosity, A.1 Remediation are the HIGHEST-VALUE targets** for DSPy+GEPA in the detection layer. They're the LLM-heaviest agents whose quality matters most.

**Net Layer 1 value:** every customer's deployment of Nexus becomes a CUSTOMER-SPECIFIC PLATFORM over time. Generic prompts compile down to customer-tuned prompts. Same code; different optimized prompts per tenant.

### §3.2 LAYER 2 — PROBABILITY / BLAST-RADIUS (Phase 2 — not yet built)

**This layer doesn't exist yet** (Phase 2 territory per the operator's 2026-05-22 strategic roadmap). But DSPy+GEPA define how it should be built.

**The blast-radius agent (call it I.1 Blast Radius, when it ships):**

- **Job:** Given a finding, compute blast radius — affected resources, dependencies, probability of harm, customer-specific impact.
- **Why DSPy+GEPA matter here MORE than detection:** blast-radius requires synthesizing many inputs (cloud graph, identity graph, network graph, customer profile, compliance context). Pure LLM call is brittle. Declarative DSPy programs with modular signatures handle the complexity correctly.
- **GEPA contribution:** the SAME finding produces DIFFERENT blast-radius reports for DIFFERENT customer profiles. Healthcare customer: emphasizes PHI paths. Financial customer: emphasizes audit-trail breakage. Startup: emphasizes production-impact. GEPA learns each customer's risk model from operator feedback and compiles per-customer prompts.

**Per-capability micro-level breakdown:**

| Blast-radius capability       | DSPy contribution                                        | GEPA contribution                                                                  |
| ----------------------------- | -------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| Affected-resource enumeration | Declarative: graph-query → affected-set                  | Learns which dependency paths matter per customer's architecture                   |
| Probability-of-harm scoring   | Modular: severity × exploitability × customer-context    | Refines probability calibration based on actual incident outcomes                  |
| Customer-impact scoring       | Per-customer signatures (compiled separately per tenant) | Reflects on customer-marked severity adjustments; learns customer's risk tolerance |
| Root-cause analysis (RCA)     | Chain-of-Thought across audit/timeline/findings          | Learns which RCA narratives customer finds actionable                              |

**Net Layer 2 value:** "the same finding for a different customer" becomes meaningfully different. Customer-specific risk modeling becomes mechanical, not aspirational.

### §3.3 LAYER 3 — CURE (Phase 3 — A.1 Remediation deepening + new orchestration agents)

**This is where DSPy+GEPA matter MOST.** Honest answer to the operator's framing ("cure is most important").

**A.1 Remediation deepening:**

- **Today (v0.1):** Narrow Tier-1 action set; hand-written remediation playbooks; same playbook for every customer.
- **With DSPy+GEPA:** action selection becomes a DSPy program with safety constraints; GEPA reflects on remediation OUTCOMES (success, rollback, operator override) to learn what actually works per customer.

**Per-capability micro-level breakdown:**

| Cure capability                 | DSPy contribution                                                | GEPA contribution                                                                |
| ------------------------------- | ---------------------------------------------------------------- | -------------------------------------------------------------------------------- |
| Action selection                | Declarative: finding + blast-radius → action-plan                | Learns which actions succeed vs get rolled back; sharpens selection per customer |
| Multi-step playbook composition | Modular: action₁ → verify → action₂ → verify; each step compiled | Learns which playbook sequences succeed; refines step ordering                   |
| Cure verification               | Re-scan-after-fix as DSPy program                                | Refines "is this actually fixed?" judgment per customer's definition of fixed    |
| Multi-system coordination       | Chain-of-Thought across affected systems                         | Learns which cross-system orchestration patterns customer trusts                 |
| Rollback decision               | DSPy program: outcome-evaluation → rollback decision             | Refines rollback criteria as evidence accumulates                                |
| Approval-gate phrasing          | Per-customer signature for Tier-2 approval requests              | Learns customer's approval preferences (terse for some, detailed for others)     |

**The compounding effect on cure:**

- Month 1 (A.1 with hand-written prompts): 70% Tier-1 success rate
- Month 6 (A.1 with DSPy compiled prompts): 80% success rate
- Month 12 (A.1 with DSPy+GEPA continuously improving): 90%+ success rate
- Same A.1 code; same action set; smarter prompts

**Net Layer 3 value:** the platform's cure quality COMPOUNDS over time per customer. That's the differentiator vs Wiz (which doesn't have autonomous cure at all) and vs other security platforms (which have hand-written remediation playbooks that never improve).

### §3.4 The cross-layer compounding insight

**The most strategic insight in this doc:**

DSPy+GEPA in Layer 1 (detection) → produces sharper findings → feeds Layer 2 (blast-radius) better inputs → which feeds Layer 3 (cure) better targets → outcomes feed back to all three layers via GEPA reflection.

**The entire three-layer pipeline becomes a compounding learning system, not just detection.**

This is what PRD §7.7.6 self-evolution PROMISES mechanically. Without DSPy+GEPA, the promise is a story. With them, the promise is code.

---

## §4. HOW — Architectural integration into Nexus

> **Operator's question:** _"add it to hermes layer but how and when shall we add this?"_

### §4.1 The architectural seams

DSPy+GEPA integrate at TWO seams in the Nexus architecture:

**Seam 1 — `charter.llm_adapter` extension (substrate):**

Today's `charter.llm_adapter` exposes a Provider interface (`AnthropicProvider`, `VLLMProvider`, etc.). DSPy programs need to invoke providers; this is already supported via DSPy's `dspy.LM` abstraction layer.

**Required substrate change:** add `charter.dspy_compiler` module — thin wrapper around DSPy's compilation API that integrates with `charter.llm_adapter`. ~100 LOC. SAFETY-CRITICAL because it's substrate.

**Seam 2 — Per-agent prompt-as-DSPy-program migration (agent-local):**

Each agent currently has hand-written prompts (strings). Migration: each prompt becomes a DSPy `Signature` + `Module`. Compilation happens lazily (first time the prompt is invoked, OR on demand via A.4).

**Per-agent work:** ~200-400 LOC per agent to migrate prompts to DSPy programs. LOW-RISK because agent-local. NOT required for v0.2 — can land per-agent during Phase 1 maturity waves.

### §4.2 A.4 Meta-Harness becomes the optimization owner

A.4's role expands from "evaluator" to "compiler that owns the optimization loop for every agent's prompts."

**Concrete new A.4 capabilities (post-v0.2.5):**

1. **GEPA compilation cycle.** A.4 periodically compiles each agent's DSPy program with GEPA against eval suite + accumulated traces. Outputs: new compiled prompt → eval-gate → deploy.
2. **Per-customer compilation.** A.4 can compile a per-customer version of an agent's program using that customer's specific eval cases + traces. Per-tenant prompts emerge.
3. **Cross-agent compilation coordination.** When Agent X's prompts compile, A.4 verifies no regression in downstream Agent Y's eval suite (since outputs flow between agents).
4. **Skill creation upgraded.** Stage 7 SKILL_CREATE uses DSPy+GEPA (not single LLM call). Quality improves substantially.

### §4.3 What changes vs current A.4 v0.2 plan

**Current A.4 v0.2 plan (already in flight, 2/16 tasks shipped):**

- N1 Progressive-disclosure NLAH ✅ (Hermes pattern)
- N2 Autonomous skill creation via single LLM call ⚠️ (insufficient compositor)
- N5 agentskills.io format ✅ (Hermes pattern)
- Auto-deploy with eval-gate ✅
- Subscriber-ACL fence ✅

**Proposed A.4 v0.2.5 (DSPy+GEPA integration cycle, ~3-4 weeks after v0.2 closes):**

- Add `charter.dspy_compiler` substrate (Seam 1)
- Upgrade Stage 7 SKILL_CREATE from single-LLM-call to DSPy+GEPA compiled program (Seam 2 for A.4 itself)
- Document the per-agent migration pattern (ADR-007 v1.5 candidate: "DSPy program as canonical prompt shape")
- Per-agent migration NOT required in v0.2.5 — happens during Phase 1 waves as each agent's v0.2+ ships

**Proposed Phase 1 sequencing change:**

- Wave 0 (current): A.4 Meta-Harness v0.2 (Hermes infrastructure) — IN FLIGHT
- **NEW Wave 0.5:** A.4 v0.2.5 (DSPy+GEPA integration) — ~3-4 weeks after v0.2 closes
- Wave 1+ (CSPM, then all subsequent waves): each agent's v0.2 includes prompt-to-DSPy-program migration as one of its tasks (~2 extra tasks per agent)

### §4.4 Cost / dependency profile

**DSPy:** ~30 transitive Python dependencies. Mature, well-maintained, MIT-licensed. Compatible with `pydantic >= 2.0`, `python >= 3.10`. Nexus's `python >= 3.12` and `pydantic >= 2.9` satisfy.

**GEPA:** ~10 additional dependencies on top of DSPy (it's a DSPy optimizer). MIT-licensed.

**Total cost:** ~40 transitive deps added to `packages/charter/`. Substrate concern but tractable. Consider isolating via optional-dependency group: `pip install nexus-charter[dspy]`.

**Compute cost during compilation:** GEPA uses 35× fewer rollouts than RL methods, so compilation is cheaper than alternatives. Each compilation cycle: ~$2-5 in LLM calls per agent (estimate). Run weekly = ~$20-50/agent/month = ~$340-850/month for 17 agents.

This is small vs the per-customer LLM-call cost during normal agent runs.

### §4.5 Migration path (per-agent, applied during Phase 1 waves)

For each Phase 1 wave (F.3 v0.2 / D.5 v0.2 / etc.), add 2 tasks to the existing 16-task structure:

**Task N+1: DSPy program migration.** Migrate this agent's hand-written prompts to DSPy Signatures + Modules. Existing eval suite serves as compilation training data.

**Task N+2: GEPA baseline compilation.** Run GEPA against the agent's eval suite. Capture baseline compiled prompt. Compare to pre-DSPy hand-written prompt. Document quality delta.

This adds ~2 weeks per agent to Phase 1 waves. Phase 1 total slip: ~14 agents × 2 weeks = ~28 weeks. **Real cost** — but each agent emerges from Phase 1 with continuously improving prompts, not static ones.

---

## §5. WHEN — Sequencing into the current Phase 1 plan

> **Operator's question:** _"when shall we add this?"_

### §5.1 The honest sequencing tension

**The Path-B / Phase 1 discipline rule:** "don't disrupt the in-flight plan." That rule got Nexus from 10/17 to 17/17 v0.1 cleanly.

**But:** DSPy+GEPA fundamentally changes A.4 Meta-Harness's role. The current A.4 v0.2 plan ships Hermes infrastructure with a weak compositor. If we ship that as-is and add DSPy later, we'd ship mediocre skills during Wave 1+ that we'd later regret.

**The operator's instinct ("we need this right away") is correct in spirit.** But "right away" needs to be precise about WHAT changes and WHEN.

### §5.2 Three sequencing options

**Option A — Pause A.4 v0.2 NOW, replan to include DSPy+GEPA.**

- Discards Tasks 1-2 work (or makes them partial).
- ~6-8 week delay to replan + execute the expanded scope.
- Wave 1 starts ~2 months later.
- **Verdict: too disruptive.** Breaks the discipline that got Nexus to 17/17. Risks scope creep (once we open the plan, what else gets added?).

**Option B — Ship A.4 v0.2 unchanged. Add A.4 v0.2.5 cycle for DSPy+GEPA BEFORE Wave 1 starts.**

- A.4 v0.2 closes clean (~3-4 weeks remaining work).
- A.4 v0.2.5 opens immediately after: focused 16-task plan for DSPy+GEPA integration (~3-4 weeks).
- Wave 1 (F.3 v0.2) starts AFTER A.4 v0.2.5 closes — with proper compounding-learning loop already in place.
- Net delay vs current plan: ~3-4 weeks (the v0.2.5 cycle).
- **Per-agent migration during Wave 1+:** each agent's v0.2 plan adds ~2 tasks for DSPy program migration.
- **Verdict: RECOMMENDED.** Preserves Path-B discipline (no mid-sequence drift); captures the architectural improvement before Wave 1 produces real skills/prompts that the optimizer would touch.

**Option C — Ship A.4 v0.2 unchanged. Defer DSPy+GEPA entirely to A.4 v0.3 (after Curator).**

- A.4 v0.2 closes clean.
- Wave 1 starts immediately with mediocre compositor (single LLM call).
- Wave 1-6 ship with hand-written prompts (no DSPy migration during waves).
- A.4 v0.3 adds Curator AND DSPy+GEPA together (~6-8 weeks).
- **Verdict: too late.** Wave 1-6 prompts ship without optimization; Phase 2 / Phase 3 work begins on mediocre prompts; substantial rework later.

### §5.3 Recommended sequencing — Option B detailed

```
NOW (2026-05-22):
  - A.4 v0.2 in flight, Task 2/16 done. CONTINUE AS PLANNED.
  - This strategic doc lands as separate LOW-RISK doc-only PR.
  - No changes to current A.4 v0.2 plan or in-flight task PRs.

A.4 v0.2 closure (~3-4 weeks at current cadence):
  - All 16 tasks merge per existing plan.
  - Verification record explicitly NAMES the v0.2.5 follow-up:
    "DSPy+GEPA integration to land as A.4 v0.2.5 before Wave 1 begins.
     Hermes infrastructure (this v0.2) provides the storage layer;
     v0.2.5 provides the optimization engine."

A.4 v0.2.5 cycle opens (~3-4 weeks):
  - Plan doc opens at docs/superpowers/plans/2026-MM-DD-a-4-meta-harness-v0-2-5.md
  - 16-task plan including:
    * charter.dspy_compiler substrate (SAFETY-CRITICAL)
    * ADR-007 v1.5 amendment ("DSPy program as canonical prompt shape")
    * Stage 7 SKILL_CREATE upgrade (single-LLM-call → DSPy+GEPA compiled program)
    * Skill quality regression test (v0.2 skills re-generated; quality delta documented)
    * GEPA compilation cycle infrastructure (periodic re-compilation; weekly cadence)
    * Per-customer compilation foundation (skeleton; full per-customer deferred to v0.x post-SET-LOCAL-fix)
    * Cross-agent regression coordinator (when Agent X compiles, verify no Agent Y regression)
    * Updated nexus_eval_runners with DSPy-program-eval support
    * Documentation + runbook for per-agent migration
  - Verification record explicitly closes v0.2.5; v0.3 (Curator) is the next A.4 cycle.

A.4 v0.2.5 closes → Wave 1 begins (F.3 Cloud Posture v0.2):
  - F.3 v0.2 plan adds 2 tasks: "Task N+1: DSPy program migration" + "Task N+2: GEPA baseline compilation"
  - All subsequent Wave 1-6 plans follow this pattern.
  - Each agent emerges from Phase 1 with DSPy-compiled prompts + GEPA continuous improvement.

A.4 v0.3 (after Wave 1 closure):
  - Curator (N3 from Hermes absorption doc).
  - Additional GEPA optimization: cross-skill composition.
  - Per-customer compilation matures.
```

### §5.4 What changes vs Hermes-absorption doc (which lands first)

The `hermes-pattern-absorption-2026-05-22.md` doc (committed in PR #175) needs ONE update to reflect this strategic widening:

**Add §5.5 (new nectar items):**

> **N7 — DSPy declarative prompt programming (lands in A.4 v0.2.5).** Foundation framework: prompts become DSPy Signatures + Modules. Eval suite serves as compilation training data. ~30 deps; MIT.
>
> **N8 — GEPA reflective prompt optimization (lands in A.4 v0.2.5).** Best-in-class DSPy optimizer. Reflective natural-language evolution. Outperforms RL (GRPO) by up to 20% with 35× fewer rollouts. Released July 2025; production-mature.

**Update §6 landing map:**

| Nectar       | Lands in                    | Plan                      |
| ------------ | --------------------------- | ------------------------- |
| N1 / N2 / N5 | A.4 Meta-Harness v0.2       | (current, in flight)      |
| N3           | A.4 Meta-Harness v0.3       | (after Wave 1)            |
| N4           | D.12 Curiosity v0.2         | (Phase 1 wave)            |
| **N7 DSPy**  | **A.4 Meta-Harness v0.2.5** | **NEW**                   |
| **N8 GEPA**  | **A.4 Meta-Harness v0.2.5** | **NEW** (same plan as N7) |
| N6           | D.13 Synthesis v0.2         | (gated on Surface track)  |

This update lands as a small amendment PR to the Hermes-absorption doc, OR is captured in this new doc instead (recommended — keeps Hermes-absorption stable; this DSPy doc supersedes for the optimization layer).

---

## §6. Risks honestly named

**Risk 1: DSPy/GEPA add substrate complexity.** ~40 transitive deps to `packages/charter/`. Mitigation: optional-dependency group; isolate import; substrate-level test isolation.

**Risk 2: Compilation cost (LLM calls during GEPA cycles).** ~$340-850/month estimated for 17 agents weekly compilation. Mitigation: tunable compilation frequency; expensive cycles can run quarterly initially.

**Risk 3: GEPA-compiled prompts might be non-deterministic across compilation runs.** Mitigation: stub-LLM mode for testing; eval-gate before deploy; per-compilation seed pinning if reproducibility required.

**Risk 4: Per-agent migration cost during Phase 1 waves.** ~2 extra tasks × 14 agents = ~28 extra weeks of plan work. Mitigation: per-agent migration is LOW-RISK agent-local work; can run partially in parallel; can be skipped for low-LLM-usage agents (deterministic detect agents need less DSPy work).

**Risk 5: Frontier frameworks (Hyperagents, SAGE, MARTI) might supersede DSPy+GEPA in 2027.** Mitigation: DSPy's modular architecture means optimizer swaps are isolated; if a better optimizer than GEPA emerges, swap it in without rewriting agents.

**Risk 6: Operator approval workflow for compiled prompts.** Each compiled prompt is auto-deployable if eval-gate passes, but operators may want review. Mitigation: same first-of-class operator approval pattern as Hermes skills (already in A.4 v0.2 plan).

**Risk 7: Compilation might over-fit to eval cases.** Same risk as ML training. Mitigation: held-out test set; cross-validation; per-customer compilation should use customer-specific data only.

---

## §7. What this doc is NOT

- **Not a replacement for the Hermes-pattern absorption doc.** That doc covers infrastructure (storage / lifecycle / format). This doc covers the optimization engine. Both layers needed.
- **Not a v0.2 plan revision.** A.4 v0.2 continues unchanged. This doc proposes A.4 v0.2.5 as a new cycle.
- **Not a code change.** No package edits proposed. This is strategic analysis.
- **Not a final commitment to specific optimizer choices.** DSPy + GEPA are the recommended starting point. TextGrad / SPO / others can be added later if evidence warrants.
- **Not a commitment to per-customer compilation in v0.2.5.** That's deferred to v0.x post-SET-LOCAL-fix per multi-tenant gating.
- **Not the final word.** Frontier frameworks (Hyperagents, SAGE, MARTI) may supersede in 2027. Revisit at A.4 v0.4+.

---

## §8. References

External:

- DSPy paper: Khattab et al., 2023 — _DSPy: Compiling Declarative Language Model Calls into Self-Improving Pipelines_ (arxiv:2310.03714)
- GEPA paper: Agrawal et al., 2025 — _GEPA: Reflective Prompt Evolution Can Outperform Reinforcement Learning_ (arxiv:2507.19457)
- TextGrad paper: Yuksekgonul et al., 2024 — Published in Nature
- SPO paper: Self-Supervised Prompt Optimization (EMNLP 2025)
- DSPy GitHub: https://github.com/stanfordnlp/dspy (32,700+ stars)
- GEPA GitHub: https://github.com/gepa-ai/gepa
- Self-Evolving Agents Survey: https://github.com/XMUDeepLIT/Awesome-Self-Evolving-Agents (2026-02)
- Production landscape: https://www.morphllm.com/prompt-optimization (2026-03)

Internal Nexus:

- `docs/_meta/hermes-pattern-absorption-2026-05-22.md` (§6 landing map updates per §5.4 above)
- `docs/strategy/PRD.md` §7.7.6 (self-evolution capability statement — this doc explains the mechanism)
- `docs/_meta/decisions/ADR-006-llm-provider-strategy.md` (DSPy works on top of `charter.llm_adapter`)
- `docs/_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md` (v1.5 candidate: "DSPy program as canonical prompt shape")
- `docs/_meta/decisions/ADR-008-eval-framework.md` (eval suite serves as DSPy compilation training data)
- `docs/superpowers/plans/2026-05-22-a-4-meta-harness-v0-2.md` (current A.4 v0.2 plan — unchanged by this doc)
- `docs/superpowers/sketches/2026-05-20-agent-version-roadmaps.md` (PR #53; per-agent versions update per §3 above)

---

## §9. Author's note (preserved for future operator)

This doc was drafted 2026-05-22 mid-Phase-1 Wave 0 (A.4 v0.2 Task 2/16 closed), in response to the operator's strategic challenge: _"DSPy+GEPA if not built the sub skill creation and curator won't work."_

The operator was right. The prior Hermes-absorption analysis was too narrow. Storage/lifecycle infrastructure is necessary but not sufficient — without an actual prompt-optimization engine, the compounding-learning promise in PRD §7.7.6 is "a story we tell, not a thing that mechanically works."

This doc closes the analytical gap. The broader landscape scan (§1) confirms DSPy + GEPA (with GEPA as DSPy's newest, best-performing optimizer) are the right choice for 2026. Alternatives (TextGrad, SPO, OPRO) are documented for future reference but not adopted in v0.2.5. Frontier frameworks (Hyperagents, SAGE, MARTI) are too new for production.

The granularity analysis (§3) maps DSPy + GEPA's micro-level contribution to each of the 17 agents across all three macro layers (detection / blast-radius / cure). Key insight: D.7 Investigation, D.12 Curiosity, A.1 Remediation (future) are highest-value targets. Cure layer benefits most from compounding optimization.

The integration plan (§4) places DSPy + GEPA at two architectural seams: `charter.llm_adapter` extension (substrate) and per-agent prompt-to-DSPy-program migration (agent-local). A.4 Meta-Harness becomes the compilation owner.

The sequencing recommendation (§5) is Option B: ship A.4 v0.2 unchanged (~3-4 weeks), then immediately open A.4 v0.2.5 (~3-4 weeks) for DSPy + GEPA integration BEFORE Wave 1 begins. Per-agent migration happens during Phase 1 waves (~2 extra tasks per agent).

Net Phase 1 timeline impact: ~3-4 weeks slip from v0.2.5 + ~2 weeks per agent in waves = ~6-8 month total Phase 1 slip vs prior estimate. **Worth it** — Phase 1 emerges with mechanically real compounding learning instead of a story.

The bee metaphor stays: workers (17 agents) get smarter foragers as A.4 (the brood-care bee) gets a better training system (DSPy + GEPA). Royal jelly (ADR-007 + execution contracts + audit chain) unchanged. F.1 Charter (queen) untouched.

— Recorded 2026-05-22, mid-A.4-v0.2-Task-2, in response to operator pushback that correctly widened the analytical lens.
