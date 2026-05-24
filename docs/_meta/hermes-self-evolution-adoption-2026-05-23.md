# Hermes Self-Evolution Adoption — Strategic Analysis (2026-05-23)

> **Status:** Strategic analysis doc — third in sequence after `hermes-pattern-absorption-2026-05-22.md` (PR #175) and `dspy-gepa-prompt-optimization-2026-05-22.md` (PR #181). Responds to the operator's 2026-05-23 challenges: _"Why are we rebuilding when Hermes already has this?"_ and _"Hermes is incomplete; fix the missing pieces wherever required."_ This doc inventories the upstream Hermes codebase's self-evolution capabilities, evaluates what Nexus can adopt vs. must rebuild, and sequences the adoption work.

> **Hard scope fence:** This doc is REFERENCE MATERIAL. It does NOT modify in-flight plans (A.4 v0.2.5 brainstorm or any other). Each prerequisite gap identified in §4 requires its own ADR-011 cycle: dedicated brainstorm → plan doc (PR #176-shape) → task PRs. This doc only catalogs what exists upstream and what work is needed.

---

## §1. Hermes asset inventory — what actually exists upstream

The operator's 2026-05-23 challenge: _"Hermes has self-evolution and skill creation already. Check whether we can adopt it. Check every single availability."_

### §1.1 Repository structure (verified via live repo spike, 2026-05-23)

**hermes-agent** (`/mnt/user-data/repos/hermes-agent` — upstream, not Nexus):

- **Version:** v0.14.0 (tagged)
- **License:** Apache 2.0
- **Language:** Python 3.11+
- **Core packages:**
  - `hermes/` — core agent runtime (event loop, tool dispatch, skill registry)
  - `hermes/self_evolution/` — skill creation + curator pipeline
  - `hermes/skills/` — skill storage, discovery, progressive disclosure
  - `hermes/eval/` — evaluation framework for skill assessment
  - `hermes/plugins/` — plugin architecture for tool extensions
  - `hermes/server/` — FastAPI web server for agent API
  - `hermes/cli/` — CLI for agent management
- **Tests:** `tests/` directory with pytest suite
- **Docs:** `docs/` with architecture docs, API reference, self-evolution guide
- **Dependencies:** `pyproject.toml` with ~40 dependencies

**hermes-agent-self-evolution** (standalone package, depends on hermes-agent):

- **Version:** Phase 1 of 5 (partial implementation — see §1.2)
- **License:** Apache 2.0
- **Package:** `hermes_agent_self_evolution/`
- **Key modules:**
  - `skill_curator/` — curator logic (Phase 1 — basic dedup only)
  - `skill_generator/` — LLM-driven skill creation (Phase 1 — single-shot only)
  - `skill_evaluator/` — quality assessment of generated skills
  - `skill_merger/` — merge/update existing skills
  - `feedback/` — feedback collection and aggregation

### §1.2 Self-evolution implementation status (5-phase roadmap, Phase 1 only shipped)

**Phase 1 — Basic Skill Creation (SHIPPED, v0.14.0):**

- Single-shot LLM skill generation from traces (similar to A.4 v0.2 Task 7's `skill_writer.py`)
- In-memory skill registry (no persistence)
- Basic dedup (exact name match only; no similarity dedup)
- No eval-gate (skills generated but not tested before deployment)
- No curator pruning
- **Status in hermes-agent-self-evolution repo:** Phase 1 code present but marked "experimental"

**Phase 2 — Skill Improvement (PLANNED, NOT IMPLEMENTED):**

- Iterative refinement of existing skills
- A/B comparison of skill variants
- Quality metrics dashboard
- **Status:** `README.md` describes Phase 2; no code

**Phase 3 — Curator (PLANNED, NOT IMPLEMENTED):**

- Similarity-based dedup (semantic similarity, not just name match)
- Skill pruning (stale/unused skill removal)
- Cross-skill composition
- **Status:** `README.md` describes Phase 3; no code

**Phase 4 — Feedback Loop (PLANNED, NOT IMPLEMENTED):**

- Operator feedback integration
- Automated quality scoring from run outcomes
- Per-skill telemetry
- **Status:** `README.md` describes Phase 4; no code

**Phase 5 — Autonomous Evolution (PLANNED, NOT IMPLEMENTED):**

- Self-directed skill creation without external triggers
- Cross-agent skill porting
- Evolutionary optimization of skill portfolio
- **Status:** `README.md` describes Phase 5; no code

### §1.3 What this inventory means for Nexus

**Directly adoptable code:** NONE. Hermes v0.14.0's Phase 1 self-evolution is at the same maturity level as A.4 v0.2 Task 7 (single-shot LLM skill composition). The code is Apache 2.0 licensed (compatible with Nexus's license), but the codebase structure, dependency chain, and architectural assumptions differ materially from Nexus.

**Adoptable patterns/designs:** Hermes's 5-phase roadmap (Basic → Improvement → Curator → Feedback → Autonomous) maps cleanly to Nexus's Hermes nectar sequence (N1-N6 from `hermes-pattern-absorption-2026-05-22.md`). The phase structure is a DESIGN REFERENCE, not buildable code.

**Adoptable concepts (architecture-level):**

| Hermes concept                      | Nexus equivalent              | Adopt/Fork/Rebuild                           |
| ----------------------------------- | ----------------------------- | -------------------------------------------- |
| `skill_generator` (Phase 1)         | A.4 v0.2 `skill_writer.py`    | Already rebuilt (A.4 v0.2 Task 7)            |
| `skill_curator` (Phase 3 — planned) | A.4 v0.3 N3 Curator           | Fork design; rebuild code (see §3)           |
| `skill_evaluator` (Phase 1)         | A.4 v0.2 `skill_eval_gate.py` | Already rebuilt (A.4 v0.2 Task 8)            |
| `skill_merger` (Phase 1)            | Not in Nexus yet              | Adopt pattern; rebuild for multi-tenant      |
| `feedback` (Phase 4 — planned)      | Not in Nexus yet              | Adopt pattern; rebuild for Nexus audit chain |
| 5-phase roadmap                     | Hermes nectar N1-N6           | Adopt as DESIGN REFERENCE                    |

---

## §2. Architectural fit analysis — can Nexus adopt Hermes code directly?

### §2.1 The multi-tenant gap

**Hermes v0.14.0 architecture:** Single-user desktop agent. One workspace. One user. No tenant isolation. State stored in `~/.hermes/` (user home directory). No multi-tenancy infrastructure. No tenant-RLS. No customer-isolated workspaces.

**Nexus architecture:** Multi-tenant SaaS platform. 17 agents. `workspace_root` per-customer (deferred to post-SET-LOCAL-fix for true isolation). SemanticStore backing. NATS fabric bus. F.6 audit chain. ADR-012 subscriber ACL.

**Verdict:** Hermes code cannot be adopted directly. The single-user assumption runs through every module — file paths, state management, skill registry, evaluation. Rewriting for multi-tenancy would be ~80% of the codebase.

### §2.2 The dependency gap

**Hermes dependency chain:**

```
hermes-agent (core)
├── langchain (LLM abstraction)
├── chromadb (vector store for skill similarity)
├── fastapi (web server — Nexus doesn't use)
├── pydantic v2
├── sqlalchemy (ORM for agent state)
└── ~30 more transitive deps
hermes-agent-self-evolution
├── hermes-agent (parent)
├── openai (LLM provider — Anthropic-only in Nexus)
├── numpy (similarity computation)
└── ~10 more transitive deps
```

**Nexus dependency chain:**

```
charter.llm_adapter (custom, not LangChain)
├── anthropic (SDK)
├── openai (VLLM compatibility layer)
└── pydantic v2
```

**Verdict:** Hermes uses LangChain; Nexus uses `charter.llm_adapter` (ADR-006). Hermes uses ChromaDB for vector similarity; Nexus uses SemanticStore (ADR-009) with pgvector. Different LLM provider abstraction, different vector store, different web framework. Adopting Hermes code would mean importing an incompatible dependency tree.

### §2.3 The evaluation framework gap

**Hermes eval:** In-memory skill evaluator. Skills assessed by running against a small set of test cases. No multi-agent coordination. No cross-agent regression testing. No byte-equal determinism probe. No WI-3 pattern.

**Nexus eval:** `eval-framework` package (ADR-008). `nexus_eval_runners` entry-point system. `MetaHarnessEvalRunner` (A.4). 15-case deterministic eval suite. WI-3 byte-equal probe. Option-B two-run baseline vs. with-candidate comparison. Cross-agent regression guard.

**Verdict:** Hermes eval is insufficient for Nexus's needs. Nexus has already built a more sophisticated eval framework. A.4 v0.2's eval infrastructure is a superset of Hermes Phase 1 eval.

### §2.4 The trust-boundary gap

**Hermes:** No subscriber ACL. No `_FORBIDDEN_SUBSCRIPTIONS`. No claims bus. No auto-acting agent safety rails (no `--force` prohibition, no mandatory eval-gate, no first-of-class operator approval).

**Nexus:** ADR-012 subscriber ACL with three forbidden subscribers. Q-ARCH-1 trajectory closed at v0.2. Three-rail safety model (bus isolation + mandatory eval-gate + operator gate). Trust boundary explicitly designed for auto-acting agents.

**Verdict:** Hermes has no trust-boundary design. A.4 v0.2's safety architecture is a superset. Hermes code cannot be dropped into Nexus without breaking all safety invariants.

### §2.5 Overall architectural verdict

**Hermes code: REBUILD.** The single-user assumption, dependency incompatibility, evaluation insufficiency, and trust-boundary gap make direct code adoption infeasible. Hermes provides DESIGN INSPIRATION, not buildable modules.

**BUT:** The operator's instinct is correct — "why are we rebuilding?" is the right question. The answer: because Hermes v0.14.0's self-evolution is at Phase 1 of 5, and Nexus has already built Phase 1-equivalent capability with production-grade infrastructure (multi-agent eval, audit chain, tenant isolation foundation, trust-boundary enforcement). Hermes's Phases 2-5 are design documents, not code. Nexus can adopt those designs without adopting the Phase 1 code.

---

## §3. Per-Hermes-module Adopt / Fork / Rebuild matrix

This is the operational reference table. Each Hermes module evaluated for direct adoption vs. design inspiration vs. full rebuild.

| Hermes module                     | Phase            | What it does                              | Verdict                         | Rationale                                                                                                                                                                                                                                                                                                                      |
| --------------------------------- | ---------------- | ----------------------------------------- | ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `skill_generator`                 | 1 — SHIPPED      | Single-shot LLM skill creation            | **REBUILD** (already done)      | A.4 v0.2 `skill_writer.py` (Task 7) is the rebuild. Same function; Nexus-native (charter.llm_adapter not LangChain; agentskills.io format; provenance from audit chain).                                                                                                                                                       |
| `skill_evaluator`                 | 1 — SHIPPED      | In-memory skill quality check             | **REBUILD** (already done)      | A.4 v0.2 `skill_eval_gate.py` (Task 8) is the rebuild. Superset: Option-B two-run comparison, byte-equal probe, regression threshold, per-case failure detail.                                                                                                                                                                 |
| `skill_registry`                  | 1 — SHIPPED      | In-memory skill registry (no persistence) | **REBUILD** (already done)      | A.4 v0.2 `skill_registry.py` (Task 9) with file persistence at `<workspace>/.nexus/skill-class-registry.json`. First-of-class operator gate. Nexus superset.                                                                                                                                                                   |
| `skill_merger`                    | 1 — SHIPPED      | Merge/update existing skills              | **ADOPT PATTERN; REBUILD CODE** | Hermes merge logic (exact name match → replace) is simpler than what Nexus needs (semantic dedup + versioning). Design: adopt the merge/update concept. Code: rebuild for Nexus multi-tenant skill registry + agent-specific skill paths.                                                                                      |
| `feedback`                        | 4 — PLANNED ONLY | Feedback collection and aggregation       | **ADOPT PATTERN; REBUILD CODE** | No Hermes code exists (Phase 4 is planning only). Adopt the concept: operator feedback → quality scoring → curator input. Rebuild using F.6 audit chain events + A.4 v0.3 N3 Curator feedback loop.                                                                                                                            |
| `skill_curator`                   | 3 — PLANNED ONLY | Similarity dedup + pruning + composition  | **FORK DESIGN; REBUILD CODE**   | Hermes Phase 3 design doc describes _what_ a curator does. Adopt that semantic model (dedup by similarity, prune stale, compose cross-skill). Rebuild all code on Nexus substrate: SemanticStore for similarity search (not ChromaDB), F.6 audit chain for usage telemetry (not SQLAlchemy), multi-tenant workspace isolation. |
| `skill_improver`                  | 2 — PLANNED ONLY | Iterative skill refinement; A/B variants  | **REBUILD WITH DSPY+GEPA**      | Hermes Phase 2 describes iterative refinement conceptually. A.4 v0.2.5's DSPy+GEPA integration (per `dspy-gepa-prompt-optimization-2026-05-22.md` §4-5) is the correct implementation — GEPA's reflective evolution is more sophisticated than Hermes's planned iterative refinement.                                          |
| `evolution_engine`                | 5 — PLANNED ONLY | Autonomous self-directed evolution        | **FUTURE REFERENCE**            | Hermes Phase 5 is a vision document, not a design. Nexus's equivalent is A.4 v0.4+ frontier integration (per strategic doc §6 Risk 5 — Hyperagents/SAGE/MARTI revisit). No action in v0.2.5 or v0.3.                                                                                                                           |
| Agent runtime (`hermes/`)         | Core — SHIPPED   | Event loop, tool dispatch, skill registry | **OUT OF SCOPE**                | Nexus has its own agent runtime (charter + per-agent drivers). Supervisor (#0) is the orchestrator. Hermes runtime is a single-user desktop loop; fundamentally incompatible with Nexus multi-agent fabric.                                                                                                                    |
| Plugin system (`hermes/plugins/`) | Core — SHIPPED   | Tool extension architecture               | **OUT OF SCOPE**                | Nexus agents define tools per-agent in NLAH. Supervisor routes via NATS. No plugin architecture needed.                                                                                                                                                                                                                        |
| FastAPI server (`hermes/server/`) | Core — SHIPPED   | Web API for agent interaction             | **OUT OF SCOPE**                | Nexus's API layer is the frontend (Phase 2 Surface track). Not part of A.4's domain.                                                                                                                                                                                                                                           |
| CLI (`hermes/cli/`)               | Core — SHIPPED   | Agent management CLI                      | **OUT OF SCOPE**                | A.4 v0.2 has its own CLI (Task 15: `approve-skill` / `reject-skill` / `list-skills`). Hermes CLI manages the single-user agent; Nexus CLI manages the meta-harness pipeline.                                                                                                                                                   |

---

## §4. Gap analysis — what Hermes has that Nexus is missing

The operator's second challenge: _"Hermes is incomplete; fix the missing pieces wherever required."_

This section catalogs every self-evolution capability that Hermes (even in planning) describes but Nexus hasn't built yet. Each gap classified as PREREQUISITE (must fix before v0.2.5 skill composition can produce quality output) or DEFERRABLE (valuable but not blocking v0.2.5).

### §4.1 PREREQUISITE gaps (block v0.2.5; fix first)

**G1 — Effectiveness scoring (no Hermes code; no Nexus code).**

- **What it is:** A metric that scores how effective a deployed skill is. Without this, GEPA cannot optimize — you can't optimize what you can't measure.
- **Hermes status:** Phase 4 planning mentions "automated quality scoring from run outcomes" but no design or code.
- **Nexus gap:** A.4 v0.2's eval-gate checks pre-deployment quality (does the skill cause regressions?). But there's no POST-deployment effectiveness score — did the skill actually improve the agent's performance over time?
- **Fix shape (Nexus-native):**
  - Skill adoption tracking: which agents loaded the skill, how often was it used
  - Run outcome correlation: did runs using this skill have higher pass rates?
  - Operator feedback aggregation: operator marks skill as "useful" / "neutral" / "harmful"
  - Composite effectiveness score (0-1) per deployed skill
  - Stored in skill sidecar (`candidate_meta.json` extended → `skill_telemetry.json`? Or SemanticStore entity per skill?)
- **Why PREREQUISITE:** GEPA needs a metric to optimize against. The strategic doc's "GEPA optimizer parameters" question (v0.2.5 brainstorm Q5) requires an effectiveness metric as input. No metric = GEPA can't compile.
- **Estimated work:** 1 dedicated plan cycle (8-10 tasks). New module `skill_effectiveness.py` in A.4 v0.2.5 or separate plan.
- **Sequencing:** Must land before GEPA compilation can produce meaningful results.

**G2 — Skill selection (no Hermes code; no Nexus code).**

- **What it is:** Which skill does an agent load for a given run? Hermes Phase 3's curator design mentions "which skills to include" but doesn't specify selection logic.
- **Nexus gap:** A.4 v0.2's progressive-disclosure `charter.nlah_loader` v1.4 loads ALL skills for an agent. But as the skill library grows (Wave 1+ agents accumulate skills), loading every skill becomes unsustainable (context window pressure, irrelevant skills adding noise).
- **Fix shape (Nexus-native):**
  - Skill-to-run relevance scoring (which skills are relevant to this customer's findings?)
  - Context-budget management (how many skills can fit in the LLM context window?)
  - Per-agent skill manifest with load priority
  - Selection policy: "load top-N most effective + relevant skills" not "load all"
- **Why PREREQUISITE:** Without skill selection, Wave 1 agents accumulate skills and context windows overflow. GEPA-compiled prompts are larger than hand-written prompts (DSPy templates add token overhead). Selection prevents context-window exhaustion.
- **Estimated work:** 1 dedicated plan cycle (8-10 tasks). Extends `charter.nlah_loader` v1.4 → v1.5.
- **Sequencing:** Must land before Wave 1 (F.3 v0.2) ships with GEPA-compiled prompts. Can land in parallel with v0.2.5 DSPy work.

### §4.2 DEFERRABLE gaps (post-v0.2.5; Phase 1 waves or later)

**G3 — Skill merging (Hermes Phase 1 code exists; inadequate for Nexus).**

- Nexus needs semantic dedup, not name-match dedup. Deferred to A.4 v0.3 N3 Curator.

**G4 — Skill pruning (Hermes Phase 3 planned; no code).**

- Remove stale/unused skills. Deferred to A.4 v0.3 N3 Curator.

**G5 — Cross-skill composition (Hermes Phase 3 planned; no code).**

- Combine two related skills into one. Deferred to A.4 v0.3 N3 Curator.

**G6 — Cross-agent skill porting (Hermes Phase 5 planned; no code).**

- "This skill works for D.7 Investigation; can D.13 Synthesis use a variant?" Deferred to A.4 v0.4+.

**G7 — Autonomous evolution triggers (Hermes Phase 5 planned; no code).**

- Self-directed skill creation without external trigger (A.4 v0.2's Q3 hash-novelty gate). Deferred to A.4 v0.4+.

**G8 — Per-skill telemetry dashboard (Hermes Phase 4 planned; no code).**

- UI for operators to see skill effectiveness, usage, quality trends. Deferred to Phase 2 Surface track.

**G9 — Multi-modal skill support (not in Hermes roadmap).**

- Skills that include images, diagrams, code snippets beyond markdown. Future consideration.

---

## §5. Sequencing — what to build, in what order

### §5.1 The dependency chain

```
G1 (effectiveness scoring)
    ↓
G2 (skill selection) ← can run in parallel with v0.2.5 DSPy work
    ↓
A.4 v0.2.5 (DSPy + GEPA Stage 7 upgrade)
    ↓          ↓
G3-G5       Wave 1 agents ship with DSPy-compiled prompts + GEPA optimization
(A.4 v0.3)
```

**Why G1 must be first:** GEPA needs a metric to optimize against. Without effectiveness scoring, GEPA compilation produces prompts that optimize for the wrong thing (or nothing). The strategic doc says "metric=skill_quality_metric" (§2.2) — G1 defines that metric mechanically.

**Why G2 can be parallel:** Skill selection is a `charter.nlah_loader` concern. It doesn't depend on GEPA compilation succeeding — it depends on the skill library growing large enough that selection matters. Wave 1 agents will be the first to accumulate skills at scale; G2 must land before Wave 1 ships, but can develop in parallel with v0.2.5 DSPy work.

### §5.2 Recommended sequence (updated from strategic doc §5.3)

```
NOW (2026-05-23):
  - A.4 v0.2 CLOSED (PR #194 merged). Wave 0 complete.
  - A.4 v0.2.5 brainstorm OPEN (resolutions 1-3 locked; Q4-Q8 pending).
  - THIS DOC lands as LOW-RISK doc-only PR.

NEXT (immediate — before v0.2.5 brainstorm resumes at Q7):
  - G1 brainstorm opens (operator + Claude). ~2-3 clarifying questions.
  - G1 plan doc drafted. PR #176-shape. 8-10 tasks. LOW-RISK.
  - G1 task PRs execute per ADR-011 cadence. ~2-3 weeks.
  - G1 closes (verification record). Effectiveness scoring is real.

THEN (can partially overlap with G1 closure):
  - G2 brainstorm opens. ~2-3 clarifying questions.
  - G2 plan doc drafted. Extends charter.nlah_loader v1.4 → v1.5.
  - G2 task PRs execute. ~2-3 weeks.
  - G2 closes. Skill selection is real.

THEN (resume paused brainstorm):
  - v0.2.5 brainstorm resumes at Q7 + Q8 (carry-forward triage).
  - v0.2.5 brainstorm completes.
  - v0.2.5 plan doc opens (PR #176-shape; ~10-13 tasks).
  - v0.2.5 task PRs execute per ADR-011 cadence. ~3-4 weeks.
  - v0.2.5 closes (verification record).

THEN:
  - Wave 1 (F.3 Cloud Posture v0.2) opens.
```

**Total pre-Wave-1 work:** G1 (~2-3 weeks) + G2 (~2-3 weeks, partially parallel) + v0.2.5 (~3-4 weeks) = ~8-10 weeks before Wave 1 opens. This is longer than the strategic doc's ~3-4 week v0.2.5 estimate, because the operator's "fix the missing pieces" directive revealed G1+G2 as prerequisites the strategic doc didn't identify.

### §5.3 What v0.2.5's plan doc inherits from G1+G2

When v0.2.5's plan doc opens (after G1+G2 close):

- **G1 delivers:** `skill_effectiveness.py` module + composite effectiveness score (0-1) per deployed skill. GEPA's `metric=` parameter uses this score.
- **G2 delivers:** `charter.nlah_loader` v1.5 with skill relevance scoring + context-budget management. v0.2.5's Stage 7 DSPy program can assume selected skills fit in context window.
- **v0.2.5 adds:** DSPy+GEPA compiler, Stage 7 upgrade, configurable LLM provider, ADR-007 v1.5, skill quality regression test.

---

## §6. Risks honestly named

**Risk 1 — G1 effectiveness scoring is novel in security-agent context.** No prior art for "how effective is a deployed security skill?" in production. Mitigation: start simple (adoption rate + operator feedback); iterate. Don't over-design the metric.

**Risk 2 — G2 skill selection interacts with GEPA compilation.** GEPA-compiled prompts are larger than hand-written prompts. If selection+compilation together exceed context window, we need a budget model that accounts for compilation overhead. Mitigation: G2's context-budget management must query DSPy's estimated token count for compiled programs.

**Risk 3 — Sequencing pushes Wave 1 further out.** Path-B discipline says "ship all agents to v0.1 first, then mature." We did that (17/17 v0.1). Now the maturity work is scoped honestly — G1+G2+v0.2.5 before Wave 1. ~8-10 weeks of pre-Wave-1 maturity work is the honest cost of doing the compounding-learning loop right.

**Risk 4 — Hermes upstream may advance while Nexus builds independently.** Hermes v0.15.0 might ship Phase 2 before Nexus finishes G1+G2. Mitigation: this doc is a snapshot (2026-05-23). If upstream ships significant new capability, reassess. But given Hermes's single-user architecture, direct adoption remains unlikely.

**Risk 5 — G1 metric may be gameable.** If effectiveness = adoption rate, agents might load skills unnecessarily to inflate scores. Mitigation: composite metric (adoption + run-outcome + operator feedback) reduces single-dimension gaming. Operator feedback is the hardest to game.

**Risk 6 — Operator feedback collection (G1 sub-task) requires UX that doesn't exist yet.** Mitigation: start with file-based feedback (operator writes to `.nexus/skill-feedback/`); UI comes later (Phase 2 Surface track).

**Risk 7 — Context-window pressure from DSPy+GEPA prompts.** DSPy templates are larger than hand-written prompts. Mitigation: G2 must budget context with DSPy token estimates; selection policy must be conservative initially.

---

## §7. What this doc IS / IS NOT

### §7.1 This doc IS:

- **A strategic reference.** Catalogs every Hermes self-evolution module with Adopt/Fork/Rebuild verdict.
- **A gap analysis.** Identifies what Nexus is missing vs. Hermes's full 5-phase vision.
- **A sequencing recommendation.** G1 → G2 → v0.2.5 → Wave 1, with dependency rationale.
- **An operational deliverable.** The operator asked "check every single availability" — §3's per-module matrix is that deliverable.

### §7.2 This doc IS NOT:

- **A build plan.** G1, G2, and v0.2.5 each require their own plan doc (PR #176-shape).
- **A code change.** No imports, no dependencies, no tests.
- **A revision to prior strategic docs.** `hermes-pattern-absorption-2026-05-22.md` and `dspy-gepa-prompt-optimization-2026-05-22.md` are unchanged.
- **A revision to A.4 v0.2.5 brainstorm.** The brainstorm (paused at Q7) continues after G1+G2 close.
- **A commitment to Hermes compatibility.** Nexus is NOT aiming for Hermes API compatibility. Design inspiration only.
- **The final word.** Hermes upstream may ship new phases; reassess at A.4 v0.3 planning.

### §7.3 Usage map — when to consult this doc

| Moment                                              | What to check                                              |
| --------------------------------------------------- | ---------------------------------------------------------- |
| G1 plan doc drafting                                | §4.1 G1 fix shape; §6 Risk 1, 5, 6                         |
| G2 plan doc drafting                                | §4.1 G2 fix shape; §6 Risk 2, 7                            |
| v0.2.5 plan doc drafting                            | §5.2 sequencing; §4.1 for what G1+G2 deliver before v0.2.5 |
| A.4 v0.3 N3 Curator plan                            | §3 `skill_curator` row; §4.2 G3-G5                         |
| `skill_merger` implementation                       | §3 `skill_merger` row; §4.2 G3                             |
| `skill_pruning` implementation                      | §3 `skill_curator` row; §4.2 G4                            |
| Per-agent DSPy migration (Wave 1+)                  | §2.5 architectural verdict (why rebuild, not adopt)        |
| Hermes upstream v0.15.0 release                     | §1 snapshot date; §6 Risk 4 reassessment trigger           |
| Cross-agent skill porting (v0.4+)                   | §3 `evolution_engine` row; §4.2 G6                         |
| `charter.nlah_loader` v1.5 planning                 | §4.1 G2 fix shape; §6 Risk 2, 7                            |
| Frontier framework reassessment (v0.4+)             | §2.5 verdict; strategic doc §1.5                           |
| Operator onboarding — "why didn't we adopt Hermes?" | §2 (architectural fit); §3 (per-module matrix)             |

---

## §8. References

**External (Hermes upstream):**

- `hermes-agent` v0.14.0 — `/mnt/user-data/repos/hermes-agent` (spiked 2026-05-23)
- `hermes-agent-self-evolution` Phase 1 — `/mnt/user-data/repos/hermes-agent-self-evolution` (spiked 2026-05-23)
- Hermes 5-phase roadmap — `hermes-agent-self-evolution/README.md` §Self-Evolution Roadmap

**Internal Nexus:**

- `docs/_meta/hermes-pattern-absorption-2026-05-22.md` (PR #175) — Hermes nectar N1-N6 + landing map
- `docs/_meta/dspy-gepa-prompt-optimization-2026-05-22.md` (PR #181) — DSPy+GEPA strategic analysis; v0.2.5 sequencing
- `docs/_meta/a-4-meta-harness-v0-2-verification-2026-05-23.md` (PR #194) — Wave 0 closure; 9 carry-forwards to v0.2.5+
- `docs/_meta/decisions/ADR-006-llm-provider-strategy.md` — `charter.llm_adapter` (not LangChain)
- `docs/_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md` — NLAH reference architecture
- `docs/_meta/decisions/ADR-008-eval-framework.md` — eval framework
- `docs/_meta/decisions/ADR-009-memory-architecture.md` — SemanticStore (not ChromaDB)
- `docs/_meta/decisions/ADR-012-claims-subject-namespace.md` — subscriber ACL; `_FORBIDDEN_SUBSCRIPTIONS`

---

## §9. Author's note (preserved for future operator)

This doc was drafted 2026-05-23, one day after Wave 0 closed (A.4 v0.2 PR #194 merged). The operator's two 2026-05-23 challenges — "why are we rebuilding when Hermes already has this?" and "Hermes is incomplete; fix the missing pieces wherever required" — were the right questions at the right time.

The Hermes inventory (§1) confirms the operator's instinct had merit: Hermes does have self-evolution capability (Phase 1 of 5 shipped). But the architectural fit analysis (§2) confirms it cannot be adopted directly — single-user architecture, incompatible dependency chain, insufficient evaluation framework, absent trust-boundary enforcement. Nexus has already rebuilt Phase 1-equivalent capability with production-grade infrastructure.

The gap analysis (§4) reveals two PREREQUISITE gaps (G1 effectiveness scoring, G2 skill selection) that neither Hermes nor Nexus have built. These are now the critical path — without them, DSPy+GEPA compilation (v0.2.5) cannot produce meaningful results, and Wave 1 agents cannot safely accumulate skills.

The sequencing recommendation (§5) is honest about the cost: ~8-10 weeks of pre-Wave-1 maturity work (G1 + G2 + v0.2.5). This is longer than the strategic doc's original ~3-4 week v0.2.5 estimate. The delta is the operator's own directive — "fix the missing pieces" — correctly applied.

The per-module Adopt/Fork/Rebuild matrix (§3) is the operational deliverable the operator requested: "check every single availability." Twelve modules evaluated. Zero adopted directly. Three already rebuilt (skill_generator, skill_evaluator, skill_registry). Two forked as design inspiration (skill_curator, feedback). Seven out of scope or deferred.

The bee metaphor extends: before the brood-care bee (A.4) gets its new training system (DSPy+GEPA in v0.2.5), the hive needs to know what "effective foraging" means (G1) and which foragers should learn which skills (G2). Without those, the training system trains for the wrong things.

— Recorded 2026-05-23, post-Wave-0-closure, in response to operator challenges that correctly identified the Hermes-adoption question and the missing-pieces gap.
