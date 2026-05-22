# Hermes-pattern absorption — analysis for Nexus v0.2+ planning (2026-05-22)

> **Status:** doc-only, LOW-RISK, untracked at draft time. Captures the analysis from the 2026-05-22 Path-B-mid-sequence side-quest where the operator examined NousResearch's Hermes Agent ([github.com/NousResearch/hermes-agent](https://github.com/NousResearch/hermes-agent)) as a reference for "what good patterns can we steal." This doc is **deliberately preserved for the post-Supervisor-v0.1 second-pass v0.2 conversation** — that is, when 17/17 agents are at v0.1 and the platform opens its first deepening cycle.

> **Operator framing (verbatim, 2026-05-22):** _"like a bee lets suck in all the good nectar and feed it to our queen bee (nexus os) only the best goes in which would become value addition."_ This doc is that nectar inventory.

---

## §0. Why this doc exists

The Path-B-breadth-first operating rule (locked 2026-05-20) defers ALL v0.2+ work on shipped agents until 17/17 reach v0.1. During the breadth-first sequence (D.5 ✅ → D.8 → D.6 → D.13 → D.12 → A.4 → Supervisor), the operator examined Hermes Agent and asked: "are our agents dumb compared to this, or better?"

The answer is **neither — they're built for a different game**, and the architectural separation Nexus enforces is deliberate and correct. But Hermes has several genuinely good patterns that should land in Nexus v0.2+ when the second-pass conversation opens. This doc:

1. Inventories what Hermes does well (the "nectar")
2. Filters out what's wrong for Nexus's audience (the "sugar water")
3. Maps each accepted nectar to a specific Nexus agent's v0.2+ scope
4. Provides the architectural rationale ("the bee colony mapping") for why Supervisor cannot and should not become Hermes
5. Preserves the strategic context so future-operator (or future-team) doesn't re-do the analysis

**This is NOT a plan.** No code. No timeline. No commitment. Just the analysis preserved for when the second-pass v0.2 conversation opens.

---

## §1. What Hermes is (and isn't)

Hermes Agent is a **general-purpose personal AI assistant framework** built by NousResearch. Per its public docs:

- One agent (not a multi-agent system)
- Talks to a single human user via Telegram / Discord / Slack / WhatsApp / Signal / CLI
- **Self-improving learning loop**: agent-curated memory + autonomous skill creation + skill self-improvement during use + cross-session search
- **5 architectural pillars** per MindStudio's breakdown: memory, skills, soul, crons, self-improving loop
- Open-source, self-hosted, runs on anything from $5 VPS to GPU cluster
- ~94.6k GitHub stars (April 2026), v0.10.0 latest release
- Uses the open agentskills.io SKILL.md format (portable across Hermes / Claude Code / Cursor / Codex CLI)

**What Hermes is NOT:** a security platform, a multi-tenant SaaS, an audit-rigorous system, a specialist-domain reasoner. It is "your personal AI that grows with you."

## §2. What Nexus is (and isn't)

Nexus Cyber OS is a **multi-tenant autonomous cloud-security platform** with 17 specialized agents under a runtime charter. Per the platform-architecture + PRD:

- 17 specialist agents (one general agent ≠ one specialist; Nexus has 17 specialists + 1 dispatcher + 1 always-on auditor + 1 self-evolver)
- OCSF v1.3 wire format across all findings
- Hash-chained immutable audit log (F.6 Audit Agent always-on)
- Tier-1/2/3 remediation authority with 9 safety primitives (A.1 Remediation)
- Multi-tenant isolation with per-customer RLS (gates on SET LOCAL `$1` fix)
- Charter-enforced budget caps + execution contracts (F.1 Charter)
- Compliance framework mapping (CIS, SOC2, HIPAA, PCI, GDPR, FedRAMP, NERC-CIP)
- Eval-framework with per-agent test suites (F.2)
- Live cluster integration (kind, AWS, Azure, GCP, Kubernetes)
- Currently 10/17 at v0.1; Path-B-breadth-first sequence underway to reach 17/17

**What Nexus is NOT:** a personal assistant, a single-agent system, a hobbyist tool. Customer ACVs $50K-$500K; buyers are enterprise security teams; failure modes include audit-chain corruption and tenant-isolation violations.

## §3. The architectural collision (and why Hermes-style design would be catastrophic for Nexus)

Hermes optimizes for: **"one agent that does everything and grows over time."** That works for personal use.

Nexus deliberately splits Hermes's "one smart thing" into **separation of concerns** that makes it safe to be a security platform:

| Concern             | Hermes's answer       | Nexus's answer                                                          | Why Nexus splits it                                                                            |
| ------------------- | --------------------- | ----------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| Who routes work     | The agent itself      | **Supervisor (#0)** — dispatcher only, no analysis                      | Supervisor on critical path; must stay reliable; clever Supervisor = fragile platform          |
| Who learns / adapts | The agent itself      | **A.4 Meta-Harness** — gated, eval'd, signed                            | Learning agents make non-deterministic decisions; in security, that means audit-chain breakage |
| Who enforces laws   | Implicit in agent     | **F.1 Charter** — execution contracts, budgets, audit-mandated          | Multi-tenant isolation + audit retention require immutable substrate                           |
| Who acts            | The agent itself      | **A.1 Remediation** with 9 safety primitives + Tier 1/2/3 authorization | Autonomous action on customer infrastructure requires explicit safety contract                 |
| Who watches         | Memory layer          | **F.6 Audit Agent** always-on, hash-chained, 7-year retention           | Audit is the compliance product, not a side-effect                                             |
| Domain reasoning    | One LLM, in the agent | **17 specialists** each with domain hire-test analog                    | "CTI analyst" ≠ "CSPM analyst" ≠ "Forensic investigator"; deep domain expertise per agent      |

**The key insight:** Hermes can be one smart bee because nothing bad happens if it makes a mistake — its user shrugs and tries again. Nexus must be a hive because mistakes in security cost customers money / data / compliance posture / their own job.

**Therefore: Supervisor cannot fill Hermes's shoes.** Supervisor is explicitly forbidden (per AGENT_SPEC) from analysis, NLAH evolution, knowledge-graph writes, remediation execution. By design. Don't change this.

---

## §4. The bee-colony mapping (architectural metaphor for future reference)

The operator's bee metaphor became load-bearing during the 2026-05-22 conversation. Preserved verbatim here because it maps the architecture cleanly:

| Bee role                                                                              | Nexus component                                                                                                                                                       | Why                                                                                                                             |
| ------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| 👑 **Queen bee**                                                                      | **F.1 Charter**                                                                                                                                                       | The substrate. Spawns agents. Defines the laws. Every worker reports to her. Cannot be killed without the colony dying.         |
| **Royal jelly** (what makes a queen)                                                  | **ADR-007 reference NLAH + Execution Contracts + F.6 Audit Chain**                                                                                                    | The discipline that makes the platform a platform. Every agent inherits from this.                                              |
| 🐝 **Worker bees**                                                                    | **17 specialist agents**                                                                                                                                              | Each goes out, does specialized work, returns with nectar (findings, remediations, reports).                                    |
| 🌸 **Forager bees** (scouts that find flowers)                                        | **D.1 Vulnerability, D.2 Identity, D.3 Runtime Threat, D.4 Network Threat, D.5 Data Security, D.8 Threat Intel, F.3 Cloud Posture, multi-cloud-posture, k8s-posture** | Detect agents. They go out into customer cloud environments and find threats/data/configurations.                               |
| 🍯 **Honey processors** (turn nectar into honey)                                      | **D.7 Investigation + D.13 Synthesis + D.6 Compliance**                                                                                                               | Refine raw findings into incidents, narratives, compliance reports.                                                             |
| 🛡️ **Guards**                                                                         | **A.1 Remediation + safety primitives + Tier 1/2/3 authorization**                                                                                                    | Take action against threats. Have authorization tiers.                                                                          |
| 💃 **Waggle-dance communicators** (tell others where the flowers are)                 | **F.7 Fabric (NATS JetStream bus)**                                                                                                                                   | Transport. How bees tell each other what they found.                                                                            |
| 🏠 **The hive structure** (where everything is built)                                 | **F.5 Memory — SemanticStore + EpisodicStore**                                                                                                                        | Shared structure. Where knowledge accumulates across runs.                                                                      |
| 🚦 **Dispatcher at the hive entrance** (directs returning bees, assigns new foragers) | **Supervisor (#0)**                                                                                                                                                   | Routes work. Not the queen. Not a learner. Just a traffic controller.                                                           |
| 👮 **Royal attendants** (maintain queen's health, watch everything)                   | **F.6 Audit Agent**                                                                                                                                                   | Always-on. Hash-chained. Watches every action.                                                                                  |
| 🎓 **Brood-care bees** (raise young, train them)                                      | **A.4 Meta-Harness**                                                                                                                                                  | THE ONE that improves the colony itself. Reviews how workers performed. Trains better-shaped future workers via NLAH evolution. |

**This mapping is now the canonical metaphor for explaining Nexus architecture to non-technical operators (or future-you who forgot the details).** Cite it.

---

## §5. The nectar inventory

Distilled from Hermes Agent v0.10.0 (April 2026) docs + operator interrogation 2026-05-22. Eight items examined; **five kept as nectar, three rejected as sugar water**.

### 5.1 NECTAR (5 items going into the hive)

#### N1. Skills as procedural memory (markdown SKILL.md files with progressive disclosure)

**What Hermes does.** Skills are markdown files with YAML frontmatter (`name`, `description`, `version`, `platforms`). Loaded via three-level progressive disclosure:

- **Level 0**: metadata index of all skills (~3,000 tokens)
- **Level 1**: full SKILL.md content for one selected skill
- **Level 2**: individual reference files from the skill's directory

Agent picks skills by matching task description to skill description. Files live under `~/.hermes/skills/<category>/<skill-name>/SKILL.md` plus optional `references/`, `templates/`, `scripts/`, `assets/` subdirectories.

**Why it's nectar for Nexus.** Today every Nexus agent's NLAH (in `packages/agents/<agent>/src/<agent>/nlah/`) is loaded in full on every run. Static, monolithic. Token cost paid every invocation. As agent expertise grows, NLAH bloats; progressive disclosure stays lean.

**Where it lands in Nexus.** **A.4 Meta-Harness v0.2**. Extend the existing NLAH directory structure (already shipped per ADR-007 v1.2) to support progressive disclosure: metadata index at Level 0, full skill content at Level 1, reference files at Level 2. Each agent's NLAH becomes a skill library, not a monolith.

**Operator's question answered (2026-05-22):** "Who creates these skills? How autonomously?"

- **A.4 writes skills, not each agent.** Single librarian, many readers. Cleaner.
- **Eval-gate required before any auto-created skill ships.** Per ADR-011 for code; same discipline for skills.
- **Honest risk per Hermes docs:** _"Autonomous creation is not always accurate. Agent-generated skills sometimes capture unnecessary steps or miss important edge cases. Review generated skills and edit them manually when needed."_ Mitigation: human-approved on first run per skill.

**Value verdict: HIGH.** Token cost drops; agents scale better; existing NLAH architecture extends naturally; no charter-substrate changes needed.

---

#### N2. Autonomous skill creation after complex tasks

**What Hermes does.** After complex tasks (5+ tool calls), the agent writes a SKILL.md describing how it solved the task. Skills self-improve — patched during use when outdated, incomplete, or wrong.

**Why it's nectar for Nexus.** Today D.7 Investigation solves a tough cross-domain incident and the reasoning evaporates after the run. Next time D.7 sees a similar pattern, it starts from scratch. Hermes pattern: write the reasoning to a skill, accumulate institutional memory per-agent.

**Where it lands in Nexus.** **A.4 Meta-Harness v0.2** (same plan as N1). Flow:

1. D.7 (or A.1, or F.3, or any specialist) completes a complex task with ≥5 tool calls
2. F.6 Audit Agent's hash-chained trace is available
3. A.4 Meta-Harness reads the trace
4. A.4 emits a candidate SKILL.md describing: "When you face <pattern X>, do steps A → B → C. Watch out for pitfall Y."
5. **Eval-gate**: candidate skill must pass the relevant agent's eval suite before deploying to NLAH library
6. **Operator approval on first instance** of each new skill class

**Example skills Nexus might generate:**

- `~/.nexus/skills/investigation/aws-iam-privesc-via-assumed-role.md` — written by A.4 after D.7 cracks a tough AWS IAM privilege-escalation incident
- `~/.nexus/skills/remediation/eks-public-endpoint-fix-with-network-policy-restoration.md` — written after A.1 completes a tricky multi-step rollback
- `~/.nexus/skills/cloud-posture/novel-s3-policy-attack-path.md` — written when F.3 finds an unusual combination

**Value verdict: HIGH.** This is the "agents that compound vs plateau" pattern. PRD §7.7.6 already gestures at this — Hermes makes it concrete.

---

#### N3. Autonomous Curator (skill library pruning)

**What Hermes does.** Periodic janitor reviews agent-created skills: consolidates overlap, archives stale entries, writes per-run reports, protects pinned skills, adds archive/prune/list-archived workflows. Three rules applied:

- **Stale**: not used in 90 days → archive candidate
- **Duplicate**: similarity-search finds two skills with >85% overlap → merge candidate
- **Failing**: success_rate <50% over last 10 uses → review candidate

**Why it's nectar for Nexus.** If autonomous skill creation works (N2), without curation the skill library bloats — duplicates, contradictions, stale entries. Curator pattern keeps the library pruned.

**Where it lands in Nexus.** **A.4 Meta-Harness v0.3** (separate plan after N1+N2 ship). Weekly job. Output: operator-reviewable report with archive/consolidate/review candidates. Operator approves bulk actions. Skills move to `archived/` (recoverable, never deleted).

**Operator's question answered (2026-05-22):** "How does it know active → stale → archive?"

- **Stale** = not loaded in 90 days (Level-1 access counter)
- **Duplicate** = >85% description similarity OR >70% procedure-step overlap (semantic-search via embeddings)
- **Failing** = success_rate of agent runs that loaded this skill, measured against eval-suite expected outcomes

**Required prerequisites (named honestly):**

- **Per-skill telemetry**: load_count, last_used, success_rate-per-load. Today's agents don't emit this. Net new work.
- **Operator-pinning**: critical-but-rare skills (e.g., disaster recovery) must be pinnable so Curator never touches them. Per Hermes: "_protects pinned skills_."

**Value verdict: MEDIUM-HIGH.** Only matters AFTER N2 ships. Pure pruning discipline. Defer to A.4 v0.3.

---

#### N4. Per-customer behavioral baseline (Honcho-pattern translated)

**What Hermes does.** Honcho integration models the individual user across sessions ("the user prefers concise answers, lives in IST, hates emoji"). Persistent model of who they are.

**Why it's _translated_ nectar for Nexus.** Hermes models the human. Nexus has no individual human user — it has **customer organizations**. But the same pattern applied to organizations is real value:

- Acme Corp's normal AWS spending pattern (so D.12 Curiosity flags anomalies)
- HealthGroup's data-residency requirements (so D.5/D.6 flag violations correctly)
- BankCorp's typical deploy schedule (so D.4 flags lateral movement that's _unusual for them_)

Per-customer baseline modeling is genuinely valuable because **what's normal varies by customer**.

**Where it lands in Nexus.** **D.12 Curiosity v0.2**. D.12 v0.1 (per sketch §4) does "hypothesis over coverage gaps." Extending to "per-customer behavioral baseline + anomaly detection against that baseline" is the same shape applied to organizational context. Built on F.5 SemanticStore (where customer-context entities live).

**Operator's verdict (2026-05-22):** _"honcho is good"_ — confirmed.

**Value verdict: MEDIUM-HIGH.** Lands in D.12 v0.2.

---

#### N5. agentskills.io open SKILL.md format (strategic free-win)

**What Hermes uses.** The agentskills.io open standard — a portable format ("just YAML frontmatter + markdown") that any compatible agent can read. Compatible agents: Hermes, Claude Code, Cursor, Codex CLI. ~672 community skills already published in the format.

**Why it's nectar for Nexus.** When A.4 writes Nexus skills, doing it in the agentskills.io standard means:

1. **Existing community skills could potentially work in Nexus** (with appropriate sandboxing — these would be untrusted by default, scan-before-use)
2. **Nexus skills are portable** — removes "vendor lock-in" objection from enterprise sales conversations: _"If you leave Nexus, you keep your skills."_
3. **Future ecosystem play** — security analysts could write Nexus-specific skills and share them (Phase 2-3 territory)

**Versus the alternative:** A.4 invents its own SKILL.md format. Works only inside Nexus. No portability. No ecosystem. **Same engineering cost. Much smaller strategic surface.**

**Operator's question answered (2026-05-22):** "I don't get agentskills.io" → It's an open file-format spec. Like PDF is an open format. Cost is the same; ecosystem leverage is much bigger.

**Value verdict: HIGH-STRATEGIC.** Land in **A.4 Meta-Harness v0.2** alongside N1+N2. Mandate that all Nexus-emitted skills conform to the agentskills.io standard from day one.

---

### 5.2 NECTAR-WITH-CAVEATS (1 item, downgraded by operator scrutiny)

#### N6. FTS5 cross-session search with LLM summarization — REQUIRES A SURFACE TO CONSUME IT

**What Hermes does.** Full-text search (SQLite FTS5) across all past session text + LLM summarizes relevant hits. Enables queries like "what did we discuss about Project X last quarter?"

**Why it's _partial_ nectar for Nexus.** Today F.5 EpisodicStore holds the data but has no good way to ask: _"have we seen this attack pattern before in this customer's last 90 days?"_ The Hermes pattern would surface that.

**The operator's correct caveat (verbatim 2026-05-22):** _"cross session llm would only useful if our system is connected to team chat for cyber team to access or we will have a window."_ This is exactly right. The capability has no value without a consumption surface.

**Required prerequisites:**

- **Surface track**: either S.1 Console v1 (web chat window) OR S.3 ChatOps (Slack/Teams integration) must exist for security analysts to ASK the questions
- Without a surface, the search engine has no mouth

**Where it lands in Nexus.** **D.13 Synthesis v0.2** — D.13 v0.1 does cross-source LLM narration; extending to cross-session search is the same agent doing the same thing across a time dimension. **BUT gated on S.1 Console OR S.3 ChatOps shipping first.** No point building the engine before there's an interface for it.

**Value verdict: HIGH for operator UX, BUT sequence-blocked.** Don't build until a surface is built.

---

### 5.3 SUGAR WATER (3 items rejected — leave behind)

#### S1. Slash commands + interactive TUI (Hermes pillar)

**Operator's verdict (2026-05-22):** _"slash command i dont think we need it."_ Confirmed.

**Why rejected:**

- Slash commands work for single-agent TUI experiences (Hermes is one); Nexus has per-agent CLIs + planned web console + planned API
- Adds zero value to enterprise SOC workflow
- UX patterns belong to Surface track (S.1/S.2), not detect-agent track

**Action: SKIP.** Don't even cite as reference. Different UX model entirely.

---

#### S2. Skills Hub marketplace (community skill registry)

**Operator's question (2026-05-22):** _"skill hub i dont get it the need."_ Correctly skeptical.

**Why rejected (in current scope):**

- **You have ~zero customers.** A marketplace without participants is an empty website.
- **Customer skills would be customer-confidential.** Acme's internal remediation playbook isn't public.
- **Trust model is wrong.** Per Hermes docs: _"Quality varies in community skills... not vetted with the same rigor as bundled skills."_ Nexus cannot run unvetted skills against customer infrastructure.
- **Wrong audience.** Hermes Hub serves hobbyists worldwide; Nexus serves enterprise SOCs.

**When (if ever) Nexus might want this:**

- Phase 2-3 (post-GA, 20+ customers, clear demand for shared community-vetted detection rules / remediation playbooks)
- Modeled on Sigma rules / Falco rules community catalogs (security-domain precedent), NOT on app-store free-for-all
- Nexus-curated marketplace with eval-gate + signing + sandboxing, not open submission

**Action: SKIP for current scope.** Park as "post-GA strategic conversation if customer demand emerges."

---

#### S3. Multi-provider model switching (Hermes "use any model" feature)

**Why rejected.** Nexus already has a **better-disciplined version** of this:

- `charter.llm_adapter` (ADR-007 v1.1) provides multi-provider abstraction
- Anthropic Claude as primary per ADR-006
- Multi-provider fallback architecture documented
- **Eval-gated model swaps**, not YOLO model switching

Hermes optimizes for "switch with one command, no lock-in." Nexus optimizes for "swap only after eval suite confirms parity." Different discipline; Nexus's is correct for security.

**Action: SKIP.** Already solved better. Cite charter.llm_adapter when asked.

---

### 5.4 Also-rejected (not in operator's 2026-05-22 examination but worth recording)

- **Multi-platform reach (Telegram / Discord / WhatsApp / Signal)**: wrong audience. Enterprise SOCs don't approve security remediations via WhatsApp. S.3 ChatOps (planned, Slack/Teams) covers the right audience.
- **Cron scheduler pillar**: Nexus has heartbeat-driven autonomous loop per PRD §4.1 + F.6 always-on pattern. Different mechanism, same outcome, more disciplined.
- **Local-model / $5 VPS focus**: wrong economic model. Enterprise customers pay $50K-$500K ACV; they don't care about $5 VPS deployment. Hermes's "cheap" is a feature for hobbyists.

---

## §6. The nectar landing map (summary)

| Nectar                                                               | Lands in         | Plan version                            | Priority                                |
| -------------------------------------------------------------------- | ---------------- | --------------------------------------- | --------------------------------------- |
| **N1** Progressive-disclosure NLAH (skill metadata + on-demand load) | A.4 Meta-Harness | v0.2                                    | First v0.2 work after 17/17 hits        |
| **N2** Autonomous skill creation post complex runs (≥5 tool calls)   | A.4 Meta-Harness | v0.2 (same plan as N1)                  | Same                                    |
| **N3** Autonomous Curator (stale/duplicate/failing pruning)          | A.4 Meta-Harness | v0.3 (after N2 ships + telemetry lands) | Second wave                             |
| **N4** Per-customer behavioral baseline (Honcho-pattern translated)  | D.12 Curiosity   | v0.2                                    | Independent track                       |
| **N5** agentskills.io open SKILL.md format                           | A.4 Meta-Harness | v0.2 (same plan as N1+N2)               | Same — free strategic win               |
| **N6** FTS5 cross-session search + LLM summary                       | D.13 Synthesis   | v0.2                                    | **Gated on Surface track (S.1 or S.3)** |

**Net: 6 patterns going into the hive across three agents' v0.2+ work (A.4, D.12, D.13).** All additive. None disrupt Path-B-breadth-first v0.1 sequence. All consistent with PRD §7.7.6 self-evolution promise.

**Three patterns deliberately left behind** (S1 slash commands / S2 skills hub / S3 multi-provider switching) plus three more (multi-platform / cron / local-model focus) — see §5.3 + §5.4.

---

## §7. Why Supervisor cannot fill Hermes's shoes (architectural reasoning preserved)

Operator's question (verbatim 2026-05-22): _"this supervisor sound more like hermes? can it fill hermes shoes?"_

**Answer: NO. And it shouldn't.**

Per AGENT_SPEC §4 (Supervisor Agent):

> _"By keeping its responsibilities narrow, we keep its failure surface narrow."_

Supervisor's restrictions are explicit and load-bearing:

| Restriction                                                       | Why                                                             |
| ----------------------------------------------------------------- | --------------------------------------------------------------- |
| Cannot itself call detection or remediation tools (must delegate) | Specialists own domain expertise                                |
| Cannot perform domain analysis (must delegate)                    | Mixing routing + analysis = unbounded scope                     |
| Cannot execute against customer infrastructure                    | A.1 Remediation owns the 9-primitive safety contract            |
| Cannot modify NLAH or charter                                     | Meta-Harness or engineering only — learning is gated separately |

**The architectural separation matters:**

- **Supervisor** = dumb dispatcher (reliable, narrow, never adapts mid-run)
- **A.4 Meta-Harness** = the learning brain (gated, eval'd, signed, deployed via canary rollout)
- **F.1 Charter** = the laws (immutable, audited)
- **17 specialists** = the workers (each disciplined to its domain)

This is the deliberate opposite of Hermes's "one smart thing." Hermes can be one agent because nothing bad happens if it gets clever and makes a mistake. Nexus must be a hive because **clever ≠ safe** in security.

**Therefore: Hermes nectar lands in A.4 Meta-Harness (the learning brain), NOT in Supervisor (the dispatcher).** This separation is non-negotiable.

---

## §8. Strategic context — why preserve this analysis now?

**Path-B-breadth-first operating rule** (locked 2026-05-20) defers all v0.2+ work until 17/17 at v0.1. The current sequence:

1. ✅ D.5 Data Security v0.1 (CLOSED 2026-05-20)
2. ⏳ D.8 Threat Intel v0.1 (plan-doc PR open, awaiting review)
3. ⬜ D.6 Compliance v0.1 (queued; coder system started parallel work)
4. ⬜ D.13 Synthesis v0.1
5. ⬜ D.12 Curiosity v0.1 (requires F.7 `claims.>` ADR first)
6. ⬜ A.4 Meta-Harness v0.1
7. ⬜ Supervisor (#0) v0.1 — LAST

**Estimated runway to 17/17 v0.1: ~3-4 months at observed Nexus per-task PR cadence (per ADR-011 discipline).**

When Supervisor v0.1 closes:

- 17/17 agents at v0.1
- Platform-complete narrow-depth across 11 of 14 Wiz capability buckets
- AI-SPM / AppSec / SSPM still missing (planned as D.9/D.10/D.11; not in current 7-agent push)
- **Second-pass v0.2+ conversation opens**

**That conversation is when this doc gets consulted.** Future-operator (or future-team) reads this and inherits the analysis without re-doing it. The natural first v0.2 candidate becomes **A.4 Meta-Harness v0.2** absorbing N1 + N2 + N5 in one plan.

---

## §9. What this doc is NOT

- **Not a plan.** No tasks. No commits. No code. Just analysis preserved for future use.
- **Not a commitment to specific timing.** v0.2 conversation opens post-Supervisor-v0.1 close; nothing scheduled today.
- **Not a revision to PR #52 (remaining-agents sketch).** Cites it; does not modify it.
- **Not a revision to PR #53 (version-roadmaps doc).** Cites it; does not modify it.
- **Not a substrate change.** No `packages/charter/`, `packages/shared/`, or `packages/agents/` changes implied.
- **Not the final word.** Reality at v0.2-conversation-time (with design-partner signal and 17/17 platform context) may revise these conclusions. This is the analysis at 2026-05-22.

---

## §10. References

External:

- [NousResearch/hermes-agent on GitHub](https://github.com/NousResearch/hermes-agent) — Hermes Agent v0.10.0 (April 2026)
- [Hermes Agent docs](https://hermes-agent.nousresearch.com/docs/) — official documentation
- [agentskills.io](https://agentskills.io) — open SKILL.md format spec
- [MindStudio's 5-pillar architecture breakdown](https://www.mindstudio.ai/blog/hermes-agent-5-pillar-architecture-memory-skills-soul-crons)
- [DeepWiki Skills System article](https://deepwiki.com/NousResearch/hermes-agent/8-skills-system)

Internal Nexus:

- `docs/strategy/PRD.md` §7.1–§7.7 (capability spec) + §7.7.6 (self-evolution)
- `docs/agents/agent_specification_with_harness.md` (canonical 14-agent spec; Supervisor §4)
- `docs/agents/_archive/AGENT_SPEC_PART1.md` (full Supervisor specification)
- `docs/superpowers/sketches/2026-05-20-remaining-agents-sketch.md` (7 unbuilt agents v0.1)
- `docs/superpowers/sketches/2026-05-20-agent-version-roadmaps.md` (17 agents trajectory)
- `docs/_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md` (reference NLAH; v1.2 NLAH loader)
- `docs/_meta/decisions/ADR-010-version-extension-template.md` (within-agent version extensions)
- `docs/_meta/decisions/ADR-011-pr-flow-and-branch-protection-discipline.md` (per-task PR cadence)

---

## §11. Author's note (preserved for future-operator)

This doc was drafted 2026-05-22 mid-Path-B-sequence, during a deliberate side-quest where the operator examined a competitive open-source agent framework to ask "are we missing something?" The honest answer was: _some patterns yes, but not the way you'd expect; here's the careful map._

The bee metaphor (§4) is load-bearing for explaining Nexus architecture to non-technical operators or to future-self when memory of this conversation fades. **Cite it. Use it.**

The Path-B-breadth-first discipline holds. This doc does NOT redirect the sequence. It informs the second-pass v0.2 conversation when it opens after Supervisor v0.1 closes.

— Recorded 2026-05-22, mid-D.8-Threat-Intel-v0.1 plan-review cycle.

---

**Status update 2026-05-22 (post-Path-B close):** Path-B-breadth-first push closed at **17/17 platform-complete-narrow-depth** (D.8 / D.6 / D.13 / D.12 / A.4 / Supervisor #0 all shipped same day as the original §8 estimate of "3-4 months" — the §8 _sequence_ prediction held; the _timing_ prediction was off by ~100×). Phase 1 (Maturity-First) operating rule now in effect, retiring Path-B-breadth-first. **This doc is the canonical reference for Wave 0 (A.4 Meta-Harness v0.2)** which absorbs nectar items **N1 + N2 + N5** per the §6 landing map. N3 (Autonomous Curator) lands in A.4 v0.3 — NOT v0.2. N4 (per-customer baseline) lands in D.12 v0.2. N6 (cross-session search) lands in D.13 v0.2 gated on Surface track.
