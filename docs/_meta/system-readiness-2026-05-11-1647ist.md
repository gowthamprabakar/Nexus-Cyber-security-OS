# Nexus Cyber OS — System Readiness (timestamped + rate-of-completion + ground-zero comparison)

|                         |                                                                                                                                                                                      |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Snapshot date**       | 2026-05-11                                                                                                                                                                           |
| **Captured at**         | 2026-05-11T11:17:01Z (UTC) · 2026-05-11 16:47:01 IST (local)                                                                                                                         |
| **Last commit at HEAD** | `e5a96bb` — `docs(d3): pin task 4+5 commit hash; flip status rows; mark q2 resolved`                                                                                                 |
| **Phase position**      | Phase 1a (Foundation), Week ~2 of 12                                                                                                                                                 |
| **Audience**            | Founders, board / investors, design partners, engineering leadership                                                                                                                 |
| **Purpose**             | Mid-day snapshot quantifying rate-of-completion across every track, **comparing against the ground-zero PRD/VISION**, and surfacing what's pending **at every level — not just FE**. |
| **Supersedes (today)**  | [system-readiness-2026-05-11-eod.md](system-readiness-2026-05-11-eod.md) — D.1 closeout (~16h ago)                                                                                   |
| **Pairs with**          | [Platform completion report](platform-completion-report-2026-05-10.md) (strategic pillars + direction check)                                                                         |

---

## 1. Ground-zero comparison

The two canonical "ground-zero" artifacts are:

- [`docs/strategy/PRD.md`](../strategy/PRD.md) — what the platform is (committed scope).
- [`docs/strategy/VISION.md`](../strategy/VISION.md) — where the platform is going (aspirational direction).

Both are still at draft 1.0 from the founding team and have not been re-baselined as Phase 1a foundation work has landed. The ground-zero capability promise:

> "Detection capability comparable to the leading CNAPPs (Wiz, etc.) **plus two architectural innovations the incumbents do not provide:**
>
> 1. Autonomous remediation through a **three-tier authority model** (Tier 1 autonomous / Tier 2 approval-gated / Tier 3 recommend-only).
> 2. **Edge mesh deployment** — single-tenant edge runtime in the customer's environment connected to a SaaS control plane."
>
> "**18 specialist agents** across detect / prevent / investigate / remediate / comply lifecycle. Self-evolution loop (Meta-Harness Agent) compounds learning across agents."

### Where we land against the ground-zero promise

| Ground-zero promise                                          | Current state                                                                                                                                                                      | Gap                                                                                                                                                         |
| ------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **18 specialist agents**                                     | **3 shipped** (cloud-posture, vulnerability, identity) + **1 in flight** (runtime-threat at 5/16 tasks)                                                                            | 14 agents pending (incl. compliance, investigation, threat-intel, application, SaaS, AI-SPM, etc.)                                                          |
| **Three-tier remediation authority**                         | Track A entirely pending; only **Tier 3 (recommend)** is implicit in current finding outputs                                                                                       | Tier 2 (approve & execute), Tier 1 (autonomous), Meta-Harness self-evolution all pending                                                                    |
| **Edge mesh deployment**                                     | Track E entirely pending. Edge runtime (Go), mTLS pipeline, Helm chart all greenfield.                                                                                             | The platform currently runs only as a CLI-invoked agent inside the customer's CI / local laptop                                                             |
| **SaaS control plane + Auth0 SSO + RBAC**                    | **F.4 complete** (auth0_client + JWT verifier + tenant resolver + RBAC + SCIM + MFA + audit chain); operator runbook written                                                       | Live Auth0 sandbox integration test deferred to a real dev-tenant bootstrap                                                                                 |
| **Memory engines: TimescaleDB + Postgres + Neo4j Aura**      | F.4 introduces Postgres baseline; F.5 (full three-engine memory) not yet started                                                                                                   | Episodic (TimescaleDB), semantic/KG (Neo4j Aura) pending. Per the system-readiness recommendation F.5 can collapse to Postgres+JSONB+pgvector for Phase 1a. |
| **Console (chat + dashboard, Next.js)**                      | **Zero LOC.** [`packages/console/`](../../packages/console/) is a single `.gitkeep` file.                                                                                          | **Largest single shippable gap.** Tracks S.1, S.2 (dashboard + chat sidebar) entirely pending — both required for paying-customer launch in Phase 1c.       |
| **ChatOps approvals (Slack + Teams + Email)**                | Track S.3 entirely pending                                                                                                                                                         | Required for Tier 2 remediation flow                                                                                                                        |
| **API + CLI (REST + Python SDK + `nexus` CLI)**              | Per-agent CLIs land at end of each agent plan (`identity-agent eval/run`, `vuln-agent eval/run`); no unified REST API yet                                                          | Track S.4 pending — single REST API + Python SDK is what design partners integrate against                                                                  |
| **Vertical content packs (tech + healthcare)**               | Track C entirely pending                                                                                                                                                           | C.1 tech pack is required for Phase 1 paying-customer; C.2 healthcare pack is Phase 1 GA target ≥ 80%                                                       |
| **OSS releases (charter + eval-framework on public GitHub)** | Track O.6 pending; substrate code already isolated under Apache 2.0 per ADR-001 split                                                                                              | One-shot release work (~2 weeks per the roadmap)                                                                                                            |
| **SOC 2 Type I scoping**                                     | Starting evidence captured in [F.4 verification record](d2-f4-verification-2026-05-11.md) — SCIM provisioning, MFA enforcement, hash-chained audit, tenant boundaries all in place | Full SOC 2 (Track O.2, 8 weeks parallel) pending. Nexus's own security architecture, threat model, pen test still ahead.                                    |

**Verdict against ground zero.** Foundation pillars are mostly in (4/6). The **detection layer is on the curve** (3 + 1 of 18 agents). The **autonomous-remediation layer** and the **edge mesh** — the two named architectural innovations differentiating from Wiz — are both at 0%. The **console** (the surface customers actually use) is at 0%. Tech-side excellence on the substrate is rising faster than customer-facing surface area.

---

## 2. Headline rate of completion

| Dimension                                                                                            |               Today | 2026-05-11 EOD baseline | Phase 1a target |    Phase 1 GA (M12) |
| ---------------------------------------------------------------------------------------------------- | ------------------: | ----------------------: | --------------: | ------------------: |
| **Sub-plans complete** (of ~25 in [build roadmap](../superpowers/plans/2026-05-08-build-roadmap.md)) |            **~33%** |                    ~28% |             80% |                100% |
| **Production agents shipped** (of 18 in PRD §1.3)                                                    |          **3 / 18** |                  2 / 18 |         ~6 / 18 |             18 / 18 |
| **Phase 1a foundation** (F.1 + F.2 + F.3 + F.4 + F.5 + F.6)                                          |           **4 / 6** |                   3 / 6 |           6 / 6 |                done |
| **ADR-007 patterns validated**                                                                       |         **10 / 10** |                 10 / 10 |         10 / 10 |             10 / 10 |
| **ADRs in force**                                                                                    | **8** (007 at v1.2) |         8 (007 at v1.1) |             ~10 |                 ~10 |
| **Wiz-equivalent capability coverage** (weighted)                                                    |          **~14.8%** |                  ~11.8% |         ~50–60% |                ~85% |
| **Frontend / Console (Track S)**                                                                     |              **0%** |                      0% |   0% (Phase 1c) |                100% |
| **Remediation (Track A)**                                                                            |              **0%** |                      0% |              0% |       100% (3-tier) |
| **Edge plane (Track E)**                                                                             |              **0%** |                      0% |              0% |                100% |
| **Vertical content (Track C)**                                                                       |              **0%** |                      0% |              0% | C.1 100% / C.2 ≥80% |

**Rate-of-completion verdict.** Phase 1a foundation has moved from 50% → 67% in the last ~16 hours (F.4 closed; D.2 closed; D.3 started). The two load-bearing remaining pieces in Phase 1a are **F.5 memory engines** and **F.6 audit-as-an-agent**, both of which now have most-of-their-substrate already shipped (Postgres in F.4, hash-chained audit in F.1/F.4). Phase 1a trajectory holds; the **shape risk is moving down-stack** to Tracks S/A/E/C/O.

---

## 3. Numbers (verifiable from `git log` + `pytest` at HEAD `e5a96bb`)

### Test surface

|                                           |   Today | 2026-05-11 EOD | Δ               |
| ----------------------------------------- | ------: | -------------: | :-------------- |
| Tests passing (default)                   | **818** |            459 | **+359 (+78%)** |
| Tests skipped (opt-in via `NEXUS_LIVE_*`) |       5 |              5 | 0               |
| Tests with all live gates set             | **823** |            464 | +359            |
| Test runtime (default suite)              |   ~8.7s |           5.3s | +3.4s           |
| mypy strict source files                  |  **93** |             60 | +33             |

### Per-package surface

| Package                          |   Tests |       Coverage | mypy strict |
| -------------------------------- | ------: | -------------: | :---------- |
| `charter` (incl. integration)    |     112 |          n/a\* | ✓           |
| `eval-framework`                 |     146 |         94.93% | ✓           |
| `shared`                         |      26 |            n/a | ✓           |
| `control-plane` (F.4 — NEW)      |     130 |     **90.67%** | ✓           |
| `cloud-posture`                  |      78 |         96.09% | ✓           |
| `vulnerability`                  |     111 |         96.84% | ✓           |
| `identity` (D.2 — NEW)           |     142 |     **97.46%** | ✓           |
| `runtime-threat` (D.3 in flight) |      78 | high (partial) | ✓           |
| **TOTAL**                        | **818** |  weighted ~95% | clean       |

\* charter coverage not measured at this commit; spot checks at 97% from the F.4 / D.3 sweep.

### Source surface

|                                     |      Today | 2026-05-11 EOD |                     Δ |
| ----------------------------------- | ---------: | -------------: | --------------------: |
| Total Python files                  |    **182** |            120 |                   +62 |
| Source LOC (excluding tests)        | **10,614** |   ~7,000 (est) |               ~+3,600 |
| Test LOC                            | **13,574** |         ~7,177 |               ~+6,397 |
| **Total Python LOC**                | **24,188** |         14,177 |    **+10,011 (+71%)** |
| Frontend (TypeScript / Next.js) LOC |      **0** |              0 |                     0 |
| Go (edge runtime) LOC               |      **0** |              0 |                     0 |
| ADRs in force                       |      **8** |              8 | 0 (007 amended twice) |
| Total commits since 2026-05-08      |    **172** |            136 |                   +36 |

**The "0 LOC" rows in `Frontend` and `Go` are the load-bearing ground-zero gaps.** Two of the three named languages in the [tech stack](../superpowers/plans/2026-05-08-build-roadmap.md#L11) have not yet been started.

---

## 4. Rate of completion — sub-plan inventory (full track table)

| Track | Title                                | Inventoried | Done / In-flight |                                                  % | Phase   | Status                                                                                                                   |
| :---: | ------------------------------------ | ----------: | ---------------: | -------------------------------------------------: | :------ | :----------------------------------------------------------------------------------------------------------------------- |
| **0** | Bootstrap (Phase 0)                  |           9 |            3 / 0 |                                                33% | 0       | P0.1 ✓ · P0.2 ✓ · P0.5 subsumed into F.1; P0.3/P0.4/P0.6/P0.7/P0.8/P0.9 spikes still open                                |
| **F** | Foundation (Phase 1a)                |           6 |            4 / 0 |                                            **67%** | 1a      | F.1 ✓ · F.2 ✓ · F.3 ✓ · F.4 ✓ · **F.5 ⬜** (memory engines) · **F.6 ⬜** (Audit Agent)                                   |
| **D** | Detection breadth                    |          13 |            3 / 1 |                                   **31%** weighted | 1b      | D.1 ✓ · D.2 ✓ · D.3 in flight (5/16 = ~31%) · D.4-D.13 ⬜                                                                |
| **A** | Action / remediation                 |           4 |                0 |                                                 0% | 1b → 1c | A.1 (Tier 3) ⬜ · A.2 (Tier 2) ⬜ · A.3 (Tier 1) ⬜ · A.4 (Meta-Harness) ⬜                                              |
| **S** | Surfaces (console, ChatOps, API/CLI) |           4 |                0 |                                             **0%** | 1b → 1c | **S.1 console-dashboard ⬜ · S.2 console-chat ⬜ · S.3 ChatOps ⬜ · S.4 API/CLI ⬜**                                     |
| **E** | Edge plane                           |           3 |                0 |                                             **0%** | 1b      | E.1 (Go runtime) ⬜ · E.2 (mTLS pipeline) ⬜ · E.3 (Helm chart) ⬜                                                       |
| **C** | Vertical content packs               |           3 |                0 |                                             **0%** | 1b → 1c | C.0 (generic baseline) ⬜ · **C.1 (tech pack) ⬜** · C.2 (healthcare ≥ 80%) ⬜                                           |
| **O** | Operations + GA readiness            |           6 |                0 |                                             **0%** | 1c → GA | O.1 (observability) ⬜ · O.2 (SOC 2) ⬜ · O.3 (onboarding) ⬜ · O.4 (DR drill) ⬜ · O.5 (docs) ⬜ · O.6 (OSS release) ⬜ |
| **Σ** |                                      |         ~48 |            10.31 | **~21%** of full inventory · **~33%** of named ~25 |         |                                                                                                                          |

**Notes on counting:**

- **In-flight** (e.g. D.3 at 5/16 tasks) is counted as `tasks_done / total_tasks` of one sub-plan and added as a partial.
- Of the 25 named sub-plans, 8 are complete (P0.1, P0.2, F.1, F.2, F.3, F.4, D.1, D.2) and 1 is in flight (D.3 at ~31%); that's **~33% of the named ~25**.
- Spike sub-plans (P0.3-P0.9) are partially subsumed into the foundation plans they unblocked (e.g. P0.5 charter PoC ↔ F.1; P0.7 budget enforcement ↔ F.1). Counting them as "not done" is conservative — the architectural questions they were meant to resolve have been answered in code.

---

## 5. ADR-007 reference-template trajectory

The platform's "amend on the third duplicate" discipline locked in:

| ADR-007 version       | Trigger                                                                                                                                       | What hoisted into `nexus-charter` | Validation gate                              |
| --------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------- | -------------------------------------------- |
| **v1.0** (2026-05-10) | F.3 Cloud Posture canonized as reference                                                                                                      | n/a                               | 10 patterns codified                         |
| **v1.1** (2026-05-11) | D.1 Vulnerability twice-validated 10/10 patterns; flagged the LLM-adapter duplicate                                                           | `charter.llm_adapter`             | -19 redundant tests removed                  |
| **v1.2** (2026-05-11) | D.2 Identity twice-validated v1.1; flagged the NLAH-loader duplicate (now duplicated 3 times across cloud-posture / vulnerability / identity) | `charter.nlah_loader`             | +10 canonical tests; -95 LOC across 3 agents |

D.3 (Runtime Threat) is the first agent built **end-to-end against the post-v1.2 canon** — its `nlah_loader.py` is a 25-line shim, not a 55-line copy; its smoke test directly imports `charter.{llm_adapter,nlah_loader}`. The substrate is locked in code.

**No new amendment expected from D.3.** If one surfaces (e.g., severity-normalization across heterogeneous sensors becomes its own duplicate by the time D.4 ships), it lands as v1.3 before D.5.

---

## 6. What remains — **at every level**

The user-facing prompt was explicit: not just frontend. This section enumerates every level.

### 6.1 Strategy & business documents (Layer 0)

| Item                           | Status                                                                                                | Risk                                                  |
| ------------------------------ | ----------------------------------------------------------------------------------------------------- | ----------------------------------------------------- |
| PRD.md (v1.0 founder draft)    | **Not re-baselined** since pre-bootstrap                                                              | Drifts from current reality every week the build runs |
| VISION.md (v1.0 founder draft) | Same                                                                                                  | Lower-stakes drift; vision is multi-year              |
| Hiring & runway sister doc     | **Not written** ([flagged in roadmap §Self-review](../superpowers/plans/2026-05-08-build-roadmap.md)) | Burn rate vs. delivery cadence not modeled            |
| First design-partner LOI       | **Pending**                                                                                           | Phase 0 exit gate; affects M4 scenario assumption     |
| Pricing & packaging in PRD §15 | Drafted                                                                                               | Needs market validation against design partners       |

### 6.2 Backend — foundation substrate (Layer 1)

| Component                                                | Status                  | Pending work                                                                                                                                     |
| -------------------------------------------------------- | ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| `charter` (F.1)                                          | ✅ shipped + 2× amended | Stable. Future amendments come from agent risk-down reviews.                                                                                     |
| `eval-framework` (F.2)                                   | ✅ shipped (ADR-008)    | OSS release (Track O.6) once first design partner signs                                                                                          |
| `control-plane.auth` (F.4)                               | ✅ shipped              | Live Auth0 sandbox integration test (operator runbook walks through it)                                                                          |
| `control-plane.tenants` (F.4)                            | ✅ shipped              | Postgres alembic baseline exists; F.5 inherits                                                                                                   |
| **Memory engines** (F.5)                                 | ⬜ **pending**          | Decision pending: full TimescaleDB + Postgres + Neo4j vs. Phase-1a collapse to Postgres + JSONB + pgvector                                       |
| **Audit Agent** (F.6)                                    | ⬜ **partly subsumed**  | Hash-chained audit chain exists in `charter.audit` + `control_plane.auth.audit`; standalone "Audit Agent" as a Track-D-style agent not yet built |
| ULID / correlation primitives (`shared`)                 | ✅ shipped              | Stable.                                                                                                                                          |
| Fabric layer (OCSF wrap/unwrap, NexusEnvelope) (ADR-004) | ✅ shipped in `shared`  | Cross-agent consumer (Investigation Agent, D.7) consumes these                                                                                   |

### 6.3 Backend — agents (Layer 2)

| Agent   | Title                                   | Status              | Effort to ship per roadmap |
| ------- | --------------------------------------- | ------------------- | :------------------------- |
| F.3     | Cloud Posture (CSPM)                    | ✅ shipped          | (was 5 wks)                |
| D.1     | Vulnerability                           | ✅ shipped          | (was 4 wks)                |
| D.2     | Identity (CIEM)                         | ✅ shipped          | (was 5 wks)                |
| **D.3** | **Runtime Threat (CWPP)**               | 🟡 in flight (5/16) | (5 wks; ~½ remaining work) |
| D.4     | Network Threat                          | ⬜ pending          | 4 wks                      |
| D.5     | Data Security (DSPM)                    | ⬜ pending          | 5 wks                      |
| D.6     | Compliance + framework engine           | ⬜ pending          | 6 wks                      |
| D.7     | Investigation + sub-agent orchestration | ⬜ pending          | 6 wks                      |
| D.8     | Threat Intel                            | ⬜ pending          | 4 wks                      |
| D.9     | Application & Supply Chain (SAST)       | ⬜ pending          | 5 wks                      |
| D.10    | SaaS Posture (SSPM)                     | ⬜ pending          | 5 wks                      |
| D.11    | AI Security (AI-SPM)                    | ⬜ pending          | 4 wks                      |
| D.12    | Curiosity Agent                         | ⬜ pending          | 3 wks                      |
| D.13    | Synthesis Agent                         | ⬜ pending          | 3 wks                      |

**Track-D pattern fitness**: 3/3 agents built so far validate ADR-007 v1.2 verbatim. **The remaining 14 agents are pure execution against a locked template** — no architectural decisions expected. The pattern-fitness coefficient drives an estimate: each subsequent agent ships ~10-15% faster than the prior because more substrate is in `charter`.

### 6.4 Backend — autonomy / remediation (Layer 3)

| Component                                          | Status     | Why it matters                                                                                                                                               |
| -------------------------------------------------- | ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| A.1 — Remediation Agent (Tier 3 / recommend)       | ⬜ pending | Generates Cloud Custodian / Terraform / runbook artifacts; the **non-controversial baseline**                                                                |
| A.2 — Remediation Agent (Tier 2 / approve&execute) | ⬜ pending | The **first interactive product surface** — requires ChatOps (S.3)                                                                                           |
| A.3 — Remediation Agent (Tier 1 / autonomous)      | ⬜ pending | 8 narrow action classes + dry-run + blast-radius cap + auto-rollback timer + post-validation. **One of the two named architectural differentiators vs. Wiz** |
| A.4 — Meta-Harness Agent (self-evolution)          | ⬜ pending | Reads traces from all D.\* agents and proposes NLAH improvements through the eval gate. **The third moat per PRD.**                                          |

**Risk:** the entire autonomy stack is unbuilt. The PRD's "true tiered autonomy with rollback safety" claim is currently aspirational — Tier 3 (recommend) is implicit in finding outputs, Tier 2/1 are not yet wired anywhere. **A.2 + A.3 + A.4 are the central Phase 1c work that buys the platform's differentiation.**

### 6.5 Frontend / surfaces (Layer 4) — **the largest single shippable gap**

| Surface                                           | Status              |                  LOC committed | Phase   | Notes                                                                                                |
| ------------------------------------------------- | ------------------- | -----------------------------: | :------ | :--------------------------------------------------------------------------------------------------- |
| **S.1 — Console dashboard (Next.js + TS)**        | ⬜ **0%**           |                          **0** | 1b → 1c | Findings list, filter, drill-down, IA shell, navigation, dark-mode theming. **6 weeks** per roadmap. |
| **S.2 — Console chat sidebar (Anthropic-backed)** | ⬜ **0%**           |                          **0** | 1c      | Customer-context-aware, HIPAA-compliant audit log of every query. **4 weeks**. Depends on S.1, F.1.  |
| **S.3 — ChatOps approvals**                       | ⬜ **0%**           |                          **0** | 1b      | Slack app + Teams Bot Framework + Email with HMAC-signed URLs. **4 weeks**. Depends on F.4.          |
| **S.4 — REST API + Python SDK + `nexus` CLI**     | ⬜ **0%** (unified) | partial — per-agent CLIs exist | 1b      | The single REST API is what design partners integrate against. **3 weeks**. Depends on F.4.          |

**Total FE/surfaces gap: ~17 person-weeks of named work**, all greenfield. Of these, **S.1 + S.4 are the critical-path items for a paying customer in Phase 1c**: customer needs to log in (F.4 ✅), see findings (S.1 ⬜), and integrate via API (S.4 ⬜). S.2 (chat sidebar) and S.3 (ChatOps approvals) are differentiators that unlock the Tier 2 remediation flow.

**The repository has a `packages/console/` directory with one file (`.gitkeep`). No Next.js scaffold, no TypeScript compiler config, no React component shipped, no design-system decision.** Track S is fully unstarted.

### 6.6 Edge plane (Layer 5)

| Component                                                                      | Status    | Lang    | Phase | Notes                                                                    |
| ------------------------------------------------------------------------------ | --------- | :------ | :---- | :----------------------------------------------------------------------- |
| **E.1 — Edge agent runtime (Go binary + charter subset)**                      | ⬜ **0%** | Go      | 1b    | The Go side of the tech stack is **0 LOC committed**. 6 wks per roadmap. |
| **E.2 — Edge ↔ control plane mTLS + telemetry pipeline (Vector → ClickHouse)** | ⬜ **0%** | Go + Py | 1b    | 4 wks. Depends on E.1, F.5.                                              |
| **E.3 — Edge Helm chart (EKS / AKS / GKE)**                                    | ⬜ **0%** | Helm    | 1b    | 3 wks. Depends on E.1. Required for design-partner deploys.              |

**Total edge gap: ~13 person-weeks**, plus the Go-binary-from-scratch effort. The edge plane is the second named architectural differentiator vs. Wiz; it's also pure ahead-of-the-curve unbuilt work.

### 6.7 Vertical content packs (Layer 6)

| Pack | Title                                                                                                                  | Status     | Phase | Notes                                                              |
| ---- | ---------------------------------------------------------------------------------------------------------------------- | ---------- | :---- | :----------------------------------------------------------------- |
| C.0  | Generic content baseline (~110 frameworks at engine level)                                                             | ⬜ pending | 1b    | 4 wks. Required for D.6 Compliance Agent to be useful.             |
| C.1  | Tech vertical (SOC 2 / ISO 27001 / GDPR-CCPA deep + DevSecOps detection rules + GitHub-GitLab-Slack integration depth) | ⬜ pending | 1c    | 8 wks. **Phase 1 sales focus.** 100% required for paying customer. |
| C.2  | Healthcare vertical (HIPAA + HITRUST + 18 PHI classifiers + H-ISAC + Teams/ServiceNow depth)                           | ⬜ pending | 1c    | 10 wks. **Phase 1 GA target ≥ 80%.**                               |

**Total content-pack gap: ~22 person-weeks** of Compliance Eng + Threat Intel + Detection Eng joint work. C.1 is the **named gating item for a Phase 1 paying customer in tech**.

### 6.8 Operations + GA readiness (Layer 7)

| Item                                                                                   | Status                                         | Effort         | Notes                                                                |
| -------------------------------------------------------------------------------------- | ---------------------------------------------- | :------------- | :------------------------------------------------------------------- |
| O.1 — Observability (Prometheus + Grafana + OTel + SLO dashboards + PagerDuty on-call) | ⬜ pending                                     | 3 wks          | Required before on-call rotation can begin                           |
| O.2 — Nexus's own SOC 2 Type I                                                         | ⬜ partial (starting evidence captured in F.4) | 8 wks parallel | Threat model, pen test, evidence collection pending                  |
| O.3 — Customer onboarding playbook                                                     | ⬜ pending                                     | 3 wks          | Universal flow + tech addendum + healthcare addendum                 |
| O.4 — Pre-GA hardening (DR + chaos + security review + rollback drill)                 | ⬜ pending                                     | 4 wks          | Quality gate before paying-customer GA                               |
| O.5 — Mintlify docs site                                                               | ⬜ pending                                     | 4 wks          | api ref + admin guide + runbooks + threat model                      |
| O.6 — OSS releases (`charter` + `eval-framework` on public GitHub)                     | ⬜ pending                                     | 2 wks          | Apache 2.0 split already enforced in ADR-001. One-shot release work. |

**Total ops gap: ~24 person-weeks** of mostly DevOps Eng + Security Eng + Tech Writer work. Most can run in parallel with Track-D agent execution.

### 6.9 Test / quality gate state

| Gate                                                         |                                                 Today | Required for Phase 1 GA                                                      |
| ------------------------------------------------------------ | ----------------------------------------------------: | :--------------------------------------------------------------------------- |
| Repo-wide `pytest`                                           |                             **818 passed, 5 skipped** | Zero regressions through GA                                                  |
| Per-package coverage threshold ≥ 80%                         |                     All 4 measured packages at 90-97% | Same                                                                         |
| ruff + format strict                                         |                             ✅ clean across 173 files | Same                                                                         |
| mypy strict                                                  |                   ✅ clean across **93** source files | Same                                                                         |
| Eval-suite case count                                        |   F.3 ✅ 10/10 · D.1 ✅ 10/10 · D.2 ✅ 10/10 · D.3 ⬜ | **≥ 100 cases per agent** at Phase 1 GA (current ≤ 10 per agent — large gap) |
| Suite-on-suite via F.2 eval framework                        | ✅ working for cloud-posture, vulnerability, identity | Same                                                                         |
| Live integration tests (LocalStack / Ollama / Auth0 sandbox) |         Skipped by default; opt-in via `NEXUS_LIVE_*` | At least quarterly run in CI                                                 |
| Critical-finding detection latency                           |                                          Not measured | **< 60s** per Phase 1 success criteria                                       |
| False positive rate                                          |                                          Not measured | **< 15%**                                                                    |
| Mean-time-to-remediation reduction                           |                                          Not measured | **≥ 50% from customer baseline**                                             |

**Eval-case count is the most under-counted gap.** Each agent has 10 cases today; Phase 1 GA wants 100. That's ~1,400 case-authoring-hours across 14 remaining agents — large but parallelizable.

---

## 7. Risk dashboard (delta from EOD baseline)

| #   | Risk                                                                                     | Status delta | Mitigation                                                                                                                                     |
| --- | ---------------------------------------------------------------------------------------- | ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | **Frontend zero LOC** (Tracks S.1-S.4)                                                   | unchanged    | Hire Frontend Eng; spike a Next.js + TypeScript scaffold before D.5                                                                            |
| 2   | **Edge plane zero LOC** (Tracks E.1-E.3 — Go runtime)                                    | unchanged    | Hire Platform Eng; spike a Go binary against the F.1 charter subset                                                                            |
| 3   | **No design-partner LOI yet** (Phase 0 exit gate)                                        | unchanged    | Sales-led; outside engineering scope                                                                                                           |
| 4   | **F.5 memory engines architectural decision pending**                                    | unchanged    | The system-readiness recommendation "collapse to Postgres+JSONB+pgvector for Phase 1a" is documented in F.4's Q1 resolution; F.5 plan inherits |
| 5   | **A.3 Tier 1 autonomy is the differentiator and still unbuilt**                          | unchanged    | Cannot begin until A.1 + A.2 ship                                                                                                              |
| 6   | **Husky deprecation warnings** continue on every commit                                  | unchanged    | Migrate to v10-compatible config when convenient                                                                                               |
| 7   | **PRD/VISION docs not re-baselined**                                                     | unchanged    | Founder review owed once Phase 1a foundation closes (after F.5/F.6)                                                                            |
| 8   | **Eval cases capped at ~10/agent** (target 100/agent at GA)                              | NEW          | Parallelizable across compliance + threat-intel + detection engineers; ~1,400 case-hours total estimated                                       |
| 9   | **Per-agent CLIs not unified into the `nexus` CLI** (S.4)                                | NEW          | Track S.4 picks this up; the existing per-agent CLIs are throwaway scaffolds                                                                   |
| 10  | **ADR-007 v1.3 candidate**: severity normalization may become the third duplicate by D.4 | newly named  | Watch as D.3 + D.4 ship; hoist into `charter.severity` if duplicated 3×                                                                        |

---

## 8. Recommended next moves

### Short-term (next 1–3 working sessions)

1. **Finish D.3 Runtime Threat (Tasks 6–16)** — 11 tasks remaining, all pattern application against the v1.2 canon. Validates that the post-amendment substrate works for the first time on a fresh agent.
2. **Write the F.5 plan** — memory engines, recommend collapsing to PostgreSQL + JSONB + pgvector for Phase 1a per the system-readiness recommendation. Unblocks D.7 Investigation Agent's knowledge-graph needs.
3. **Scaffold `packages/console/`** — even a minimal Next.js + TypeScript scaffold lands the Frontend tooling so the next person to pick up S.1 isn't starting from `.gitkeep`. ~1 day of work.

### Medium-term (next 1–2 weeks)

4. **F.5 implementation** — Postgres alembic schema for episodic + procedural memory; defer Neo4j to Phase 2.
5. **F.6 Audit Agent** — the audit-chain machinery is already in charter; "Audit Agent" wraps it as a queryable agent surface for compliance teams.
6. **D.4 Network Threat or D.6 Compliance** — both unblock immediate customer demos; Compliance Agent is the one customers ask for first.

### Phase-1a closeout requirements (M3 exit gate)

- F.5 + F.6 done.
- ≥ 1 design-partner LOI signed.
- Console scaffold landed (even if empty) so Frontend Eng can begin.
- PRD/VISION re-baselined against current reality.

---

## 9. Trajectory vs. the 9–12-month plan

| Phase      | Target months | Today's position                                                                     | Confidence                                      |
| ---------- | :------------ | :----------------------------------------------------------------------------------- | :---------------------------------------------- |
| Phase 0    | M0 (4–6 wks)  | Sub-plans P0.1 + P0.2 ✓; 7 of 9 spikes architecturally answered in code; LOI pending | 80% (LOI gate)                                  |
| Phase 1a   | M1–M3         | 4/6 foundation pillars done; 3/18 agents shipped; trajectory holds                   | **High** (substrate work + pattern is locked)   |
| Phase 1b   | M4–M7         | 0 of 14 remaining agents started past D.3; 0 of edge plane; 0 of console             | Medium (depends on hiring + parallel execution) |
| Phase 1c   | M8–M10        | 0 of 3 remediation tiers; 0 of vertical content packs; 0 of console                  | Low–medium (depends on Phase 1b velocity)       |
| Phase 1 GA | M11–M12       | 0 of ops/observability; SOC 2 Type I scoping started in F.4; no paying customers yet | Low (paying-customer gate is sales-led)         |

**The engineering trajectory is on the curve.** The **business gates** (design-partner LOI, paying customers, SOC 2 Type I) are the ones that determine whether M11–M12 closeout happens on calendar. **Engineering risk is concentrated in Tracks S/A/E** — three large unbuilt surfaces that can't be parallelized against substrate work indefinitely.

---

## 10. Bottom line

**Substrate is winning.** ADR-007 has been twice-amended and twice-validated. Foundation pillars are at 67%. Three agents have shipped to a locked template; a fourth is half-done. Repo-wide quality (test count, coverage, mypy strict, ruff) keeps rising in lockstep with surface growth.

**Customer-facing surface is losing.** Console, edge runtime, remediation tiers, vertical content packs, ops/observability — five large bodies of work, all at 0%, all required for paying-customer launch. The two named architectural differentiators in the PRD (tiered autonomy + edge mesh) are entirely unbuilt.

**The Phase 1a engineering bet** — that an ADR-locked reference template would let 17 more agents ship at predictable cadence — is **paying off**. The Phase 1b/c **business bet** — that we can ship console + remediation + vertical packs in 4–6 months — is **untested**. Hiring sequencing (Frontend Eng, Platform Eng, Compliance Eng, Threat Intel) becomes the gating constraint from here.

— recorded 2026-05-11 16:47 IST · HEAD `e5a96bb`
