# D.11 AI-SPM — v0.4 Stage 2 brainstorm (net-new agent)

**Date:** 2026-06-17 · **Stage:** 2 (2nd workstream, after D.10 SSPM closed #741) · **Status:** FOR OPERATOR REVIEW
**Scope LOCKED (directive §2b.2):** (a) AI deployment discovery + (b) prompt-injection detection (Garak + PyRIT + LLM Guard). (c) model-file scanning + (d) training-data sensitivity → **v0.5**. Trigger #47 pauses on mid-impl scope divergence.

AI-SPM = discover the org's AI/ML deployments (models + inference endpoints) across cloud
AI services, assess their posture, and (b) detect prompt-injection exposure — writing the
AI inventory onto the coherent ADR-018 spine (first consumer of the scaffolded `AI_SERVICE`/
`AI_MODEL` vocab).

---

## 1. What's reusable vs net-new (recon, 2026-06-17)

**Reusable (no new infra) — seal stays EMPTY:**

- **ADR-018 AI vocab already scaffolded:** `NodeCategory.AI_SERVICE` + `AI_MODEL`; `EdgeType`
  `SERVES_MODEL` / `EXPOSES_MODEL` / `HOSTS_AI` / `TRAINED_ON` / `INFERENCES_LOGGED_TO` /
  `INVOKED_BY`. **D.11 is the first writer — no graph_types edit.**
- **Cloud `CredentialResolver`** (charter, hoisted) + concrete subclasses: AWS boto3
  ([identity/credentials.py]), Azure ([identity/credentials_azure.py]), GCP
  ([multi-cloud-posture/credentials_gcp.py]). Discovery reads Bedrock/SageMaker (boto3),
  Azure OpenAI (azure SDK), Vertex (google SDK) through these — no new credential type.
- **D.10 SSPM template**: agent skeleton, `run()` shape, `ctx.call_tool` connector routing,
  `HttpTransport`/`GraphClient` Protocol + fake-injection tests, OCSF 2003 `build_finding` +
  `finding_id` regex, `KnowledgeGraphWriterBase` kg_writer, eval_runner + golden cases.
- **Subprocess-tool pattern** (trivy / prowler / kube-bench): async `create_subprocess_exec`
  - timeout + JSON parse + typed `Result` dataclass + injectable runner seam → the shape for
    **Garak** (a CLI red-teamer).
- **LLM plumbing** (if needed for narrative): `charter.llm` / `llm_adapter` + the hoisted
  invariants `assert_categorical_only` / `assert_bounded_retry` (`nexus_runtime.llm_invariants`).

**Net-new (the real work):**

- Per-cloud **AI-service discovery readers** (Bedrock, SageMaker, Azure OpenAI, Vertex) — none exist.
- **AI posture rule packs** (public endpoint, no auth, network exposure, logging off, no guardrail).
- **Garak** subprocess integration (gated active red-team) + parser → OCSF 2004.
- **kg_writer** AI domain methods (`AI_SERVICE`/`AI_MODEL` + edges).
- Tool **deps** — Garak/PyRIT/LLM-Guard declared nowhere (heavy; see Q6).

---

## 2. Proposed v0.4 scope (DEPTH-FIRST)

**(a) Deployment discovery — AWS-first, then Azure + GCP.** AWS (Bedrock + SageMaker) is the
deepest reuse (boto3) and most common; recommend it as connector #1, Azure OpenAI #2, Vertex
#3 (mirrors D.10's "deepest-reuse-first" sequencing). ~6-8 posture checks per cloud, e.g.:

- SageMaker endpoint **not in a VPC** / publicly reachable → HIGH (`EXPOSES_MODEL`).
- SageMaker endpoint **data-capture (inference logging) off** → MEDIUM.
- Bedrock model invocation **logging disabled** → MEDIUM.
- Bedrock **guardrail not attached** to a model/agent → MEDIUM.
- Endpoint **without KMS-CMK encryption** → LOW/MEDIUM.
- Azure OpenAI deployment **public network access enabled** → HIGH.
- Vertex endpoint **public** / no VPC-SC → HIGH.

→ OCSF **2003** (posture), `finding_id` `AISPM-<PROVIDER>-<NNN>-<context>`.

**(b) Prompt-injection detection — Garak first (gated), PyRIT/LLM-Guard as follow-ups.** Garak
is a CLI probe-runner (subprocess, trivy-shaped) that red-teams a model endpoint with
injection/jailbreak probes. It is **active** (sends adversarial prompts → cost + safety), so
it runs **only behind `NEXUS_LIVE_AISPM_PROBE=1`** against a **discovered cloud endpoint**
(reusing the same cloud creds — no external API key, so no new credential type). Parsed Garak
hits → OCSF **2004** (Detection). PyRIT (Microsoft red-team, heavy Python dep) + LLM-Guard
(guardrail-config/static check) → **v0.4 follow-up or v0.5** depending on Q2/Q6.

---

## 3. Fleet-graph contribution (the spine win)

- **Nodes:** `AI_SERVICE` (Bedrock/SageMaker/Azure-OpenAI/Vertex deployment), `AI_MODEL`
  (the served model), keyed `{provider}:{account}:{kind}:{id}`.
- **Edges:**
  - `SERVES_MODEL`: endpoint → model.
  - `EXPOSES_MODEL`: endpoint → internet (when public) — the headline risk edge.
  - `HOSTS_AI`: cloud compute/account → AI service — the **cross-domain bridge** to the
    `CLOUD_RESOURCE`/account nodes the posture agents own (D.11's analogue of D.6's IRSA
    bridge), closing on the same coherent spine. Drawable now because discovery yields the
    owning account id.
  - `INFERENCES_LOGGED_TO` (endpoint → capture bucket) + `TRAINED_ON` (model → dataset) —
    ship **when discovery surfaces the target id**; else surface as follow-up (no fabrication).

This makes "a publicly-exposed model endpoint on account X with logging off" a traversable
subgraph for Stage 3 correlation — the AI bucket the competitive benchmark flagged at 0%.

---

## 4. Swiss bar (same as D.10)

- Net-new agent, **seal empty** (AI vocab already in ADR-018; no charter edit).
- **Opt-in `semantic_store`** (default None inert → byte-identical offline).
- **Real backends**: cloud AI SDKs behind injectable seams + deterministic fakes (no live
  cloud in CI; moto for AWS where it supports the service, else fake readers). Garak behind a
  subprocess-runner seam (fakes in CI; live probing `NEXUS_LIVE_AISPM_PROBE`-gated).
- **No reverse-parsing OCSF** — kg_writer reads typed inventories.
- Honest tri-state (unknown config never flags). kg_writer subclasses `KnowledgeGraphWriterBase`.

---

## 5. Proposed PR sequence

1. **PR1 — skeleton + OCSF schemas (2003 + 2004)** + agent run() + empty registry. (Review: see Q7.)
2. **PR2 — AWS discovery (Bedrock + SageMaker)** connector + posture rules → 2003.
3. **PR3 — Azure OpenAI + GCP Vertex** discovery + posture rules.
4. **PR4 — Garak prompt-injection** (subprocess, gated) → 2004. (Active red-team = safety-sensitive; review per Q7.)
5. **PR5 — kg_writer** (`AI_SERVICE`/`AI_MODEL` + `SERVES_MODEL`/`EXPOSES_MODEL`/`HOSTS_AI`).
6. **PR6 — eval + integration + close record.**

---

## 6. Open questions for the operator (Q-set)

- **Q1 — discovery cloud scope/order.** _Rec: AWS (Bedrock+SageMaker) → Azure OpenAI → Vertex_
  (deepest reuse first). All three in v0.4, or AWS+Azure with Vertex→follow-up?
- **Q2 — prompt-injection tooling.** Directive names Garak + PyRIT + LLM-Guard. _Rec: Garak
  (CLI subprocess, gated) in v0.4; PyRIT + LLM-Guard as a v0.4 follow-up / v0.5_ — PyRIT is a
  heavy Python red-team lib and LLM-Guard is a guardrail lib (both pull torch/transformers).
  Ship all three in v0.4, or Garak-first?
- **Q3 — OCSF classes.** _Rec: 2003 for discovery/posture, 2004 for prompt-injection detection_
  (formalize in ADR-020). Confirm the 2003/2004 split.
- **Q4 — credentials.** Discovery + Garak-probing target **cloud-deployed** endpoints → reuse
  the cloud `CredentialResolver` (no new credential type, **seal stays empty**). Probing
  **external** SaaS LLM APIs (OpenAI/Anthropic public) would need the SaaS env-token resolver
  → the **2nd consumer → Path-B hoist of `SaaSCredentialResolver` to charter** (a substrate
  PR). _Rec: v0.4 probes only discovered cloud endpoints (no hoist); defer external-API
  probing + the hoist until needed._ Confirm.
- **Q5 — kg edges for v0.4.** \*Rec: `AI_SERVICE` + `AI_MODEL` + `SERVES_MODEL` + `EXPOSES_MODEL`
  - `HOSTS_AI` (cross-domain bridge to cloud account).\* `TRAINED_ON`/`INFERENCES_LOGGED_TO`
    ship when discovery surfaces the target id, else follow-up. OK?
- **Q6 — heavy ML deps.** Garak/PyRIT/LLM-Guard pull torch/transformers. _Rec: Garak via
  **subprocess** (no Python dep on the core workspace); PyRIT/LLM-Guard as **optional extras**
  or deferred — never in the core dependency set._ Confirm the no-bloat constraint.
- **Q7 — review mode.** Directive classifies D.11 **per-PR review**. _Rec: per-PR review on PR1
  (skeleton/schemas) + PR4 (active red-team, safety-sensitive); self-merge cascade for the
  discovery connectors PR2/PR3/PR5/PR6._ Or full per-PR review like the directive's default?

---

## 7. Non-goals (v0.4)

- (c) model-file scanning + (d) training-data sensitivity → v0.5 (locked).
- Underlying compute/storage hosting AI (D.3/D.5 own; D.11 adds only the AI-classification layer + `HOSTS_AI` bridge).
- Training-data content classification (D.4 owns; D.11 connects lineage when available).
- External SaaS-LLM-API probing + the `SaaSCredentialResolver` charter hoist (until a real consumer needs it).
- OSS framework inventory (MLflow / HuggingFace / LangChain / vector stores) — catalogue-listed but → a later slice.
