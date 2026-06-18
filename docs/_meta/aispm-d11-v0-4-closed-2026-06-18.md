# D.11 AI-SPM v0.4 — cycle close record

**Date:** 2026-06-18 · **Stage:** 2 (2nd workstream, after D.10 SSPM) · **Status:** CLOSED (pending #748 merge)
**Brainstorm:** #742 · **ADR:** ADR-020 · **PRs:** #743 (PR1) → #744 (PR2) → #745 (PR3) → #746 (PR4) → #747 (PR5) → #748 (PR6)

## What shipped

D.11 AI-SPM — a **net-new** AI Security Posture Management agent — locked dual scope
(operator): **(a) deployment discovery + (b) prompt-injection detection**. Discovers AI/ML
deployments across AWS/Azure/GCP, assesses posture (OCSF 2003), red-teams discovered
endpoints with Garak (OCSF 2004), and writes the AI inventory onto the coherent ADR-018 spine.

| PR   | Deliverable                                                                                                                 |
| ---- | --------------------------------------------------------------------------------------------------------------------------- |
| #743 | Skeleton + **dual-class OCSF schemas** (2003 posture + 2004 detection) + **ADR-020**. Per-PR review (Q7).                   |
| #744 | **AWS** discovery (SageMaker + Bedrock) + 6 posture checks.                                                                 |
| #745 | **Azure OpenAI** (4 checks) + **GCP Vertex** (3 checks) discovery.                                                          |
| #746 | **Garak** prompt-injection probe (subprocess, gated) → OCSF 2004. Per-PR review (Q7 — active red-team).                     |
| #747 | **kg_writer** — `AI_SERVICE`/`AI_MODEL` + `SERVES_MODEL`/`EXPOSES_MODEL`/`HOSTS_AI` (first consumer of ADR-018's AI vocab). |
| #748 | **Eval** runner + 4 golden cases + multi-cloud/multi-tenant integration + this record.                                      |

**Total:** 13 OCSF 2003 posture checks (AWS 6 / Azure 4 / Vertex 3) + Garak-driven 2004
prompt-injection; ~28 package tests.

## Decisions honored (Q-set, #742)

- **Q1** cloud scope: AWS → Azure → Vertex (all three). **Q2** Garak-only via subprocess;
  **PyRIT + LLM-Guard → v0.5** (torch weight not justified). **Q3** OCSF 2003 discovery +
  2004 prompt-injection (ADR-020). **Q4** cloud `CredentialResolver` only — **no SaaS-resolver
  hoist**, external-API probing → v0.5, **seal stays empty**. **Q5** 5 core edges
  (`AI_SERVICE`+`AI_MODEL`+`SERVES_MODEL`+`EXPOSES_MODEL`+`HOSTS_AI`);
  `TRAINED_ON`/`INFERENCES_LOGGED_TO` opportunistic. **Q6** no torch in core (Garak subprocess;
  cloud SDKs only). **Q7** per-PR review on PR1 + PR4; self-merge PR2/3/5/6.

## Swiss bar (held every PR)

Real cloud SDKs behind injectable `Reader`/`GraphClient`/`GarakRunner` seams + deterministic
fakes (no live cloud/garak in CI; live paths gated, active probe behind
`NEXUS_LIVE_AISPM_PROBE`). No torch in the core dependency set. Tokens/creds never persisted;
`call_tool` audits only kwarg key names. kg_writer reads typed inventories, never OCSF dicts.
Honest tri-state — unknown config never flags. Substrate **seal empty** the whole cycle
(ADR-018 AI vocab `AI_SERVICE`/`AI_MODEL` + edges already scaffolded; D.11 is its first
consumer). ruff + mypy clean throughout.

## Honest deferrals (v0.5)

1. **(c) model-file scanning + (d) training-data sensitivity** — locked out of v0.4.
2. **PyRIT + LLM-Guard** (Q2) — torch-heavy; Garak subprocess covers v0.4 prompt-injection.
3. **External SaaS-LLM-API probing** + the `SaaSCredentialResolver` charter hoist (Q4) — v0.4
   probes only discovered cloud endpoints (cloud creds).
4. **`TRAINED_ON` / `INFERENCES_LOGGED_TO`** edges — drawn when discovery surfaces the
   dataset / capture-bucket id (not yet collected); surfaced, not faked.
5. OSS framework inventory (MLflow / HuggingFace / LangChain / vector stores) — later slice.

## Fleet impact

D.11 + D.10 (SSPM) close the two **net-new breadth agents** the competitive benchmark flagged
at 0% (AI + SaaS). Both write onto the same coherent ADR-018 spine — `HOSTS_AI` (AI→cloud
account) and `IRSA_MAPPING`/`AUTHORIZED` join AI, K8s, cloud, and SaaS identity into one graph.

## Next

Stage 2 continues: **Hermes 2-5**. Pending operator (carried): compliance D.6→D.9 +
multi-cloud-posture rename; Wazuh 12-item spec; D.10 SSO_INTO (→v0.5).
