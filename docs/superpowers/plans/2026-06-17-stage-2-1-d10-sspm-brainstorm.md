# D.10 SSPM — v0.4 Stage 2 brainstorm (net-new agent)

**Date:** 2026-06-17 · **Stage:** 2 (opens after Stage 1 closed at #734) · **Status:** FOR OPERATOR REVIEW
**Operator decision in force:** Q-v0.4-1 DEPTH-FIRST · Q-v0.4-5 BOTH D.10 + D.11 · R-6 "sequence Salesforce/GitHub/Slack first"

SSPM = **SaaS Security Posture Management**: discover SaaS application posture —
configurations, identities, OAuth integrations, data-sharing — across an org's SaaS
estate, emit OCSF posture findings, and write the SaaS inventory onto the fleet graph
spine (the first consumer of the scaffolded `SAAS_TENANT`/`OAUTH_APP`/`SAAS_USER` nodes).

---

## 1. What's reusable vs net-new (recon, 2026-06-17)

**Reusable (no new infra):**

- **Protocol + fake-injection test pattern** — `GraphReader`/`_HttpGraphReader`
  ([identity/tools/azure_ad.py](../../../packages/agents/identity/src/identity/tools/azure_ad.py))
  and `HttpTransport`/`HttpPoller`
  ([threat-intel/tools/http_poller.py](../../../packages/agents/threat-intel/src/threat_intel/tools/http_poller.py)).
  Both are clean seams; tests inject deterministic fakes (no respx, no recorded fixtures —
  the institutional standard). SSPM connectors mirror this exactly.
- **ADR-018 graph vocabulary is already scaffolded** for SaaS: `NodeCategory.SAAS_TENANT`,
  `OAUTH_APP`, `SAAS_USER`; `EdgeType.INTEGRATED_WITH`, `FEDERATED_FROM`, `AUTHORIZED`,
  `SSO_INTO` (+ reuse `MEMBER_OF`, `HAS_ACCESS_TO`, `IDENTITY` from D.2). **D.10 is their
  first writer** — no graph_types edit needed (seal stays empty).
- **`KnowledgeGraphWriterBase`** (ADR-019) — same base every Stage 1 writer used.
- **OCSF 2003 emission** — re-export `build_finding` from `cloud_posture.schemas` like
  k8s-posture does, or a thin per-agent builder (appsec pattern). Posture-class → 2003.
- **Net-new agent skeleton** — mirror appsec (D.14), the most recent net-new agent:
  `src/sspm/{agent,schemas,kg_writer,eval_runner,cli}.py` + `tools/` + `tests/` + `eval/cases/`,
  workspace member in root `pyproject.toml`, `nexus_eval_runners` entry-point.

**Net-new (the real work):**

- **Per-SaaS connectors** — no Okta/M365/Google Workspace/Slack/GitHub-org/Salesforce
  readers exist anywhere. Greenfield, one `tools/<provider>.py` per connector.
- **SaaS credential resolution** — charter `CredentialResolver` is **cloud-only**
  (AWS/Azure/GCP). SaaS auth is OAuth2 client-credentials / API-token / PAT. Net-new
  `SaaSCredentialResolver` following the existing contract (store only a _source
  identifier_; the token itself comes from env/secret-source per call, **never persisted**).
- **Posture rule packs** per connector (the depth).
- **kg_writer** SaaS domain methods (tenant/user/oauth-app nodes + the 4 SaaS edges).

---

## 2. Proposed v0.4 scope (DEPTH-FIRST)

Depth-first (Q-v0.4-1) means **few connectors, real depth**, not all six shallow. The
directive names six providers but recommends sequencing 3 first. I propose v0.4 ships
**three connectors, deep**, with the 4th–6th explicitly deferred to a v0.4 follow-up or v0.5.

**Recommended v0.4 connector set (see Q1 — operator locks):**

| Connector         | Why first                                                                                                                                                    | Auth                       | Reuse                                                 |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------- | ----------------------------------------------------- |
| **GitHub org**    | Cleanest REST API + PAT; highest security signal (org 2FA, OAuth-app/PAT grants, repo visibility, deploy keys); de-risks the agent fastest                   | PAT / GitHub App token     | new `tools/github_org.py` (httpx via `HttpTransport`) |
| **Microsoft 365** | **Reuses the Azure AD `GraphReader`** verbatim (Graph API) — lowest net-new cost; high coverage (admin roles, MFA/CA policy, external sharing, OAuth grants) | Graph (client-credentials) | reuse `GraphReader` Protocol                          |
| **Slack**         | Clean admin API; common shadow-IT/integration surface (workspace settings, OAuth apps, external-shared channels, admin count)                                | bot/admin token            | new `tools/slack.py`                                  |

This set maximizes **reuse (M365 → GraphReader)** + **fast de-risk (GitHub PAT)** + **breadth
of posture signal**, while honoring the directive's "GitHub/Slack first" steer. Salesforce
(richer OAuth model, R-6 complexity) + Google Workspace + HubSpot → **deferred** (next D.10
slice). _If the operator prefers the directive's literal "Salesforce first," that's Q1._

**Posture depth per connector (the "depth-first" deliverable):** ~6–10 real posture
checks each (e.g. GitHub: org 2FA-required off, OAuth-app access policy unrestricted,
overly-broad PAT/deploy-key, public repos in private org, no SSO enforcement). Each check
→ one OCSF 2003 finding with a stable `finding_id` token.

---

## 3. Fleet-graph contribution (the spine win)

Per the catalogue, D.10 owns SaaS-tenant nodes and bridges to cloud identity:

- **Nodes:** `SAAS_TENANT` (provider, tenant_id, admin_count, mfa_enforcement),
  `SAAS_USER` (provider, user_id, roles, mfa_status), `OAUTH_APP` (app_id, scopes,
  authorized_by). Misconfig findings stay OCSF (not separate nodes) — consistent with the
  Stage 1 writers.
- **Edges:**
  - `AUTHORIZED`: OAuth app → SaaS tenant (with scope) — the shadow-integration surface.
  - `MEMBER_OF`: SaaS user → SaaS tenant.
  - `FEDERATED_FROM`: IdP → account (D.10 surfaces federation **config**; D.2 owns the
    federated-identity **computation** — boundary in Q4).
  - `SSO_INTO` / `INTEGRATED_WITH`: SaaS → cloud account — **cross-domain bridge**, the
    D.10 analogue of D.6's IRSA bridge. The cloud-account side is a `CLOUD_RESOURCE`/account
    node the posture agents own → resolves on the **same coherent spine** Stage 1 built.

This is the high-value payoff: an over-scoped OAuth app or an SSO path from a SaaS tenant
into a cloud account becomes a traversable subgraph for Stage 3 correlation.

---

## 4. Swiss bar (unchanged)

- Net-new agent, **seal empty** (graph_types already has the SaaS vocab; no charter edit).
- **Opt-in `semantic_store`** (default None inert → `findings.json` byte-identical offline).
- **Real-backend tests**: `Protocol` + deterministic fake connectors (no live SaaS in CI);
  in-memory `SemanticStore` for the kg*writer e2e. Live connectors behind `NEXUS_LIVE_SSPM*\*`.
- **No reverse-parsing OCSF** — kg_writer reads the typed connector inventory, not findings.
- OCSF 2003, NexusEnvelope-wrapped, stable `finding_id` tokens (ADR-010).
- **Secrets never persisted** — `SaaSCredentialResolver` stores only the source identifier.

---

## 5. Proposed PR sequence (self-merge cascade, sequence-via-main)

1. **PR1 — skeleton + SaaSCredentialResolver + schemas** (agent package, OCSF 2003 builder,
   `SaaSCredentialResolver` contract, empty `build_registry`/`run`, eval_runner stub).
2. **PR2 — GitHub-org connector + posture rules + OCSF emission** (first deep connector, full tests).
3. **PR3 — M365 connector (reuse GraphReader) + posture rules.**
4. **PR4 — Slack connector + posture rules.**
5. **PR5 — kg_writer (SAAS_TENANT/SAAS_USER/OAUTH_APP + AUTHORIZED/MEMBER_OF/FEDERATED_FROM/SSO_INTO) + spine e2e.**
6. **PR6 — eval golden cases + integration (multi-connector + multi-tenant) + close record.**

Each PR: real backend (fake-connector), real tests, opt-in, seal empty, ruff+mypy clean.

---

## 6. Open questions for the operator (Q-set)

- **Q1 — connector set.** Lock the v0.4 depth-first connectors. _Rec: GitHub-org + M365 +
  Slack_ (reuse + fast de-risk). Alternative: directive's literal _Salesforce + GitHub + Slack_.
  Which three (or two)? What's deferred?
- **Q2 — OCSF class.** Confirm **2003** (posture-class, consistent with F.3/D.5/D.6/compliance/appsec).
  Any reason for a distinct class? _Rec: 2003._
- **Q3 — SaaS credential model.** OK to add a net-new `SaaSCredentialResolver` (OAuth2
  client-credentials / API-token / PAT), tokens sourced from env/secret-source per call,
  never persisted — mirroring the cloud `CredentialResolver` contract? _Rec: yes._ Should it
  live in the agent package or be hoisted to charter (it's the first SaaS auth — Path-B says
  hoist on 2nd consumer, so agent-local now)?
- **Q4 — D.2 identity boundary.** Confirm D.10 surfaces federation **config** + writes
  `FEDERATED_FROM`/`SSO_INTO` edges, while D.2 owns federated-identity **computation** and the
  IdP user nodes. (Okta/Azure-AD are read by both — D.10 for tenant posture, D.2 for identity.)
- **Q5 — inventory depth for v0.4.** Ship all three node types (tenant/user/oauth-app) + all
  four edges, or start with tenant + oauth-app + `AUTHORIZED`/`SSO_INTO` and defer SaaS-user
  enumeration (can be large) to a follow-up? _Rec: tenant + oauth-app + AUTHORIZED/SSO_INTO
  first; user enumeration in PR5b._
- **Q6 — review mode.** Self-merge cascade (like the Stage 1 net-new writers), or per-PR
  review on PR1 (skeleton + new credential resolver) then cascade? _Rec: per-PR review on PR1
  (new resolver contract), self-merge PR2-6._

---

## 7. Non-goals (v0.4)

- Cloud resources SaaS integrates with (D.3/D.5 own) — D.10 only writes the bridge edge.
- Code-as-code (D.14 appsec / D.9) — D.10 covers GitHub **org-level** settings only.
- Federated-identity **computation** (D.2) — D.10 surfaces config only.
- Salesforce / Google Workspace / HubSpot connectors — deferred (next slice / v0.5).
- SaaS DLP content scanning (DSPM/D.5 territory).
