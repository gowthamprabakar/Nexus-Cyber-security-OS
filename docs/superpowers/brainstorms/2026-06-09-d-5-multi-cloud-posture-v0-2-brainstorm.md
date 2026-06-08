# D.5 Multi-Cloud Posture v0.2 — brainstorm (Azure + GCP live + native rule engines) (2026-06-09)

> **Investigation only.** Second cycle on the strict-serial detection track (γ sequencing), after [F.3 v0.2 closed](../../_meta/f-3-cloud-posture-v0-2-verification-2026-06-08.md) (#267). D.5 is the **non-AWS** cloud-posture agent (Azure + GCP) per the locked per-agent scope discipline. This doc surfaces findings across 7 axes + proposes **7 Q-locks for operator decision**. **No plan doc, no code, no execution** — the plan doc follows once Q-locks are locked. Template mirrors the [F.3 v0.2 brainstorm](2026-06-07-f-3-cloud-posture-v0-2-brainstorm.md) (#246).

---

## §1. Axis 1 — Current state of D.5 (ground truth from `main` HEAD)

`packages/agents/multi-cloud-posture/`, **v0.1.0**, **fully offline**.

- **Dependencies** ([`pyproject.toml`](../../../packages/agents/multi-cloud-posture/pyproject.toml)): `nexus-charter`, `nexus-shared`, `nexus-eval-framework`, **`nexus-cloud-posture`** (← already depends on F.3), pydantic/pyyaml/click/structlog. **No `azure-mgmt-*`, no `google-cloud-*`** → live SDKs are the v0.2 work.
- **Architecture** ([`agent.py`](../../../packages/agents/multi-cloud-posture/src/multi_cloud_posture/agent.py)): charter + **4 readers + 2 normalizers + summarizer**, ADR-007-compliant (mirrors F.3's shape: NLAH, `eval_runner`, OCSF emission). `run(contract, *, azure_findings_feed, azure_activity_feed, gcp_findings_feed, gcp_iam_feed)` — each reader takes an **optional filesystem JSON path**, skipped if `None`. All 4 tools registered `cloud_calls=0` (offline).
- **The 4 readers:**
  - `read_azure_findings` ([`tools/azure_defender.py`](../../../packages/agents/multi-cloud-posture/src/multi_cloud_posture/tools/azure_defender.py)) — **Microsoft Defender for Cloud passthrough** (assessments/alerts JSON → `AzureDefenderFinding`). **Zero native rules.** Docstring already names the live seam: "Phase 1c live mode swaps the implementation behind this same signature to `azure-mgmt-security`'s `AssessmentsOperations.list`."
  - `read_azure_activity` ([`tools/azure_activity.py`](../../../packages/agents/multi-cloud-posture/src/multi_cloud_posture/tools/azure_activity.py)) — Azure Activity Log ingest, severity pass-through.
  - `read_gcp_findings` ([`tools/gcp_scc.py`](../../../packages/agents/multi-cloud-posture/src/multi_cloud_posture/tools/gcp_scc.py)) — GCP Security Command Center passthrough.
  - `read_gcp_iam_findings` ([`tools/gcp_iam.py`](../../../packages/agents/multi-cloud-posture/src/multi_cloud_posture/tools/gcp_iam.py)) — **the only native rule engine**: ~4–5 IAM-binding rules over Cloud Asset Inventory (`roles/owner` to non-Google-managed → HIGH; `roles/owner` to external `user:*` → CRITICAL; `roles/editor` to `user:*` → MEDIUM; `allUsers`/`allAuthenticatedUsers` public bindings → CRITICAL/HIGH).
- **OCSF 2003:** [`schemas.py`](../../../packages/agents/multi-cloud-posture/src/multi_cloud_posture/schemas.py) already does `from cloud_posture.schemas import (...)` — re-exports the F.3 canonical `class_uid 2003` (confirmed invariant in the F.3 Task 9 sweep, #262).
- **Tests:** **214 passed** (offline). Areas: gcp_iam 21 · gcp_scc 18 · azure_defender 15 · azure_activity 12 · normalizers_azure 16 · normalizers_gcp 14 · + agent/cli/eval/nlah/schemas/smoke/summarizer.

**The structural exposure (benchmark [§5](../../strategy/competitive-benchmark-2026-06-08.md) / §8.5), confirmed:**

- **Azure = a thin reformatter over a competitor's engine** (Defender for Cloud) — **0 native rules**.
- **GCP = ~4–5 native IAM rules** + SCC passthrough — thin, but real.
- **No account/subscription/project scoping yet** — `run()` is feed-path-based, not scope-based (no analog to F.3's account/region threading).

## §2. Axis 2 — Live Azure SDK integration

- **Seam already exists:** swap `read_azure_findings` behind its signature to `azure-mgmt-security` (`AssessmentsOperations.list` / `AlertsOperations.list_by_subscription`). Add `azure-mgmt-*` + `azure-identity` deps.
- **Auth** (→ Q2): `azure-identity` `DefaultAzureCredential` covers Service Principal (env), Managed Identity, and Azure CLI in one chain — the cleanest analog to F.3's boto3-default-chain `CredentialResolver`.
- **Scope** (→ Q6): subscription is Azure's account analog. Single-subscription at v0.2, multi-subscription deferred to v0.3 (mirrors F.3 Q4 current-account-only).
- **Defender** (→ Q7): live `read_azure_findings` still reads Defender — the question is whether Defender stays as a finding _source_ alongside the new native rules, or is dropped.

## §3. Axis 3 — Live GCP SDK integration

- **Seam:** `read_gcp_findings` → `google-cloud-securitycenter`; `read_gcp_iam_findings` → `google-cloud-asset` (Cloud Asset Inventory). Add `google-cloud-*` deps.
- **Auth** (→ Q3): Service Account JSON key (`GOOGLE_APPLICATION_CREDENTIALS`) is the simplest start; Workload Identity Federation is the keyless production path.
- **Scope** (→ Q6): project is GCP's account analog. Project-scoped at v0.2; organization-scoped (folder/org traversal) deferred to v0.3.

## §4. Axis 4 — Native Azure rule engine

- **Today: zero native Azure rules** (§1). This is D.5's single largest exposure — Nexus currently _wraps_ Defender rather than detecting.
- **Proposal:** a native Azure rule engine over Azure Resource Graph / `azure-mgmt-*` resource reads, seeded from the **CIS Microsoft Azure Foundations Benchmark** (mirrors F.3's 3 native boto3 checks over CIS-AWS).
- **Starting corpus** (→ Q4): e.g. storage-account public access, NSG 0.0.0.0/0 inbound, no-MFA/privileged-role, unencrypted disks, key-vault soft-delete — ~5–10 to start; the full CIS-Azure expansion is **v0.3** (same liveness-vs-rule-breadth lesson as F.3 — see [WI-C](../../_meta/f-3-cloud-posture-v0-2-verification-2026-06-08.md)).

## §5. Axis 5 — Native GCP rule engine

- **Today: ~4–5 native IAM-binding rules** ([`tools/gcp_iam.py`](../../../packages/agents/multi-cloud-posture/src/multi_cloud_posture/tools/gcp_iam.py)); 0 non-IAM native rules.
- **Proposal:** grow from ~5 → ~10–15, seeded from the **CIS Google Cloud Platform Foundation Benchmark** — beyond IAM into storage-bucket public access, default-network/firewall, unencrypted disks, audit-logging config.
- **Starting corpus** (→ Q4): ~10–15 at v0.2; full CIS-GCP is v0.3.

## §6. Axis 6 — Hoist consumption (the consumer-count correction)

**Finding that sharpens the directive's framing:** F.3 is the **1st** consumer of its own patterns; **D.5 is the 2nd**; D.2 Identity v0.2 is the likely **3rd**. Per [ADR-007](../../_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md)'s third-consumer rule, the **charter hoist fires at the 3rd consumer (D.2), not at D.5.** So strictly, **D.5 v0.2 should not hoist to `charter`** — and it has a cleaner option than re-implementing: **D.5 already depends on `nexus-cloud-posture`**, so it can **import the cloud-agnostic seams directly from `cloud_posture`** (region-scoping precedence, live-lane gating shape, degradation contract) and supply only per-cloud probes/enumeration. The hoist-to-charter then happens once at D.2 (3rd consumer) with two real adopters proven. Mapped to the [#266 candidates](../../_meta/f-3-cloud-posture-v0-2-hoist-candidates-2026-06-08.md):

| F.3 pattern (#266)            | D.5 need                                    | What D.5 supplies per-cloud                             |
| ----------------------------- | ------------------------------------------- | ------------------------------------------------------- |
| D — live-eval lane gating     | `NEXUS_LIVE_AZURE` / `NEXUS_LIVE_GCP` lanes | Azure ARM / GCP reachability probes                     |
| E — partial-scan degradation  | per-subscription / per-project degradation  | Azure SDK / GCP gax error taxonomy                      |
| C — region scoping precedence | subscription/project/location precedence    | Azure locations / GCP regions enumeration               |
| A — CredentialResolver seam   | Azure + GCP credential resolution           | `DefaultAzureCredential` / GCP ADC                      |
| B — account autodiscovery     | subscription / project discovery            | ARM subscriptions list / Resource Manager projects list |

→ Q1 decides hoist scope vs. import-from-`cloud_posture` vs. re-implement.

## §7. Axis 7 — Cross-cloud OCSF 2003 emission

- OCSF 2003 is cloud-agnostic and **already shared** from `cloud_posture.schemas` (§1) — proven invariant across 5 consumers (#262).
- D.5 must keep emitting `class_uid 2003` for **both** Azure and GCP, mapping: Azure **subscription id** → `account_uid`, Azure **location** → region; GCP **project id** → `account_uid`, GCP **region**. (Both normalizers already emit 2003 offline; live mode must preserve the mapping.)
- **Plan a D.5 v0.2 cross-agent sweep at closure** (Task 9-style, mirror #262) to re-confirm 2003 invariance once live Azure/GCP findings flow.

---

## §8. Proposed Q-locks (operator decides)

> Each: plain statement · options · **recommendation** · rationale. Team proposes; operator locks before any plan doc.

**Q1 — Hoist scope.** Which F.3 patterns move to `charter` in D.5 v0.2?

- (A) all 5 hoist to charter · (B) C+D+E hoist (small effort), A+B deferred · **(C) no charter hoist this cycle — D.5 imports cloud-agnostic seams from `cloud_posture` (it already depends on it) + supplies per-cloud probes.**
- **Recommend (C).** D.5 is the **2nd** consumer; ADR-007 hoists at the **3rd** (D.2). Hoisting now bakes a 2-cloud-shaped abstraction into the substrate with the WI-1 seal cost (SAFETY-CRITICAL PRs) for no third proof point. Importing from `cloud_posture` keeps the seam single-sourced without touching charter — seal stays empty all cycle.

**Q2 — Azure auth primary.** Service Principal vs Managed Identity?

- (A) **`DefaultAzureCredential` chain** (SP-env → Managed Identity → Azure CLI) · (B) Service Principal only · (C) Managed Identity only.
- **Recommend (A).** It's the direct analog to F.3's boto3-default-chain `CredentialResolver` — one seam covers dev (CLI/SP) and prod (MI) without per-environment branching.

**Q3 — GCP auth primary.** Service Account JSON key vs Workload Identity Federation?

- (A) **GCP ADC (Application Default Credentials)** — SA key via `GOOGLE_APPLICATION_CREDENTIALS` in dev, WIF in prod, one chain · (B) SA JSON key only · (C) WIF only.
- **Recommend (A).** Same default-chain principle as Q2; ADC spans SA-key (dev) and WIF (prod) behind one resolver, deferring the keyless-only stance without blocking it.

**Q4 — Native rule starting size per cloud at v0.2 closure.**

- (A) **Azure ~5–10 (from 0) + GCP ~10–15 (from ~5)**, full CIS-Azure/GCP expansion = v0.3 · (B) larger (~20+/cloud) this cycle · (C) Azure-only this cycle, GCP rules in v0.3.
- **Recommend (A).** Mirrors F.3 (a few native CIS checks at v0.2; library expansion at v0.3). Closing Azure's **zero-native-rule** gap is the highest-value move; over-scoping rules risks the cycle. **Honesty pin (WI-C):** v0.2's coverage lift comes from these _new native rules_, not from going live — report it that way.

**Q5 — Live-eval lane naming.** Per #266: `NEXUS_LIVE_AZURE` / `NEXUS_LIVE_GCP`?

- (A) **`NEXUS_LIVE_AZURE=1` + `NEXUS_LIVE_GCP=1`** (separate, independent lanes) · (B) one `NEXUS_LIVE_MULTICLOUD=1` lane · (C) other.
- **Recommend (A).** Matches the #266 convention + F.3's lane-independence contract (#261) — separate gates let Azure and GCP live tests run/skip independently.

**Q6 — Multi-subscription / multi-project at v0.2?**

- (A) **single subscription + single project at v0.2; multi deferred to v0.3** · (B) multi at v0.2 · (C) multi-subscription yes, multi-project no (or vice-versa).
- **Recommend (A).** Direct analog to F.3 Q4 (current-account-only at v0.2; cross-account at v0.3). Multi-scope is the large-effort divergence (#266 Pattern B); keep v0.2 bounded.

**Q7 — Defender-passthrough behavior.**

- (A) **keep Defender as a complementary finding _source_ alongside native rules** (provenance-tagged) · (B) remove Defender entirely once native rules exist · (C) keep but default-off.
- **Recommend (A).** Removing Defender drops real coverage before the native engine is broad; keeping it provenance-tagged (native-rule vs Defender-sourced) is honest and additive. Revisit removal at v0.3 when native CIS-Azure breadth lands.

---

## §9. Out of scope (locked discipline — not in this brainstorm)

Parked per [macro plan §1.5](../../strategy/nexus-agent-maturity-roadmap-2026-06-07.md): ADR-013, Hermes, Wazuh, AppSec/AI-SPM net-new, Surface UI, v2.0 graph. Also out: F.3 v0.3 (post-arc), substrate fixes beyond the parked #253, plan-doc drafting, ownership, timelines.

## §10. Cross-references

- [F.3 v0.2 brainstorm](2026-06-07-f-3-cloud-posture-v0-2-brainstorm.md) (#246, template) · [F.3 v0.2 plan](../plans/2026-06-07-f-3-cloud-posture-v0-2.md) · [F.3 v0.2 verification record](../../_meta/f-3-cloud-posture-v0-2-verification-2026-06-08.md) (#267)
- [F.3 v0.2 hoist-candidate documentation](../../_meta/f-3-cloud-posture-v0-2-hoist-candidates-2026-06-08.md) (#266) — the patterns D.5 consumes
- [ADR-007](../../_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md) (reference agent + third-consumer rule) · [ADR-010](../../_meta/decisions/ADR-010-version-extension-template.md) · [ADR-011](../../_meta/decisions/ADR-011-pr-flow-and-branch-protection-discipline.md)
- [Macro plan](../../strategy/nexus-agent-maturity-roadmap-2026-06-07.md) (§4 sequence) · [Competitive benchmark](../../strategy/competitive-benchmark-2026-06-08.md) (§5 D.5 analysis)

---

— recorded 2026-06-09 (D.5 Multi-Cloud Posture v0.2 brainstorm; investigation-only; 7 axes + 7 Q-locks for operator review; no plan, no code).
