# Attack-Path & Toxic-Combination Expansion — the complete addable scope

**Date:** 2026-07-06 · Written after the 4-cycle operating-path arc landed (#801 ranking-real,
#802 dead-signal, #803 moat-productized, #804 multi-cloud-parity — all on `main`). Operator asked:
_"scope all possible attack paths & toxic combinations we can increase."_ This is the complete,
current menu — reconciled with everything built since the earlier scope maps
(`graph-model-scope-map-2026-06-29.md`, `detection-combination-plan-2026-06-27.md`), which it
supersedes as the live planning surface.

## The frame (why this stays finite, not boil-the-ocean)

Two disciplines from the prior scope map still govern:

1. **The graph powers the paths — invest in edges, not detector count.** A detector's job is to add
   accurate _nodes + edges + properties_; an attack path is a _traversal the graph makes possible_.
   Fund the connective tissue (bridge edges), and Track B's generic engine turns richness into new
   combinations _emergently_ — we don't hand-code every path.
2. **Scope is bounded by MITRE ATT&CK for Cloud**, a finite external technique list. A node/edge
   earns a build only if it participates in ≥1 ATT&CK technique. That is the gate against infinity.

**Edge = provider-agnostic contract; detector = per-cloud implementation.** `CAN_ESCALATE_TO`,
`CAN_REACH`, etc. are cloud-agnostic — the path engine, ranker, Track B, and remediation operate on
them with zero cloud awareness. AWS/Azure/GCP each _populate_ the same edge differently. Build the
edge once; light every cloud.

## Where we are now (reconciled, post-Cycle-4)

| Layer                                       | State                                                                                                                                                                                                                                                                                                                         |
| ------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Vocabulary**                              | ~40 `NodeCategory`, ~72 `EdgeType` defined                                                                                                                                                                                                                                                                                    |
| **Produced into the graph**                 | **17/38 node types**, **27/42 edge types** (verified 2026-07-06 producer inventory; Track A + Cycle 2 + v0.5 lifted it from 15/21)                                                                                                                                                                                            |
| **Consumed by the path engine**             | ~12 node domains / ~22 traversable edges (was 6/15)                                                                                                                                                                                                                                                                           |
| **Node types produced by NO agent**         | `CLOUD_ACCOUNT`, `COMMIT`, `BUILD`, `DEVELOPER`, `SAAS_USER`, `NETWORK_PATH`, `NETWORK_FLOW_EVENT`, `CONTAINER_LIFECYCLE_EVENT`, `AUTH_EVENT`, `SAST_FINDING`, `REMEDIATION_ACTION` (+ threat-intel `ioc`/`cve`/`ttp` live in SemanticStore, **not graphed**)                                                                 |
| **Notable edges NOT produced**              | `TRUSTS`, `ASSUMABLE_BY`, `IN_SUBNET`/`IN_VPC`, `ENCRYPTED_BY`, `ROUTES_TO`, `LOGS_TO`, `EXPOSED_TO`, `SELECTS`, `INGRESS_TO`, `MOUNTS`, `GRANTS`, `SSO_INTO`/`FEDERATED_FROM` (bridges `MATCHES_INDICATOR`/`DEPLOYED_VIA`/`OWNED_BY`/`RUNS_IMAGE` are written by the meta-harness **correlation resolvers**, not the agents) |
| **Named path-types (the "confirmed" tier)** | ~27, ranked by KEV/EPSS expected-loss × blast radius                                                                                                                                                                                                                                                                          |
| **Track B (the "candidate" tier)**          | generic bounded-BFS engine, live, surfaces novel source→sink combos                                                                                                                                                                                                                                                           |
| **Reach**                                   | AWS + Azure + GCP for identity/data/host-vuln/KMS/DB (parity wired)                                                                                                                                                                                                                                                           |

**The ~27 named paths already cover the "obvious" archetype families** — crown-jewel, public-secret,
internet-exposed-vuln, privileged-vuln, external-trust, exposed-AI, fine-grained-data, KMS/DB
exposure, lateral-movement-via-reachability, SBOM supply-chain, malicious-destination (C2/exfil),
runtime-exploit, IaC-misconfig-deployed, CI/CD-compromise, rbac-escalation-to-data. The expansion
below is what is **genuinely not yet modeled** — mapped to ATT&CK so it's the real frontier, not
re-skins of what exists.

---

## The complete addable catalog — by ATT&CK tactic

Legend: **signal** = does the raw data already land in the graph? **prove** = can we CI-verify it
offline (moto/kind/injected-fake) or is it operator/live-only? **type** = new _archetype_ (named
path) vs _edge/property_ enrichment (feeds many paths + Track B) vs _toxic-combo_ (multi-signal
correlation).

### 1. Privilege Escalation — edge EXISTS tri-cloud but THIN (deepen, high connectivity)

**Reconciliation (2026-07-06):** v0.5 already built `CAN_ESCALATE_TO` — identity writes it on AWS,
Azure, and GCP, and the engine consumes it (`find_privilege_escalation_to_data`,
`find_escalation_method_to_data`). But it is explicitly **thin**: AWS models only **5 privesc methods,
target=admin only** ([identity/agent.py:642](../../packages/agents/identity/src/identity/agent.py)).
So this is a _deepening_, not a net-new build — but still top-tier by connectivity.

| Add                                            | Graph pattern                                                                                                                                                                    | Signal                                                                                                 | Prove                     | Type                                                                                       |
| ---------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ | ------------------------- | ------------------------------------------------------------------------------------------ |
| **Deepen `CAN_ESCALATE_TO` (5 → ~20 methods)** | add PassRole+lambda/glue/ec2, CreateAccessKey, UpdateLoginProfile, sts:AssumeRole via editable trust, CreatePolicyVersion, Attach*Policy, Put*Policy, UpdateFunctionCode+role, … | edge + 5 methods exist; ~15 methods + **NotAction/boundary/condition** awareness missing               | REAL (moto IAM)           | **edge deepening** — densest connective tissue; each method is more fan-out + Track-B fuel |
| **Non-admin escalation targets**               | principal --CAN*ESCALATE_TO--> \_any higher-priv* identity (today: admin only)                                                                                                   | target set is admin-only                                                                               | REAL                      | edge breadth — catches privesc to a non-admin role that still reaches data                 |
| **Cross-account `ASSUMES` chains**             | principal (acct A) --ASSUMES--> role (acct B) --HAS_ACCESS_TO--> data                                                                                                            | external-trust is a _property_; cross-account `ASSUMES`/`TRUSTS`/`ASSUMABLE_BY` edges **not produced** | REAL (moto multi-account) | edge — multi-account is where real blast radius lives                                      |

_Highest-leverage deepening: each new method + non-admin target multiplies the escalation fan-out and
feeds Track B directly. AWS-first to extend the contract, then Azure/GCP (both already have the thin edge)._

### 2. Credential Access — breadth (partial today: only code + bucket secrets)

| Add                                               | Graph pattern                                                                                                          | Signal                                                                                     | Prove                                                          | Type                                           |
| ------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------ | -------------------------------------------------------------- | ---------------------------------------------- |
| **IMDS / SSRF → instance-role creds**             | public/reachable workload --(IMDSv1 enabled / SSRF-able)--> steal role creds --ASSUMES--> role --HAS_ACCESS_TO--> data | reachability exists (`CAN_REACH`); IMDS-options **not collected**                          | REAL (moto EC2 metadata options)                               | archetype + property (IMDS config on instance) |
| **Secrets in env / Secrets Manager / SSM**        | workload --OWNS/STORES_SECRET--> `SECRET` --grants--> cloud                                                            | ECS env partly done (AWS-key regex only); SM/SSM/env-broad **not modeled as SECRET nodes** | REAL (moto SM/SSM)                                             | edge + node breadth                            |
| **Secrets in EBS/RDS snapshots**                  | snapshot --CONTAINS--> `SECRET`/`DATA_CLASSIFICATION`                                                                  | snapshot content **not sampled**                                                           | operator/live (no moto content) → offline via injected sampler | archetype + collection                         |
| **Cross-cloud stored secrets** (Cycle-5 deferral) | env/config --> non-AWS `SECRET` (GCP SA key, Azure conn-string, PATs)                                                  | regex is AWS-AKIA-only                                                                     | REAL (extends existing extraction)                             | property breadth — cheap                       |

### 3. Lateral Movement — deepen (Cycle 2 added derived `CAN_REACH` + `PEERED_WITH`)

| Add                                                  | Graph pattern                                             | Signal                                                 | Prove       | Type                                        |
| ---------------------------------------------------- | --------------------------------------------------------- | ------------------------------------------------------ | ----------- | ------------------------------------------- |
| **Reachability richness (NACL / WAF / port-scoped)** | tighten `CAN_REACH` with NACL + WAF + per-port conditions | SG-based reach exists; NACL/WAF **thin**               | REAL (moto) | edge property — precision + new reach paths |
| **Cross-VPC / cross-account reach → sensitive**      | `PEERED_WITH` + `CAN_REACH` → datastore/admin             | peering edge exists (Cycle 2); cross-account join thin | REAL        | archetype — extends the Cycle-2 detector    |

### 4. Persistence — a whole tactic, unmodeled (net-new)

| Add                                         | Graph pattern                                     | Signal                                                  | Prove                                                    | Type                                      |
| ------------------------------------------- | ------------------------------------------------- | ------------------------------------------------------- | -------------------------------------------------------- | ----------------------------------------- |
| **Backdoor identity / access-key creation** | anomalous new IAM user/key/role with broad grants | **not modeled** — needs create-event or drift detection | operator/live (CloudTrail) → offline via injected events | archetype + node/edge (persistence event) |
| **Trust-policy / assume-role modification** | role trust-policy widened to external             | needs config-drift or event                             | operator/live → offline via injected                     | archetype                                 |

### 5. Defense Evasion — a whole tactic, unmodeled (net-new)

| Add                                                             | Graph pattern                                                               | Signal          | Prove                       | Type                                                          |
| --------------------------------------------------------------- | --------------------------------------------------------------------------- | --------------- | --------------------------- | ------------------------------------------------------------- |
| **Disabled logging / GuardDuty / CloudTrail as a path-enabler** | resource in a region/account with detection disabled → raises path severity | **not modeled** | REAL (moto describe config) | property/edge — modifies path scoring (attacker moves unseen) |

### 6. Initial Access — new exposure archetypes (mostly covered; these are net-new families)

| Add                                                      | Graph pattern                                                                               | Signal                                       | Prove                                                 | Type                                                             |
| -------------------------------------------------------- | ------------------------------------------------------------------------------------------- | -------------------------------------------- | ----------------------------------------------------- | ---------------------------------------------------------------- |
| **Public snapshot / AMI sharing → data**                 | EBS/RDS snapshot or AMI shared `all` (public) --CONTAINS--> sensitive data                  | snapshot-sharing inventory **not collected** | REAL (moto describe-snapshots CreateVolumePermission) | archetype + collection — very common real Wiz finding            |
| **Serverless (Lambda) exposure → over-priv role → data** | public Function-URL / open resource-policy Lambda --ASSUMES--> role --HAS_ACCESS_TO--> data | Lambda inventory **not collected**           | REAL (moto Lambda)                                    | archetype + collection — extends ASSUMES→role→data to serverless |
| **API Gateway / public endpoint → backend**              | public API GW --> integration --> resource                                                  | not collected                                | REAL (moto)                                           | archetype (lower priority)                                       |

### 7. Collection / Exfiltration — deepen (partial via `malicious_destination`)

| Add                                     | Graph pattern                                                                       | Signal                                                                               | Prove                                            | Type                   |
| --------------------------------------- | ----------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------ | ------------------------------------------------ | ---------------------- |
| **Public-egress data-exfil path**       | principal --HAS_ACCESS_TO--> data + resource --(broad egress 0.0.0.0/0)--> external | egress edges **thin**                                                                | REAL (moto SG egress)                            | archetype + edge       |
| **Public-RDS → PII** (Cycle-5 deferral) | public `rds-instance` --CONTAINS/EXPOSES_DATA--> PII classification                 | `record_rds_instances` writes the node only; **no rds→DATA_CLASSIFICATION** producer | needs SQL content sampler → offline via injected | archetype + collection |

### 8. Impact — ransomware / destruction blast radius (partial)

| Add                                                  | Graph pattern                                                             | Signal                                                  | Prove       | Type                                                                        |
| ---------------------------------------------------- | ------------------------------------------------------------------------- | ------------------------------------------------------- | ----------- | --------------------------------------------------------------------------- |
| **State-mutation potential (delete/encrypt/ransom)** | principal with delete/kms-disable/put-bucket-policy over crown-jewel data | ties to remediation blast-radius; not modeled as a path | REAL (moto) | property — enriches ranking (what an attacker can _destroy_, not just read) |

---

## Cross-domain toxic combinations (the moat — multi-signal correlations)

Beyond single archetypes, the moat's edge is **stacking independent weak signals into one severe
story**. Cold-agent bridges still not fully wired:

| Toxic combo                                                                   | Domains                                                            | Bridge needed                                                   | Prove                                                                  |
| ----------------------------------------------------------------------------- | ------------------------------------------------------------------ | --------------------------------------------------------------- | ---------------------------------------------------------------------- |
| **Over-scoped SaaS/OAuth app → SSO into cloud identity**                      | sspm + identity                                                    | `SSO_INTO` / `FEDERATED_FROM` (federation-config collection)    | operator/live (no moto federation) — WIRED-not-REAL honestly, or defer |
| **Anomalous auth (impossible-travel / MFA-off) → privileged identity → data** | audit `AUTH_EVENT` + identity + data                               | join `AUTH_EVENT` → `IDENTITY`                                  | REAL if AUTH_EVENT lands offline                                       |
| **Threat-actor TTP attribution on an active path**                            | threat-intel `THREAT_ACTOR`/`ATTRIBUTED_TO` + any active detection | `ATTRIBUTED_TO` on the detection node                           | REAL (injected intel) — enriches, doesn't gate                         |
| **Compliance-weighted severity**                                              | compliance framework context on a path                             | re-contextualize severity by framework (lossy — not a new path) | N/A — reporting overlay, not a feeder                                  |

**The generative multiplier — Track B.** The generic candidate engine already surfaces _unnamed_
source→sink combos (e.g. `runtime_detection→sensitive_data`, `external_identity→known_vulnerability`)
as a "what to name next" backlog. **Every edge added above (especially `CAN_ESCALATE_TO`) makes Track
B discover many new multi-hop combinations with zero new detector code** — enrich the graph, the
catalog grows emergently. This is why edges outrank archetypes on leverage.

---

## Prioritized sequence — two honest lenses

The two disciplines pull slightly differently, so here are both, explicitly:

**Lens A — leverage (edges > archetypes; the scope-map thesis).** Maximizes emergent paths via Track B:

1. **Deepen `CAN_ESCALATE_TO` (5 → ~20 methods + non-admin targets)** — densest fan-out; each method
   multiplies escalation edges and Track-B combinations. Tri-cloud (thin edge already on all three).
2. **Cross-account / federation `ASSUMES`/`TRUSTS` edges** — real blast radius; multi-account.
3. **Impact/ransomware + defense-evasion properties** — enrich _ranking_ of every existing path.

**Lens B — count (net-new named archetypes; the "increase the number" ask).** Directly grows the catalog:

1. **IMDS/SSRF → cred-theft** — flagship demo path; needs IMDS-options collection (moto-REAL).
2. **Public snapshot/AMI → data** + **serverless (Lambda) exposure** — very common Wiz findings;
   self-contained, moto-REAL, each a new named archetype.
3. **Public-RDS→PII** + **cross-cloud stored secrets** (the Cycle-5 deferrals) — also net-new paths.
4. **Persistence** (backdoor identity / trust-policy mod) — closes a whole ATT&CK column (needs
   event/config collection; offline via injected).
5. **Cold-agent toxic combos** — audit `AUTH_EVENT` join (REAL) + threat-actor attribution (REAL);
   sspm `SSO_INTO` federation deferred (operator-only, no moto).

## Honest boundaries

- **Live-cloud is operator-gated.** Everything above is offline-provable via moto/kind/injected
  fakes (the fleet's standard bar) _except_ where noted (federation, snapshot content, CloudTrail
  events) — those are WIRED-not-REAL until you provide a real account. The whole catalog is proven on
  synthetic data; **real-cloud verification remains a separate operator-triggered step** (`NEXUS_LIVE_*`).
- **Precision scales with richness.** More edges → more candidate paths → more noise. Every new edge
  ships with its red-team false-positive bank; Track B's confirm/dismiss + scoring is the governor.
- **One edge, deep, across the ICP's clouds** — not all-detectors-wide, not all-AWS-then-someday.
  Each slice's definition of done includes its per-cloud report-card bank.

## Recommendation

Because the highest-connectivity edge (`CAN_ESCALATE_TO`) already exists tri-cloud (just thin), the
"increase the number" ask is best served by a **mixed first cycle** that grows the catalog _and_
deepens the leverage edge — all offline-provable, with live-cloud activation as the parallel
operator-triggered validation:

- **3 net-new archetypes (count):** IMDS/SSRF → cred-theft, public snapshot/AMI → data, serverless
  Lambda exposure. Each moto-REAL, demo-able, directly grows the named catalog (~27 → ~30).
- **+ fold in the Cycle-5 deferrals** (public-RDS→PII, cross-cloud stored secrets) — also net-new paths.
- **1 leverage deepening (optional, parallel):** `CAN_ESCALATE_TO` 5 → ~20 methods + non-admin
  targets — supercharges Track B so the _emergent_ count climbs too.
- **Live-cloud activation** runs alongside: I build the seams; you trigger the `NEXUS_LIVE_*` run on a
  real account to move any slice from offline-proven → real-cloud-verified.

Net effect: the named archetype count rises directly, Track B's emergent discovery rises with the
richer edges, and each slice ships offline-proven with its red-team bank. Pick the batch below and I'll
design → build it the same subagent-driven way as the 4 cycles.
