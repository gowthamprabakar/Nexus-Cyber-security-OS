# Graph-model scope map — the first-order work we skipped

**Date:** 2026-06-29. Written after a strategic correction: we were finding detector flaws one at a
time (bottom-up whack-a-mole) instead of deciding, top-down, **what graph the fleet must produce.**

## The reframe (the thing we're actually building)

```
Detectors  →  (nodes + edges + properties)  →  Knowledge Graph  →  traversal  →  Attack Paths
```

- A detector's real job is **not** "emit a finding." It is to **contribute accurate nodes, edges,
  and properties to the graph.**
- An attack path is **not** something we hand-build — it is a **traversal the graph makes possible.**
- Therefore the unit of value is **graph richness + connectedness**, not detector count or
  hand-coded path count. **Detectors power the graph; the graph powers the paths.** (We had this
  backwards: scoping detectors to serve today's tiny path catalog freezes the product — a weak
  detector makes a sparse graph makes no paths.)

The lever that turns graph-richness into path-richness **without hand-coding every path** already
exists: the **Track B discovery engine**. Enrich the graph → it discovers the new combinations →
the catalog grows emergently. So: **invest in the graph; the paths follow.**

## Current graph — measured (your "very very little", made concrete)

|                             | Defined in the vocabulary | Actually produced | Used |
| --------------------------- | ------------------------- | ----------------- | ---- |
| Node types (`NodeCategory`) | 40                        | 15                | 37%  |
| Edge types (`EdgeType`)     | 72                        | 21                | 29%  |
| Edges a path can traverse   | —                         | 15                | —    |

**The real problem is edge density, not node variety.** Almost every edge type is written by exactly
ONE writer in ONE context — the graph is a set of small stars, not a mesh. And the **cross-domain
bridge edges** — the connective tissue that makes a multi-step path possible — are the very sparsest:

| Bridge edge         | Connects                    | Written |
| ------------------- | --------------------------- | ------- |
| `OWNED_BY`          | network endpoint → instance | once    |
| `MATCHES_INDICATOR` | endpoint → threat IOC       | once    |
| `DEPLOYED_VIA`      | resource → IaC artifact     | once    |
| `IRSA_MAPPING`      | K8s SA → IAM role           | once    |
| `HOSTS_AI`          | account → AI service        | once    |

Five bridges, each produced once. **That is the entire cross-domain surface of the product.** This is
why the attack-path catalog is small: not because we lack detectors, but because the graph barely
connects across domains.

## Target graph — anchored to attacker techniques (the compass, so this stays finite)

Scope is bounded by **MITRE ATT&CK for Cloud** (a finite, external technique list), not by tool
completeness (infinite) and not by today's paths (too weak). Each tactic _implies_ the graph it
needs. The gaps below are what's missing to represent real attacker movement.

| ATT&CK tactic (cloud)         | Graph it requires                                                                                                                       | Have?                   | Gap                                              |
| ----------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- | ----------------------- | ------------------------------------------------ |
| **Initial Access**            | `is_public` resources, internet-exposure edge, external-trust, leaked-secret → cloud                                                    | ~yes                    | reachability conditions (SG/NACL/WAF) thin       |
| **Execution**                 | `RUNS_IMAGE`, `EXECUTED_ON`, process events                                                                                             | yes                     | —                                                |
| **Persistence**               | new identity / access-key creation, trust-policy modification edges                                                                     | **no**                  | persistence not modeled at all                   |
| **Privilege Escalation**      | `ASSUMES` chains **+ a derived `CAN_ESCALATE_TO` edge from effective permissions** (PassRole, CreatePolicyVersion, AttachUserPolicy, …) | **assume-role only**    | **the privesc-method edge — biggest single gap** |
| **Defense Evasion**           | edges to logging/audit/GuardDuty config (disabled detection)                                                                            | **no**                  | not modeled                                      |
| **Credential Access**         | `SECRET` nodes + `DEFINED_IN` / `OWNS` / `EXPOSES_DATA`; instance-metadata, env, secrets-manager sources                                | partial                 | only code + bucket secrets; no metadata/env/SM   |
| **Lateral Movement**          | observed `COMMUNICATES_WITH` **+ derived `CAN_REACH`** (SG/route reachability), cross-account `ASSUMES`                                 | **observed flows only** | derived reachability; cross-account trust        |
| **Collection / Exfiltration** | `HAS_ACCESS_TO` data + egress edge to external / malicious destination                                                                  | partial                 | egress/exfil edges thin                          |
| **Impact**                    | state-mutation potential (delete/encrypt) — ties to remediation's blast radius                                                          | partial                 | —                                                |

## The gap, ranked by connectivity (build edges + properties, in this order)

Weighted by **how many traversals a piece unlocks** (bridges first), not by how easy it is:

1. **Effective-permissions + `CAN_ESCALATE_TO` (identity).** The densest connective tissue in any
   cloud attack graph is "who can reach / become what." Today we model `ASSUMES` + full-admin only;
   the ~20 privesc methods and `NotAction`/boundaries/conditions are unmodeled. **One capability,
   enormous edge fan-out** — it connects identities to nearly everything. _Highest leverage._
2. **Derived reachability `CAN_REACH` (network).** Turns observed flows into _potential_ lateral
   movement (SG/route/peering-aware). Unlocks lateral paths the observed-only edge can't see.
3. **Cross-account / federation trust edges (identity).** Multi-account is where real blast radius
   lives; today external-trust is a single property, not a traversable cross-account edge.
4. **Credential-access breadth (data + identity).** Secrets in instance metadata, env vars,
   Secrets Manager, EBS snapshots — each a `SECRET` node + an `OWNS`/`EXPOSES` edge to a workload.
5. **Persistence + defense-evasion (new).** Backdoor identities, disabled logging — whole tactics
   currently invisible. Lower path-frequency but real.

Note the pattern: **every top item is an EDGE or a PROPERTY, not a new node type or a new finding.**
That is the strategic conclusion — fund edges and bridges, in connectivity order.

## Compass + premortem (so "deep deep deep" doesn't sink us)

- **Bound:** a node/edge type earns a build only if it participates in ≥1 ATT&CK technique. The
  threat model is the gate against boil-the-ocean.
- **Precision scales with richness:** more edges → more candidate paths → more noise. Every edge
  ships with its false-positive trap set; Track B's confirm/dismiss + scoring is the governor.
- **Dormancy test:** a capability that adds a node/edge that _connects_ is alive; one that adds an
  isolated finding is dormant — emit it as a flat finding, don't invest depth.
- **Unvalidated on real cloud:** richness proven only on synthetic data is still unproven on
  reality. Unchanged; stated honestly.

## The operating rule — one edge at a time (agreed 2026-06-29)

The unit of work is **the edge-slice**, not the detector and not the cloud. We do **not** widen all
20 detectors (findings-breadth — low connectivity), and we do **not** do "all AWS then Azure/GCP
someday" (compounds the AWS bias). We take **one edge, deep, and finish it across the clouds the ICP
needs**, then the next edge by connectivity rank.

### Edge = contract · detector = per-cloud implementation

The reframe is what makes multi-cloud tractable instead of 3× everywhere:

- The **edge** (`CAN_ESCALATE_TO`, `CAN_REACH`, …) is a **provider-agnostic contract.** The path
  engine, Track B, the ranker, and remediation advice all operate on `NodeCategory`/`EdgeType` with
  **zero cloud awareness** — build once, works for every cloud.
- The **detector** that populates an edge is a **per-cloud implementation.** AWS privesc methods,
  Azure role-assignment escalation, GCP service-account impersonation are different mechanics that
  write the **same edge.**

### A slice's definition of done

1. **AWS first — to prove the contract, not to ship one cloud.** Build the AWS detector concretely
   (start _thin_ — the few most common cases — for a fast working slice); it reveals the edge's true
   shape, properties, and precision traps. AWS-first is a de-risking tactic, not the strategy.
2. **Then Azure + GCP for the same edge**, before the next edge. This also stress-tests the universal
   contract on the keystone — if the model doesn't fit Azure RBAC, we learn it on edge #1, not #10.
3. **Per-cloud report-card bank is the def of done.** An edge isn't done until it has its red-team
   bank on each cloud it claims. Quality folds into the slice — no deferred "report cards later."
4. **Per-cloud scope is an explicit, ICP-driven decision** — "tri-cloud" or "AWS-only for now,
   because the ICP doesn't ask for it on Azure." Written down per edge. Never drift.

### Sequence

By connectivity. **#1 = identity `CAN_ESCALATE_TO`** — densest connective tissue, biggest red-team
finding, _and_ the one agent that already has Azure depth (so the keystone is also the cheapest place
to go tri-cloud). Then network `CAN_REACH`, then cross-account trust, then credential-access breadth,
then persistence/defense-evasion. Enrich the graph where it connects most; let Track B turn that into
paths.
