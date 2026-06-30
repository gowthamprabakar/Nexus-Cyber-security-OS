# Slice #1 design — the `CAN_ESCALATE_TO` edge (identity privilege escalation)

**Date:** 2026-06-29. The keystone edge. This contract is inherited by every later edge slice, so it
is designed before any code. Operating rule: graph-model-scope-map (one edge at a time; edge =
provider-agnostic contract, detector = per-cloud implementation).

## Why this edge first

Identity edges ("who can become / control whom") are the densest connective tissue in a cloud attack
graph, and the biggest red-team gap: today we model only `ASSUMES` (assume-role) + full-admin. The
~20 IAM privilege-escalation methods are invisible — a non-admin with `iam:CreatePolicyVersion` on
an admin-attached policy _is_ admin, and we'd show a normal principal.

**Free win:** `CAN_ESCALATE_TO` is already in the `EdgeType` enum (defined, never written). Slice #1
populates an edge the schema already anticipated — **no schema change.**

## The edge — the provider-agnostic contract

```
IDENTITY  --CAN_ESCALATE_TO-->  IDENTITY
```

**Semantics:** the source principal can, via a privilege-escalation technique, obtain the privileges
of the target principal (become it, or grant itself the target's power). Direction is always
**toward higher privilege.**

`ASSUMES` stays as-is (it's the assume-role _instance_, used by the named path #13). `CAN_ESCALATE_TO`
is the **general** escalation edge for the method-based techniques. (We do not refactor `ASSUMES`
into it now — minimize churn; they can converge later.)

### Edge properties (the contract every cloud's detector must fill)

| Property      | Meaning                                                                                                           | Example                                                                                                   |
| ------------- | ----------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------- |
| `method`      | the technique, provider-agnostic vocabulary                                                                       | `policy_rewrite`, `self_grant_admin`, `pass_privileged_role`, `trust_rewrite`, `credential_mint`          |
| `via_action`  | the specific cloud permission that enables it (explainability)                                                    | `iam:CreatePolicyVersion` / `Microsoft.Authorization/roleAssignments/write` / `iam.serviceAccounts.actAs` |
| `confidence`  | `confirmed` (all preconditions resolved) vs `potential` (action present, target/preconditions not fully resolved) | `confirmed`                                                                                               |
| `target_kind` | what is gained                                                                                                    | `admin`, `privileged_role`, `user`                                                                        |

`confidence` is how we stay honest about precision (below). The path engine treats both, but a
`potential` edge is ranked lower and surfaced as a candidate, not a confirmed finding.

## The precision crux (this is the hard part, and why it's the keystone)

An escalation edge is **only real if there is an actual reachable target that is more privileged.**
"Principal has `iam:CreatePolicyVersion`" alone is NOT escalation — it's escalation only if there is
a policy they can version _that is attached to a more-privileged principal._ So the detector must
**resolve the target**, not just match the action. This is the discipline that makes the contract
right:

- Target resolvable + more-privileged → `confidence: confirmed`.
- Action present but no resolvable privileged target → **emit nothing** (or `potential`, never a
  confirmed edge). A bare risky action is not a path.

This is exactly the false-positive trap class the red-team taught us. The bank (below) is built
around it.

## AWS detector — slice #1, thin first (5 methods)

Mirror `_assume_grants`: iterate principals, parse their allowed actions from
`IdentityListing` (attached + inline policy documents), resolve the target, emit the edge.

| #   | Method (`method`)      | Trigger action(s)                                                                            | Target resolution → edge                                                                         |
| --- | ---------------------- | -------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| 1   | `self_grant_admin`     | `iam:AttachUserPolicy`/`AttachRolePolicy` or `iam:PutUserPolicy`/`PutRolePolicy` on self/`*` | principal → **admin sentinel** (`target_kind=admin`)                                             |
| 2   | `policy_rewrite`       | `iam:CreatePolicyVersion` (+ set-default) on a customer-managed policy                       | principal → each principal that policy is **attached to** (skip if attached to none / only self) |
| 3   | `pass_privileged_role` | `iam:PassRole` + a service-launch action (`lambda:CreateFunction`, `ec2:RunInstances`, …)    | principal → the **passable role** if that role is more privileged                                |
| 4   | `trust_rewrite`        | `iam:UpdateAssumeRolePolicy` on a role                                                       | principal → that **role**                                                                        |
| 5   | `credential_mint`      | `iam:CreateAccessKey`/`iam:CreateLoginProfile` on another user                               | principal → that **user**                                                                        |

"More privileged" reuses the existing admin/fine-grained machinery (`_synthesize_admin_grants`,
permission-boundary capping — gap #8) so we don't reinvent privilege comparison.

**Thin = these 5**, each with target resolution. The other ~15 methods (UpdateLoginProfile,
PassRole+Glue/CloudFormation/Datapipeline, AddUserToGroup, etc.) are fast follow-ups _once the
contract holds_.

## Path-engine integration — where the paths emerge

1. Add `CAN_ESCALATE_TO` to `TRAVERSABLE_EDGES`.
2. The walker already treats any `IDENTITY` as an `identity_principal` source. So:
   `identity_principal --CAN_ESCALATE_TO--> admin --HAS_ACCESS_TO--> bucket --EXPOSES_DATA--> data`
   becomes walkable → privilege-escalation-to-data paths **emerge** via Track B (the discovery
   engine), no hand-coding.
3. **Transitivity is free.** A→B and B→C single-hop edges chain into A→C through normal traversal —
   so multi-hop escalation chains fall out of single-hop edges. (We do _not_ compute chains in the
   detector; the graph does it.)
4. Promotion: once Track B surfaces these candidates and we confirm them, the BP4 confirm-loop drafts
   a named `privilege_escalation_via_method` archetype. We eat our own dogfood.

## The universal contract — how Azure + GCP fill the SAME edge

Same edge, same properties, different per-cloud detectors:

| Cloud     | Escalation mechanic → `CAN_ESCALATE_TO`                                                                                                                                |
| --------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **AWS**   | the 5 IAM methods above                                                                                                                                                |
| **Azure** | `Microsoft.Authorization/roleAssignments/write` on a scope → self-grant Owner; or rewrite another principal's credentials. `method=self_grant_admin`/`policy_rewrite`. |
| **GCP**   | `iam.serviceAccounts.actAs` / `getAccessToken` / `setIamPolicy` → impersonate a more-privileged service account. `method=pass_privileged_role`/`self_grant_admin`.     |

The edge, the path engine, Track B, the ranker — all unchanged across clouds. Only the detector that
computes the edge differs. **This is the multi-cloud payoff: define once, implement per cloud.**

## Per-cloud scope for slice #1 — the one open decision

AWS detector is built first **to prove this contract** (thin, 5 methods). Whether Azure + GCP
detectors are built in this slice depends on the **ICP answer still pending:** _does the ICP need
privilege-escalation detection on Azure specifically (healthcare/defense)?_

- **Yes →** slice #1 is tri-cloud (Azure role-assignment + GCP SA-impersonation detectors follow AWS).
- **No →** slice #1 ships AWS, **explicitly marked "AWS-only for now, ICP-driven"**, and Azure/GCP
  escalation is scheduled, not silently dropped.

Either way the _contract_ is designed multi-cloud now, so adding the other clouds is detector work,
not redesign.

## Report-card bank (per cloud the slice claims) — built around the precision crux

- **standard violations:** each of the 5 methods with a resolvable privileged target → `confirmed` edge.
- **false-positive traps (the heavy set):** `iam:CreatePolicyVersion` on a policy attached to nothing;
  `PassRole` to a _non_-privileged role; `AttachUserPolicy` scoped to a read-only policy ARN, not `*`;
  a read-only `roleAssignments/read` (Azure); `actAs` on a same-or-lower-privilege SA (GCP). All →
  **no edge.**
- **edge cases:** boundary-capped admin (reuse gap #8 — capped → no escalation); self-referential
  (escalate to self → no edge); transitive A→B→C (assert the _single_ hops emit, chain is the graph's).
- **negative space / clean baseline** as standard.

Def of done = `confirmed`-edge precision/recall pinned per cloud, traps all dark.

## Scope boundaries (what slice #1 does NOT do)

Full effective-permissions simulation, condition-key evaluation, SCP interplay, session policies,
and the remaining ~15 methods are **out** — deliberately. Slice #1 proves the edge contract on the 5
highest-frequency methods with honest `confidence`, and lets transitivity + Track B do the rest.
