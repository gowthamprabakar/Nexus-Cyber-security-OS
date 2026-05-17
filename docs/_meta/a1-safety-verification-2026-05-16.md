# A.1 v0.1 safety verification record — 2026-05-16

**What this is.** The standalone safety record for A.1 v0.1 (Remediation Agent, production-action mode). Distinct from the implementation-completeness record at [`a1-verification-2026-05-16.md`](a1-verification-2026-05-16.md) (which covers what shipped, test counts, ADR-007 conformance). This record answers the safety question the implementation record sidestepped:

> **"Why is collapsing Tier-3 → Tier-2 → Tier-1 into one agent safe, and what specifically must be true before `--mode execute` runs unattended in a customer's production environment?"**

**Why it exists.** The implementation record framed A.1's scope-collapse as a calendar win ("pulled ~10 weeks out of the critical path"). That framing buried the question of whether merging three planned safety tiers into one shippable agent is _safe_. This record makes the safety contract explicit and auditable.

**Scope.** The contents below are load-bearing for any decision to enable `--mode execute` in a customer environment. If anything here is wrong, that decision is wrong.

---

## §1. The reframe — tiers are graduation stages, not separate agents

The original Phase-1c plan named A.1 / A.2 / A.3 as three sequential **agents**. That framing was load-bearing on a hidden assumption: that the safety surface of remediation is so different per tier that each tier deserves its own agent and its own multi-week build cycle.

That assumption is wrong. The three tiers share the same five primitives — patch builder, dry-run, executor, validator, rollback — and the only thing that differs between tiers is **how much human judgment is in the loop on any given action**:

| Original Tier | Original framing          | Reframed as: per-action-class promotion stage                                             |
| ------------- | ------------------------- | ----------------------------------------------------------------------------------------- |
| A.1 Tier-3    | Recommend-only agent      | Stage 1: artifact generation (operator reviews + hand-applies)                            |
| A.2 Tier-2    | Approve-and-execute agent | Stage 3: human-approved execute (operator clicks "go" per action)                         |
| A.3 Tier-1    | Autonomous agent          | Stage 4: unattended execute (operator owns policy + kill switch, not per-action approval) |

The intermediate `dry_run` mode (originally absent from the A.1/A.2/A.3 split) is **stage 2**: server-side validation against a real cluster, no apply.

**The three tiers were never three agents. They were graduation stages for each individual action class.** Once A.1 v0.1 collapses them into one agent's `--mode` flag space, the safety question shifts: it isn't "is this whole agent safe to ship" but rather "**which action classes have earned which stage of autonomy, in which environment**." That is the earned-autonomy pipeline.

This record's claim: **the scope-collapse is safe only if the earned-autonomy pipeline is followed**. Without the pipeline, collapsing tiers means promoting every action class to Stage 4 by default, which is the failure mode A.1's safety contract exists to prevent.

---

## §2. The four-stage earned-autonomy pipeline

Each action class lives in exactly one stage at any moment, **per customer environment**. (An action class may be at Stage 4 in customer X's environment and Stage 1 in customer Y's, depending on how much demonstrated reliability the action class has against each cluster's specifics.)

### Stage 1 — `recommend`

| Property                | Value                                                                                                                     |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| **What runs**           | A.1 generates the artifact; operator reviews the diff in PR / change-management; operator hand-applies.                   |
| **Blast radius**        | None at the platform level — A.1 never touches the cluster.                                                               |
| **Human role**          | Reviews every artifact. Signs the change-management ticket. Applies the patch via their own change tooling.               |
| **Failure mode**        | Operator applies a bad patch. Owned entirely by operator's change-management. A.1 is a recommender.                       |
| **Auth required**       | `mode_recommend_authorized: true` (default).                                                                              |
| **Operational flag**    | None.                                                                                                                     |
| **Promotion criterion** | The operator has applied A.1's artifact for this action class at least once and confirms it produced the expected result. |

This is the entry point for every action class. **No action class ships above Stage 1 in any customer environment without explicit graduation.**

### Stage 2 — `dry_run`

| Property                | Value                                                                                                                                                                             |
| ----------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **What runs**           | A.1 generates the artifact AND invokes `kubectl --dry-run=server` against the live cluster. Apply never happens.                                                                  |
| **Blast radius**        | None at the workload level. The cluster's admission webhooks see the patch (which has side effects for some webhooks — e.g. policy engines may log the attempt).                  |
| **Human role**          | Reviews the dry-run diff. Decides whether the diff matches expectation. Hand-applies if so.                                                                                       |
| **Failure mode**        | Server-side dry-run rejects (good — caught before apply). Dry-run succeeds but apply behaves differently (mutating webhook strips fields — see Stage 3 risk).                     |
| **Auth required**       | `mode_dry_run_authorized: true`. Cluster access (`--kubeconfig` or `--in-cluster`).                                                                                               |
| **Operational flag**    | None.                                                                                                                                                                             |
| **Promotion criterion** | Action class has run `dry_run` against the customer's actual cluster at least **5 times** for distinct workloads without rejection. Every dry-run output reviewed by an operator. |

The promotion-out-of-Stage-1 evidence is the dry-run record. Stage 2 is where action classes prove they work against this customer's admission webhooks, this customer's RBAC, this customer's workload shapes — not the platform's hypothetical defaults.

### Stage 3 — human-approved `execute`

| Property                | Value                                                                                                                                                                                                                                                                                                                                                              |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **What runs**           | A.1 generates + dry-runs + (on operator approval per action) executes. Rollback timer + post-validation re-detection fire.                                                                                                                                                                                                                                         |
| **Blast radius**        | One workload per approval. The operator approves each individual action before A.1 applies.                                                                                                                                                                                                                                                                        |
| **Human role**          | Approves each action individually. Reviews the rollback decision if it fires. Owns the kill switch.                                                                                                                                                                                                                                                                |
| **Failure mode**        | Approved patch applies but webhook re-mutates spec → rolled-back automatically. Approved patch applies but breaks workload → rolled-back automatically. Operator approves a patch they didn't read → not A.1's failure to prevent; this is what change-management process is for.                                                                                  |
| **Auth required**       | `mode_execute_authorized: true`. The specific action class in `authorized_actions`. Cluster access. **Per-action approval gate** (S.3 ChatOps in Phase-1c; for v0.1, manual CLI invocation per workload).                                                                                                                                                          |
| **Operational flag**    | `--i-understand-this-applies-patches-to-the-cluster` MUST be passed.                                                                                                                                                                                                                                                                                               |
| **Promotion criterion** | Action class has run successfully at Stage 3 against the customer's actual cluster for **at least 10 distinct workloads**, with **zero rolled-back outcomes** caused by an issue with the action class itself (rollbacks caused by external admission webhooks count separately — they validate the rollback contract works, not that the action class is broken). |

This is the stage every action class graduates to once Stage 2 evidence exists. **No action class skips Stage 3 — there is no path from Stage 2 to Stage 4 without operator-approved execute time at Stage 3.**

### Stage 4 — unattended `execute`

| Property                | Value                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **What runs**           | A.1 runs on a schedule (Phase-1c scheduler), ingests D.6 findings, applies remediations for action classes that have reached Stage 4 in this environment, runs rollback validation, halts on first unexpected failure.                                                                                                                                                                                                    |
| **Blast radius**        | Bounded by `max_actions_per_run` (1-50). Whole run halts if any action's rollback-decision fires unexpectedly. Operator-defined exclusion list per workload kind / namespace.                                                                                                                                                                                                                                             |
| **Human role**          | Owns policy (which action classes are at Stage 4, in which namespaces, with what blast-radius cap). Owns the kill switch (single env-var or auth.yaml flip stops all Stage 4 execution platform-wide). Reviews rollback-decisions weekly. **Does not approve individual actions.**                                                                                                                                        |
| **Failure mode**        | A.1 applies a patch that the admission webhook silently mutates → rolled back automatically. Cluster controller falls behind → measured rollback window exceeds default → caught by Stage-3 promotion criterion before reaching Stage 4. A previously-stable workload changes shape (HPA tuned, new sidecar added) → action class output may not match cluster expectation → rolled back, action class re-enters Stage 3. |
| **Auth required**       | `mode_execute_authorized: true`. Action class in `authorized_actions`. Cluster access.                                                                                                                                                                                                                                                                                                                                    |
| **Operational flag**    | `--i-understand-this-applies-patches-to-the-cluster` MUST be passed (for ad-hoc invocations). Scheduled runs (Phase-1c) use a separate Stage-4-only authorization scope.                                                                                                                                                                                                                                                  |
| **Promotion criterion** | Action class has accumulated **30 consecutive successful Stage-3 executions** against the customer's cluster, with the customer's security lead signing off on the promotion. **No Stage-4 promotion is automatic.**                                                                                                                                                                                                      |

The human never fully leaves. The shift between Stage 3 and Stage 4 is the human moving **from approving each action** to **owning policy and the kill switch**. Both stages have human authority over the agent; the granularity is different.

---

## §3. Promotion-tracking: where the per-action-class graduation state lives

A.1 v0.1 does not yet have a per-action-class promotion state file. **This is a gap.** The v0.1 model is binary at the `auth.yaml` level: an action class is either in `authorized_actions` or not, with no record of what stage it's at or what evidence justified the listing.

For the earned-autonomy pipeline to be auditable, A.1 v0.2 (or earlier) needs:

1. **A `promotion.yaml` per customer environment** that records, per action class:
   - Current stage (1-4).
   - Promotion-evidence count (e.g. `stage2_dry_runs: 7`, `stage3_executes: 14`, `stage3_unexpected_rollbacks: 0`).
   - Promotion-sign-off (who, when) for the most recent stage transition.
   - Excluded namespaces / workload kinds / labels.
2. **Per-action audit log emission** on every Stage-N event — incrementing the corresponding counter in `promotion.yaml`. Reuses A.1's F.6 audit hash chain; the promotion state is derivable from the chain replay.
3. **A `remediation promotion` CLI subcommand** that prints the per-action-class state and proposes promotions to the operator (e.g. "action `runAsNonRoot` has accumulated 12 successful Stage-3 executions in `production`; ready for sign-off to Stage 4?").

**Until promotion.yaml ships**, the human role for every Stage 3 and Stage 4 action is owned by manual operator discipline — the operator-of-record reviews the audit log + `findings.json` weekly and makes promotion decisions out-of-band. This is documented in the runbook ([§4 of `remediation_workflow.md`](../../packages/agents/remediation/runbooks/remediation_workflow.md)) but it is fragile. **Manual discipline is not a substitute for in-product tracking.**

**Gap closure target:** Phase-1c, before any "do" agent expansion (A.1 v0.2, A.1 v0.3, A.2, etc.). The promotion model is the load-bearing contract every future cure-quadrant agent inherits; it must be in code before more action classes ship.

---

## §4. The kill switch — what stops Stage 3 / Stage 4 immediately

In any customer environment with any action class at Stage 3 or Stage 4, the operator must be able to **halt all execute-mode runs platform-wide in under 60 seconds**. The mechanisms:

| Mechanism                                                                   | Latency | Who can trigger                      | Scope                                                                                                   |
| --------------------------------------------------------------------------- | ------- | ------------------------------------ | ------------------------------------------------------------------------------------------------------- |
| **`auth.yaml`: `mode_execute_authorized: false`**                           | <60s    | Operator with auth.yaml write access | Per-customer (the auth.yaml is per-tenant)                                                              |
| **`--i-understand-this-applies-patches-to-the-cluster` flag absent in CLI** | Instant | Operator at the CLI                  | Per-invocation (already true by default; the flag is the operational gate)                              |
| **`authorized_actions: []` in auth.yaml**                                   | <60s    | Operator with auth.yaml write access | Per-customer; finer-grained — disables only the listed action classes, leaves recommend mode functional |
| **`kubectl delete clusterrolebinding nexus-remediation-execute`**           | <60s    | Cluster admin                        | Per-cluster; cuts off A.1's RBAC at the K8s layer — survives even a misconfigured auth.yaml             |

The last mechanism is the **defense-in-depth kill switch**: even if auth.yaml is over-broad AND the CLI flag is somehow inadvertently set, the cluster's RBAC will refuse the patch with a 403 and A.1's executor will emit `execute_failed`. **Three layers must align before any patch lands.**

The runbook ([§6 of `remediation_workflow.md`](../../packages/agents/remediation/runbooks/remediation_workflow.md)) documents the ClusterRole. For Stage-4 customers, **the cluster admin should be a different individual than the `auth.yaml` operator** — the standard separation-of-duties pattern. Until that separation exists (no S.3 ChatOps yet, no separate admin role yet), A.1 v0.1 customers should treat Stage 4 as off-limits regardless of any other consideration.

---

## §5. Why scope-collapse is safe — the argument in writing

The user's question, reproduced: _"Why is collapsing Tier-3 → Tier-2 → Tier-1 into one agent safe?"_

**Answer.** The scope-collapse is safe **if and only if** every action class is gated by the four-stage promotion pipeline, every customer environment has explicit per-action-class stage assignments, and the kill switches at §4 are wired and tested.

The original three-agent split would have enforced this pipeline at the **agent boundary**: customer adopts A.1 (recommend), then A.2 (approve-and-execute) ~weeks later, then A.3 (autonomous) ~weeks after that. The boundary was implicit; the pipeline was implicit; the customer's choice of which agent to deploy was the (very coarse) promotion gate.

The unified A.1 v0.1 enforces the same pipeline at the **`--mode` flag + `auth.yaml` + operational flag boundaries**, with finer granularity. The risk shifts from "customer accidentally upgrades agent version" (low — agent versions are operator-managed) to "customer accidentally flips an auth.yaml field" (higher — config drift is everyone's problem). **The operational `--i-understand-this-applies-patches-to-the-cluster` flag exists precisely to close that risk:** even an over-broad auth.yaml cannot reach apply-time without the operator explicitly opting in at the CLI for each invocation.

The collapse is therefore safe **conditional on**:

1. **The four-stage promotion pipeline is documented and operator-visible.** ✅ This record + the runbook.
2. **`--mode execute` is locked OFF by default behind the operational flag.** ✅ As of gate G2 closure today.
3. **The execute path has been proven against a real cluster, not just mocked tests.** ⚠️ **PENDING — gate G3.** Scaffolding is in place ([`tests/integration/test_agent_kind_live.py`](../../packages/agents/remediation/tests/integration/test_agent_kind_live.py)) but not yet run green.
4. **Promotion tracking exists in code, not just in operator memory.** ⚠️ **PENDING — Phase-1c task.** Documented gap in §3 above.
5. **The kill switches are tested in customer environments before Stage-3 or Stage-4 enablement.** ⚠️ **PENDING — customer-onboarding task.** No customers at Stage 3 or 4 yet.

**Until items 3-5 close, no action class graduates above Stage 2 in any customer environment.** Stage 1 (recommend) and Stage 2 (dry_run) are safe to ship today; they are by construction unable to apply patches to customer clusters.

This is the bright line. Below it, A.1 v0.1 is shippable today. Above it, A.1 v0.1 is shippable only after items 3-5 close. The post-A.1 readiness report's "production-action mode" framing was — to the extent it suggested customers could enable Stage 3 or Stage 4 today — premature.

---

## §6. What must be true before `--mode execute` runs unattended in a customer's production environment

The user's second question: _"What specifically must be true before `--mode execute` runs unattended in a customer's production environment?"_

The complete list (every item must close; this is not "pick three"):

### Platform-side prerequisites

1. **Gate G3 closure** — the `NEXUS_LIVE_K8S=1` lane passes `test_execute_validated_against_live_cluster` and `test_rollback_window_matches_real_reconcile` against a `kind` cluster of the customer's K8s minor version. Recorded by appending a note to this file: date, kind version, measured reconcile latency, commit hash.
2. **Promotion tracking in code (§3 gap)** — `promotion.yaml` ships; per-action audit emission lands; `remediation promotion` CLI exists. Phase-1c task; no Stage 4 customer enablement until done.
3. **The mutating-admission-webhook fixture** lands and `test_execute_rolled_back_against_live_cluster` flips from `xfail` to `pass`. This proves the rolled-back path works end-to-end, not just the validated path. Phase-1c follow-up after initial G3 closure.
4. **At least one design-partner customer has run Stage 3 in their environment for ≥4 weeks without an unexpected rollback.** This is the empirical floor; no synthetic test substitutes for a real customer cluster's webhook landscape.

### Customer-side prerequisites

5. **A signed runbook acknowledging the four-stage pipeline.** Customer's security lead countersigns this record's §2 verbatim. The customer agrees that no action class reaches Stage 4 in their environment without the customer's own sign-off + 30 consecutive Stage-3 executions.
6. **Separation of duties.** The individual who edits `auth.yaml` is different from the individual who holds the K8s ClusterRoleBinding-delete permission. Two-person control on the kill switch.
7. **A defined kill-switch drill cadence.** Quarterly: customer triggers each of the four kill-switch mechanisms (§4) and verifies the platform halts Stage-3/Stage-4 execution within 60s. Recorded in the customer's compliance audit log.
8. **A defined rollback-window-tuning process.** The default 300s `rollback_window_sec` was measured against `kind` (gate G3). If the customer's cluster has higher reconcile latency (large clusters, slow-reconciling controllers, OPA Gatekeeper-heavy webhook chain), the customer measures their actual latency and raises the value. **Stage 3 cannot graduate to Stage 4 until rollback_window_sec is empirically validated against the customer's cluster** — not the platform default.
9. **A defined incident-response playbook for `execute_failed` and unexpected `executed_rolled_back` outcomes.** Customer's on-call rotation has a runbook entry for both. A.1 v0.1 produces structured audit logs; the customer's playbook must reference the F.6 5-axis query API to triage.

### Process prerequisites

10. **A.1 v0.2 OR equivalent has shipped with promotion tracking AND a live-cluster gate has been run for every customer environment.** The mocked-tests-only floor is too low for Stage 4.
11. **The board/investor framing has been corrected** to reflect that A.1 v0.1 ships Stages 1 + 2, not "production action" in the unqualified sense. Stage 3 and Stage 4 are conditional on items 1-10.

---

## §7. Why this record exists and what's next

This record exists because the implementation-completeness record at [`a1-verification-2026-05-16.md`](a1-verification-2026-05-16.md) said the safety primitives shipped without saying what counts as "shipped" for a production-action claim. It separates implementation hygiene (271 tests pass, mypy strict clean) from safety hygiene (promotion pipeline documented, kill switches drilled, real-cluster proof gathered).

The next steps:

1. **Close gate G3 (live `kind` run).** Operator runs the `NEXUS_LIVE_K8S=1` lane. Appends results to this file's §8 (Live-cluster proof log).
2. **Write the Phase-1c plan for promotion tracking.** Per §3 above. Should land before A.1 v0.2 or any new "do" agent.
3. **Write the customer-onboarding playbook addendum** that ratifies items 5-9 of §6. Required before any customer touches Stage 3.

Only when all three of these complete does the post-A.1 readiness report's "first 'do' agent online" framing become accurate at the customer-environment level. Until then, the framing is accurate at the **platform-capability level** and should be qualified accordingly in board/investor comms.

---

## §8. Live-cluster proof log

**Gate G3 closed at HEAD `96bd75c` (2026-05-16).** First entry below.

Each successful `NEXUS_LIVE_K8S=1` run records:

```
DATE: YYYY-MM-DD
COMMIT: <git sha at HEAD of the run>
KIND VERSION: <kind --version output>
K8S VERSION: <kubectl version output (server)>
MEASURED RECONCILE LATENCY: <seconds, from test_rollback_window_matches_real_reconcile>
TESTS PASSED: test_execute_validated_against_live_cluster | test_rollback_window_matches_real_reconcile
OPERATOR: <name / GitHub handle>
NOTES: <anything noteworthy about webhooks, RBAC quirks, etc.>
```

When this section has at least one entry, gate G3 is closed for that K8s minor version. Customers running a different K8s minor version need a separate entry — A.1 does not assume reconcile latency is the same across K8s versions.

---

### Entry 1 — kind v0.31.0 / K8s v1.30.0 / 2026-05-16

```
DATE:                       2026-05-16
COMMIT:                     96bd75cf4dfef5f0abffe6aa161b4f9f5e1d093a
KIND VERSION:               kind v0.31.0 go1.25.5 darwin/arm64
KIND NODE IMAGE:            kindest/node:v1.30.0
K8S SERVER VERSION:         v1.30.0
KUBECTL CLIENT VERSION:     v1.36.1
HOST:                       Darwin 25.4.0 arm64 (10 CPU, 7.6 GiB RAM)
DOCKER:                     29.1.3 (Docker Desktop)
MEASURED RECONCILE LATENCY: 0.26s (agent_overhead from test_rollback_window_matches_real_reconcile)
ROLLBACK_WINDOW_SEC:        300 (default)
CUSHION:                    299.74s (99.9% of the window unused)
TESTS PASSED:               test_execute_validated_against_live_cluster
                            test_rollback_window_matches_real_reconcile
TESTS XFAIL:                test_execute_rolled_back_against_live_cluster (pending webhook fixture)
OPERATOR:                   gowthamprabakar
TOTAL RUN WALL-CLOCK:       372s (full lane, 3 tests), 302s (measurement test alone)
```

#### What this entry proves

1. **The execute path actually applies a patch to a real cluster.** `test_execute_validated_against_live_cluster` deployed a Deployment with `runAsUser: 0`, ran A.1 with `--mode execute`, watched the agent invoke `kubectl patch`, watched the validator re-run D.6 against the live cluster, and confirmed the post-patch deployment has `runAsNonRoot: true`. Outcome: `executed_validated`. **The seven-stage pipeline is no longer a hypothesis.**

2. **The default `rollback_window_sec=300` is conservative-to-a-fault on kind.** Measured agent overhead (apply + re-detect + cleanup, excluding the rollback-window sleep) was **0.26 seconds**. The 300-second default leaves **299.74 seconds of cushion** — ~99.9% of the window is unused on this cluster shape. **No code fix needed.** On real customer clusters with mutating webhooks (OPA Gatekeeper, Linkerd / Istio sidecars), many controllers, and Pod-disruption budgets, reconcile latency will be substantially higher — but the default still has multi-order-of-magnitude headroom over the kind baseline. The runbook's "measure your cluster's actual reconcile latency before promoting to Stage 4" guidance remains the right framing.

3. **The post-validation re-detection contract works against a live cluster.** The validator's `build_d6_detector` closure ran `read_cluster_workloads` against the real cluster's kube-apiserver, found zero `run-as-root` findings post-patch, and returned `requires_rollback=False`. This was previously asserted only by mocked tests.

#### What this entry does NOT prove

1. **The rolled-back path.** `test_execute_rolled_back_against_live_cluster` is `xfail` pending a mutating-admission-webhook fixture. The follow-up CL needs to install (e.g.) OPA Gatekeeper or a custom MutatingWebhookConfiguration that strips `runAsNonRoot` on apply, then assert A.1's validator re-runs detection, finds the rule still firing, and applies the inverse patch automatically. **Until that test passes, the `executed_rolled_back` outcome is asserted only by mocked tests.**

2. **Real-customer reconcile latency.** The 0.26s measurement is on an empty kind cluster with no webhook chain. Production reconcile latency is higher and varies per cluster. Each customer's cluster needs a separate measurement before any Stage-4 promotion.

3. **Multi-tenant safety.** The cluster used here is single-namespace, single-customer. F.4 tenant-RLS / multi-tenant routing was not exercised by this run.

#### Operator follow-ups generated by this run

- **The 300s default may be too conservative for normal use.** A 30-60s default would still have >100x cushion on kind. The current default trades operator wait time for safety margin; that may be wrong for the `recommend` → `dry_run` promotion flow where operators want fast feedback. **No action this session** — empirical data from real customer clusters should drive the tuning, not kind data. Tracked as a Phase-1c hardening item.
- **The `xfail` rolled-back test should land before any customer enables Stage 3.** The validated path is proven; the rolled-back path is the safety claim that matters most when something goes wrong. Tracked as the highest-priority Phase-1c follow-up.

#### Reproduction

```bash
export PATH="/opt/homebrew/bin:/Applications/Docker.app/Contents/Resources/bin:$PATH"
open -a Docker && \
  until docker info >/dev/null 2>&1; do sleep 3; done
kind create cluster --name nexus-remediation-test --image kindest/node:v1.30.0
NEXUS_LIVE_K8S=1 uv run pytest \
    packages/agents/remediation/tests/integration/test_agent_kind_live.py -v -s
# Cluster persists across runs by design (operator-owned).
# Tear down via `kind delete cluster --name nexus-remediation-test`.
```

---

### Entry 2 — kind v0.31.0 / K8s v1.30.0 / 2026-05-17

Closes Task 13 of the [A.1 v0.1.1 earned-autonomy-pipeline plan](../superpowers/plans/2026-05-17-a-1-earned-autonomy-pipeline.md). Proves the v0.1.1 fail-closed default + evidence-emission + reconcile parity against a real Kubernetes apiserver, complementing Entry 1's proof of the execute path.

```
DATE:                       2026-05-17
COMMIT:                     1d730301a4b43879bce62c05bbd5733218315373
KIND VERSION:               kind v0.31.0 go1.25.5 darwin/arm64
KIND NODE IMAGE:            kindest/node:v1.30.0
K8S SERVER VERSION:         v1.30.0
KUBECTL CLIENT VERSION:     v1.36.1
HOST:                       Darwin 25.4.0 arm64 (10 CPU, 7.6 GiB RAM)
DOCKER:                     29.1.3 (Docker Desktop)
TESTS PASSED:               test_stage1_only_refuses_execute_against_live_cluster
                            test_promotion_evidence_emitted_to_audit_chain_live
                            test_reconcile_matches_tracker_state_live
OPERATOR:                   gowthamprabakar
TOTAL RUN WALL-CLOCK:       4.36s (three tests against the persistent cluster)
```

#### What this entry proves

1. **Stage 1 + `--mode execute` against a real Kubernetes apiserver refuses, with zero kubectl mutation.** `test_stage1_only_refuses_execute_against_live_cluster` ran the agent with a Stage-1 tracker and `RemediationMode.EXECUTE` against the real cluster. Two-layer proof:
   - **Python-level (subprocess spy):** `_install_mutating_kubectl_spy` wrapped `kubectl_executor._run` — the single chokepoint the executor's docstring names — with a counter. After the run: `mutating_kubectl_calls=0` AND `total_kubectl_calls=0`. The agent did not even read the cluster — the gate halted before the executor was reached.
   - **Cluster-level (resourceVersion):** the Deployment's `metadata.resourceVersion` was identical before and after (`rv_before=34034`, `rv_after=34034`). The Kubernetes apiserver never saw a write.

   Every prior test of the fail-closed default ran against `apply_patch`-level mocks. This is the first proof that the property holds against a real apiserver. Workload exercised: `nexus-rem-test/bad-app-1779012864`. Outcome: `refused_promotion_gate`.

2. **Successful actions emit `promotion.evidence.*` audit entries against a real cluster.** `test_promotion_evidence_emitted_to_audit_chain_live` ran the agent at Stage 2 + `--mode dry_run` — `kubectl --dry-run=server` hits the real apiserver, succeeds, the agent records evidence. Audit-chain assertion: exactly one `promotion.evidence.stage2` entry was emitted (payload `action_type = remediation_k8s_patch_runAsNonRoot`). Replay over the run's chain reconstructed `evidence.stage2_dry_runs=1`, matching the live tracker's counter end-to-end.

3. **`replay(audit_chain)` reproduces evidence counters identical to the live tracker against a real cluster run.** `test_reconcile_matches_tracker_state_live` drove a dry_run sequence and compared the replayed `PromotionFile.action_classes[X].evidence` to the live tracker's evidence field-by-field. They were equal (`{stage1_artifacts: 0, stage2_dry_runs: 1, stage3_executes: 0, ...}` on both sides). The §3 source-of-truth contract holds for the evidence surface against a real apiserver.

#### What this entry does NOT prove

1. **Reconcile parity for stage + sign-offs.** The agent's run-time audit chain does not include `promotion.advance.applied` / `promotion.init.applied` events — those come from the CLI `promotion advance` / `promotion init` paths. As a result, `replay()` cannot reconstruct the Stage 2 designation or the `advance(1→2)` sign-off from the dry_run chain alone. The tests assert evidence-counter parity (which the chain DOES carry); the stage + sign_offs limitation is the same one observed in Task 12 review for eval cases 012 / 013 and is documented in the test docstrings.

2. **The rolled-back path under a Stage-3 fixture.** Same xfail as Entry 1: `test_execute_rolled_back_against_live_cluster` still depends on a mutating-admission-webhook fixture that hasn't landed yet. The plan's immediate next-plan gate.

3. **Long-running drift.** All three tests run in ~4 seconds against an empty cluster. They prove the safety properties hold in the single-run case; they do not exercise audit-chain length, hash-chain integrity under high-volume runs, or cross-run state accumulation.

#### Operator follow-ups generated by this run

- **None blocking** — the fail-closed default is the single most load-bearing safety property of the plan, and it now holds against a real apiserver. The other items (rolled-back path webhook fixture, long-running drift) are tracked as Phase-1c hardening + the immediate next-plan gate respectively.

#### Reproduction

```bash
export PATH="/opt/homebrew/bin:/Applications/Docker.app/Contents/Resources/bin:$PATH"
open -a Docker && \
  until docker info >/dev/null 2>&1; do sleep 3; done
# Reuse the persistent cluster from Entry 1; create only if absent.
kind get clusters | grep -q nexus-remediation-test || \
    kind create cluster --name nexus-remediation-test --image kindest/node:v1.30.0
NEXUS_LIVE_K8S=1 uv run pytest \
    packages/agents/remediation/tests/integration/test_agent_kind_live.py -v -s \
    -k 'stage1_only_refuses or evidence_emitted_to_audit_chain_live or reconcile_matches_tracker_state_live'
# Cluster persists across runs by design (operator-owned).
```

---

## Sign-off

**A.1 v0.1 is safe to ship at Stages 1 + 2 (recommend, dry_run) today.** Stage 3 (human-approved execute) becomes safe to ship per-customer once items 1, 5, 6, 7, 9 of §6 close. Stage 4 (unattended execute) becomes safe to ship per-customer once items 1-10 close.

**The scope-collapse from three planned agents into one shipped agent is safe conditional on the four-stage promotion pipeline being followed.** Without the pipeline, the collapse would auto-promote every action class to Stage 4, which is the failure mode A.1's safety contract is designed to prevent. The pipeline is the product, not the cure-quadrant calendar compression.

**Pending gates** before any v0.2 work or any further "do"-agent build:

- ✅ G1: Math correction recorded — [`wiz-coverage-math-correction-2026-05-16.md`](wiz-coverage-math-correction-2026-05-16.md)
- ✅ G2: `--mode execute` locked OFF by default
- ⚠️ G3: `NEXUS_LIVE_K8S=1` lane scaffolded; actual run pending operator
- ✅ G4: This record exists

— recorded 2026-05-16 (post-A.1, safety-verification record)
