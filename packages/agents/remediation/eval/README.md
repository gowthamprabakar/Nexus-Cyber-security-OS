# A.1 eval cases — fixture schema reference

This directory contains the YAML acceptance suite for the Remediation
Agent. The suite is loaded by `RemediationEvalRunner`
([`eval_runner.py`](../src/remediation/eval_runner.py)) and executed via:

```bash
uv run remediation eval packages/agents/remediation/eval/cases
# or via the eval-framework entry point:
uv run eval-framework run --runner remediation \
    --cases packages/agents/remediation/eval/cases \
    --output /tmp/a1-eval-out.json
```

The acceptance gate is **N/N passed** where N is the number of cases —
currently 10 (v0.1) shipping in this directory, growing to 15 with the
A.1 v0.1.1 earned-autonomy-pipeline tasks.

## Case file shape

Each `*.yaml` file under `cases/` is parsed as a `EvalCase` by the
eval-framework, then handed to `RemediationEvalRunner.run()`. Top-level
keys:

| Key           | Type | Description                                                                                       |
| ------------- | ---- | ------------------------------------------------------------------------------------------------- |
| `case_id`     | str  | Unique identifier; filename stem by convention (e.g. `004_single_action_execute_validated`).      |
| `description` | str  | Free-text. Surfaces in the failure report when the case doesn't pass.                             |
| `fixture`     | dict | The agent-input scaffold — see [Fixture schema](#fixture-schema).                                 |
| `expected`    | dict | Assertions the runner makes against the agent's report — see [Expected schema](#expected-schema). |

## Fixture schema

```yaml
fixture:
  mode: recommend | dry_run | execute
  authorization:
    mode_recommend_authorized: bool
    mode_dry_run_authorized: bool
    mode_execute_authorized: bool
    authorized_actions: [str, ...] # RemediationActionType values
    max_actions_per_run: int (1-50)
    rollback_window_sec: int (60-1800)
  promotion: # v0.1.1 — see "Promotion field" below
    schema_version: '0.1'
    cluster_id: str
    created_at: ISO 8601 UTC
    last_modified_at: ISO 8601 UTC
    action_classes: dict[action_type, ActionClassPromotion]
  findings: [ManifestFinding, ...] # D.6-shaped detect findings
  dry_run_result: { exit_code, ... } # optional; defaults to success
  execute_result: { exit_code, ... } # optional; defaults to success
  rollback_result: { exit_code, ... } # optional; defaults to success
  post_validate_findings: [ManifestFinding, ...] # what the validator sees post-patch
```

### Promotion field (added in v0.1.1)

The `fixture.promotion` block declares the per-action-class
**graduation-state assumption** for the case — what stages the
PromotionTracker should be in when `agent.run()` is invoked.

**Shape.** The same shape as
[`promotion.yaml`](../src/remediation/promotion/schemas.py) (the
operator-readable cache that the safety-verification §3 contract names
as the _cache_ over the F.6 source-of-truth audit chain):

```yaml
fixture:
  promotion:
    schema_version: '0.1' # pinned; bumping is a separate migration
    cluster_id: eval-fixture # operator-supplied label
    created_at: '2026-05-17T00:00:00Z' # UTC-aware
    last_modified_at: '2026-05-17T00:00:00Z' # >= created_at
    action_classes:
      remediation_k8s_patch_runAsNonRoot:
        action_type: remediation_k8s_patch_runAsNonRoot
        stage: 3 # 1 / 2 / 3 (Stage 4 is globally closed in v0.1.1)
        sign_offs:
          - event_kind: advance | demote
            operator: alice
            timestamp: '2026-05-17T00:00:00Z'
            reason: 'free-text justification'
            from_stage: 1
            to_stage: 2
          # ... one sign-off per stage transition; chronologically ordered
```

**Conventions for the 10 v0.1 cases:**

| Case mode   | Required stage      | Action-classes shape                                                   |
| ----------- | ------------------- | ---------------------------------------------------------------------- |
| `recommend` | Stage 1 (the floor) | Empty `{}` — every action class implicitly at Stage 1.                 |
| `dry_run`   | Stage 2+            | `{action_type: { stage: 2, sign_offs: [advance(1→2)] }}`               |
| `execute`   | Stage 3+            | `{action_type: { stage: 3, sign_offs: [advance(1→2), advance(2→3)] }}` |

**Stage 4 in fixtures.** Forbidden. Stage 4 is globally closed in
v0.1.1 — the pre-flight gate ([safety-verification §6
items 3+4](../../../../docs/_meta/a1-safety-verification-2026-05-16.md#platform-side-prerequisites))
holds until two Phase-1c prerequisites land. Fixtures that need Stage 4
behavior should refuse the run (test `010_promotion_blocked_*` in
Task 10 covers this surface).

**Default when omitted.** Reserved for Task 12 — the eval runner will
synthesize "every action class at the stage required by `fixture.mode`"
when `promotion` is absent. v0.1.1 cases declare the field explicitly
for clarity.

### Findings shape (ManifestFinding)

```yaml
- rule_id: run-as-root # D.6 manifest analyser rule_id
  rule_title: 'Container running as root'
  severity: critical | high | medium | low | info
  workload_kind: Deployment | StatefulSet | DaemonSet | Pod | ReplicaSet | Job | CronJob
  workload_name: api
  namespace: production
  container_name: nginx
  manifest_path: cluster:///production/Deployment/api
  detected_at: '2026-05-16T12:00:00Z'
```

### Per-stage subprocess results

```yaml
dry_run_result:
  exit_code: 0 # 0 = success; non-zero = failure
  stdout: 'deployment.apps/api patched (dry run)' # optional
  stderr: '...' # optional
execute_result:
  exit_code: 0
rollback_result:
  exit_code: 0 # only consulted on the rolled-back path
post_validate_findings: [] # empty = rule no longer fires = validated
```

Omitting any of these uses the runner's success default.

## Expected schema

```yaml
expected:
  finding_count: int # report.total
  by_outcome: # report.count_by_outcome()
    recommended_only: int
    dry_run_only: int
    executed_validated: int
    executed_rolled_back: int
    refused_unauthorized: int
    refused_blast_radius: int
    refused_promotion_gate: int # v0.1.1
    dry_run_failed: int
    execute_failed: int
  action_types_distinct: int # len(unique action_types in report)
  raises: AuthorizationError | PromotionGateError | ... # for cases that should raise
  raises_match: regex # optional: error message must contain this regex
```

Only the keys you specify are asserted; missing keys are not checked.

## Index of v0.1 cases

| Case                                    | Mode      | Highlight                                                         |
| --------------------------------------- | --------- | ----------------------------------------------------------------- |
| `001_clean`                             | recommend | No findings → empty report.                                       |
| `002_single_action_recommend`           | recommend | One artifact, no kubectl.                                         |
| `003_single_action_dry_run`             | dry_run   | Stage 2 fixture; one successful dry-run.                          |
| `004_single_action_execute_validated`   | execute   | Stage 3 fixture; validated execute (no rollback).                 |
| `005_single_action_execute_rolled_back` | execute   | Stage 3 fixture; validator sees the rule still firing → rollback. |
| `006_unauthorized_action_refused`       | recommend | Action class not in allowlist → REFUSED_UNAUTHORIZED.             |
| `007_unauthorized_mode_refused`         | execute   | `mode_execute_authorized: false` → `AuthorizationError` raised.   |
| `008_blast_radius_cap`                  | recommend | 5 findings + cap 2 → whole run REFUSED_BLAST_RADIUS.              |
| `009_multi_finding_batch`               | recommend | 3 same-class findings → 3 RECOMMENDED_ONLY outcomes.              |
| `010_mixed_action_classes`              | recommend | 3 different classes → 3 distinct action_types.                    |

## Index of v0.1.1 cases (promotion surface — pending Task 12 runner wiring)

The 5 cases below ship in
[A.1 v0.1.1 Task 10](../../../../docs/superpowers/plans/2026-05-17-a-1-earned-autonomy-pipeline.md)
as authoritative spec for the promotion surface. They are not yet executable
by the runner — the `fixture.promotion` parser, the `REFUSED_PROMOTION_GATE`
outcome, and the new assertion keys (`by_promotion_proposal`,
`reconcile_matches`) all land in Task 12, at which point the eval-suite
acceptance gate flips from 10/10 to 15/15. Until then the runner-test asserts
the 5 YAMLs parse as valid `EvalCase` objects (catches schema drift) and
defers execution.

| Case                               | Mode      | Highlight                                                                                       |
| ---------------------------------- | --------- | ----------------------------------------------------------------------------------------------- |
| `011_promotion_blocked_at_stage_1` | dry_run   | Stage 1 + dry_run → REFUSED_PROMOTION_GATE (auth passes, promotion gate fires).                 |
| `012_promotion_blocked_at_stage_2` | execute   | Stage 2 + execute → REFUSED_PROMOTION_GATE.                                                     |
| `013_promotion_mixed_per_finding`  | execute   | Stages 1/2/3 across 3 findings → 1× RECOMMENDED_ONLY + 1× DRY_RUN_ONLY + 1× EXECUTED_VALIDATED. |
| `014_promotion_advance_proposed`   | recommend | Stage 1 + 1 artifact crosses `_STAGE1_ARTIFACT_THRESHOLD` → propose(1→2).                       |
| `015_reconcile_round_trip`         | recommend | 3 evidence events + 1 propose; `replay(chain)` matches the live tracker.                        |
