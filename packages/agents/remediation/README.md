# `nexus-remediation-agent`

Remediation Agent — A.1; **first "do" agent** in the platform; **tenth under [ADR-007](../../../docs/_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md)** (F.3 / D.1 / D.2 / D.3 / F.6 / D.7 / D.4 / D.5 / D.6 / **A.1**). **Opens the cure quadrant of the build roadmap.**

> **Version:** v0.1 (2026-05-16) — **production-action mode**: ships all three operational tiers (`recommend` / `dry_run` / `execute`) as `--mode` flags on a single agent, gated by safety primitives that match each mode's blast radius. Re-scoped from the original three-plan (A.1 / A.2 / A.3) split per the 2026-05-16 user direction "make it production action."

## What it does

A.1 emits OCSF v1.3 Remediation Activity (`class_uid 2007`) for every remediation it considers — recommended, dry-run, executed, rolled-back, or refused. Given an `ExecutionContract` and a `findings.json` from a detect agent (D.6 today; D.5 / F.3 / D.1 later), A.1 runs a **seven-stage pipeline**:

```
INGEST → AUTHZ → GENERATE → DRY-RUN → EXECUTE → VALIDATE → ROLLBACK
```

Three operational tiers, gated by separate `auth.yaml`:

- **`--mode recommend`** (default; lowest blast radius) — generate artifacts only; no execution. The CI/PR review surface: operators see exactly what would change.
- **`--mode dry_run`** — execute against `kubectl --dry-run=server`; reports the diff but applies nothing. Catches admission webhook + RBAC failures before they touch the cluster.
- **`--mode execute`** — apply for real with **mandatory post-validation + rollback timer**. Re-runs the D.6 detector after `rollback_window_sec` (default 300s; 60-1800); if the rule is still firing, the inverse patch reverts the change automatically.

The `execute` mode is **only allowed when explicitly opted in via `mode_execute_authorized: true` in `auth.yaml`**. Per-run defaults to `recommend`; operators must opt in to higher tiers.

## ADR-007 conformance

A.1 is the **tenth** agent under the reference template. Inherits v1.1 (LLM adapter via `charter.llm_adapter`; no per-agent `llm.py`) and v1.2 (NLAH loader is a 21-LOC shim — A.1 is the **7th native v1.2 agent**). **Not** in the v1.3 always-on class — A.1 honours every budget axis. **Does not consume** the v1.4 candidate; single-driver per the agent spec.

**Schema wire shape (Q8).** A.1 is the **first producer of OCSF `class_uid 2007 Remediation Activity`** in the platform. Wire shape is independent of the input finding shape — A.1 emits its own OCSF class regardless of which detect agent produced the input. `finding_info.types[0]` carries the action_type (`remediation_k8s_patch_runAsNonRoot`, etc.). `finding_info.analytic.name` carries the outcome (`recommended_only` / `dry_run_only` / `executed_validated` / `executed_rolled_back` / `refused_unauthorized` / `refused_blast_radius` / `dry_run_failed` / `execute_failed`). Downstream consumers (D.7 Investigation, fabric routing) filter on `class_uid 2007` and route by outcome.

**REM_FINDING_ID_RE.** `^REM-[A-Z0-9]+-\d{3}-[a-z0-9_-]+$` — widened from F.3's `[A-Z]+` cloud-token to admit the `K8S` token (same widening D.6 applied to the cloud regex).

LLM use: **not load-bearing** (matches D.5 + D.6). Action class builders, the generator, the validator, and the summarizer are all deterministic pure functions. The `LLMProvider` parameter on `agent.run` is plumbed but never called in v0.1 — keeps the contract surface stable when Phase 1c adds optional LLM narrative.

## Quick start

```bash
# 1. Run the local eval suite (10/10)
uv run remediation eval packages/agents/remediation/eval/cases

# 2. Run via the eval-framework (resolves through nexus_eval_runners entry-point)
uv run eval-framework run \
    --runner remediation \
    --cases packages/agents/remediation/eval/cases \
    --output /tmp/a1-eval-out.json

# 3a. Run against an ExecutionContract — recommend mode (no cluster access)
uv run remediation run \
    --contract path/to/contract.yaml \
    --findings /path/to/d6-findings.json
# → emits artifacts only; no kubectl call. Safe to run in CI.

# 3b. Dry-run against a live cluster — explicit kubeconfig
uv run remediation run \
    --contract path/to/contract.yaml \
    --findings /path/to/d6-findings.json \
    --auth path/to/auth.yaml \
    --mode dry_run \
    --kubeconfig ~/.kube/config

# 3c. Execute against a live cluster — explicit kubeconfig + opt-in auth
uv run remediation run \
    --contract path/to/contract.yaml \
    --findings /path/to/d6-findings.json \
    --auth path/to/auth.yaml \
    --mode execute \
    --kubeconfig ~/.kube/config \
    --rollback-window-sec 300

# 3d. Execute as a Pod inside the cluster — production deployment mode
uv run remediation run \
    --contract path/to/contract.yaml \
    --findings /path/to/d6-findings.json \
    --auth path/to/auth.yaml \
    --mode execute \
    --in-cluster
```

The two cluster-access modes (`--kubeconfig`, `--in-cluster`) are **mutually exclusive**. `--mode dry_run` and `--mode execute` both **require** cluster access; `--mode recommend` runs without any cluster connection.

See [`runbooks/remediation_workflow.md`](runbooks/remediation_workflow.md) for the full operator workflow (auth.yaml schema · RBAC requirements · the 7-stage pipeline · execute-mode safety playbook · rollback semantics · routing findings to D.7 Investigation + F.6 Audit · troubleshooting).

## Architecture — 7-stage pipeline

```
findings.json (D.6 OCSF 2003)
         │
         ▼ INGEST       — read_findings (Stage 1)
         │
         ▼ AUTHZ        — filter by auth.authorized_actions allowlist (Stage 2)
         │                + enforce blast-radius cap (max_actions_per_run)
         │
         ▼ GENERATE     — per-finding → RemediationArtifact (Stage 3)
         │                pure-function builder + inverse-patch pair
         │
         ▼ DRY-RUN      — kubectl --dry-run=server apply (Stage 4)
         │                always runs in dry_run + execute modes
         │
         ▼ EXECUTE      — kubectl patch (Stage 5; execute mode only)
         │                pre/post-patch SHA-256 captured for audit
         │
         ▼ VALIDATE     — wait rollback_window_sec; re-run D.6 (Stage 6)
         │                checks if the original rule_id still fires
         │
         ▼ ROLLBACK     — apply inverse patch if Stage 6 said so (Stage 7)
         │
         ▼ HANDOFF      — findings.json (OCSF 2007) + report.md + audit.jsonl
                          + dry_run_diffs.json + execution_results.json
                          + rollback_decisions.json + artifacts/<corr>.json
```

Five action class builders ([`action_classes/`](src/remediation/action_classes/)), one generator ([`generator.py`](src/remediation/generator.py)), one kubectl executor ([`tools/kubectl_executor.py`](src/remediation/tools/kubectl_executor.py)), one validator + post-detection re-run ([`validator.py`](src/remediation/validator.py)), one summarizer with dual-pin pattern ([`summarizer.py`](src/remediation/summarizer.py)), and the agent driver ([`agent.py`](src/remediation/agent.py)).

## The five v0.1 K8s action classes

| D.6 rule_id                    | RemediationActionType                                | What the patch does                                              |
| ------------------------------ | ---------------------------------------------------- | ---------------------------------------------------------------- |
| `run-as-root`                  | `remediation_k8s_patch_runAsNonRoot`                 | Set `securityContext.runAsNonRoot: true` + `runAsUser: 65532`    |
| `missing-resource-limits`      | `remediation_k8s_patch_resource_limits`              | Set `resources.limits.{cpu: 500m, memory: 256Mi}` (conservative) |
| `read-only-root-fs-missing`    | `remediation_k8s_patch_readOnlyRootFilesystem`       | Set `securityContext.readOnlyRootFilesystem: true`               |
| `image-pull-policy-not-always` | `remediation_k8s_patch_imagePullPolicy_Always`       | Set `imagePullPolicy: Always` on the affected container          |
| `allow-privilege-escalation`   | `remediation_k8s_patch_disable_privilege_escalation` | Set `securityContext.allowPrivilegeEscalation: false`            |

Each action class is a `(build, inverse)` pair. The inverse patch is what makes deterministic rollback work — Stage 7 swaps `patch_body` ↔ `inverse_patch_body` and re-applies. All five use strategic-merge-patch with container `name` as the merge key.

## Output contract — the seven artifacts

| File                       | Format                                | Purpose                                                                                                                               |
| -------------------------- | ------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| `findings.json`            | `RemediationReport.model_dump_json()` | Wire shape consumed by D.7 Investigation, fabric routing. **OCSF 2007 — first producer in the platform.**                             |
| `report.md`                | Markdown                              | Operator summary. **Dual-pin pattern:** rollbacks pinned first, failures second. Per-outcome breakdown ordered most-actionable-first. |
| `artifacts/<corr_id>.json` | JSON                                  | One file per generated artifact — the exact kubectl-patch body (and inverse) the agent would apply. The operator review surface.      |
| `dry_run_diffs.json`       | JSON list                             | Per-action server-side dry-run results. Always written in `dry_run` + `execute` modes.                                                |
| `execution_results.json`   | JSON list                             | Per-action pre/post-patch state + SHA-256 hashes. Execute mode only.                                                                  |
| `rollback_decisions.json`  | JSON list                             | Per-action validate-pass/fail + rollback flag + matched-findings count. Execute mode only.                                            |
| `audit.jsonl`              | `charter.audit.AuditEntry` JSON-lines | This run's own F.6 hash-chained audit log. **11-action `remediation.*` vocabulary.** Tamper-evident pre/post-patch SHA-256 chain.     |

## Earned-autonomy pipeline (v0.1.1+)

Each action class lives in one of four graduation stages **per customer environment**. The pre-flight stage gate in `agent.run()` reads the action class's stage from `promotion.yaml` (the operator-readable cache; the F.6 audit chain is the source of truth) and refuses any operator-requested mode that exceeds the stage cap:

| Stage | What runs                                   | Required sign-off chain                                                                                                          |
| ----- | ------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| 1     | `recommend` (artifact emission, no kubectl) | None (the floor; absent action classes are implicitly Stage 1)                                                                   |
| 2     | `dry_run` (kubectl --dry-run=server)        | `advance(1→2)`                                                                                                                   |
| 3     | `execute` (human-approved per-action)       | `advance(1→2)` then `advance(2→3)` (chronological)                                                                               |
| 4     | `execute` (unattended)                      | **Globally closed in code** pending the rolled-back-path mutating-admission-webhook fixture + ≥4 weeks customer Stage-3 evidence |

Per-finding routing: when one run carries findings spanning multiple stages, each artifact gets its own effective mode (Stage-1 finding → `RECOMMENDED_ONLY`, Stage-2 finding → `DRY_RUN_ONLY`, Stage-3 finding → `EXECUTED_VALIDATED`) in a single audit chain. When **all** authorised artifacts would be downgraded and the operator's requested mode is non-recommend, the gate emits `REFUSED_PROMOTION_GATE` per finding with zero kubectl contact (proven against mocks in [`test_promotion_gate.py`](tests/test_promotion_gate.py) and against a real `kind` cluster in [`test_agent_kind_live.py`](tests/integration/test_agent_kind_live.py) — see safety-verification [§8 Entry 2](../../../docs/_meta/a1-safety-verification-2026-05-16.md#entry-2--kind-v0310--k8s-v1300--2026-05-17)).

Operator surface: the `remediation promotion` CLI subcommand group (`status` / `init` / `advance` / `demote` / `reconcile`). v0.1.1 ships the package + the CLI; the `remediation run` subcommand does not yet wire `--promotion <path>` (v0.1.2 task). Full migration guide for v0.1 operators in [the runbook §14](runbooks/remediation_workflow.md#14-v01--v011-migration); schema reference in [§13](runbooks/remediation_workflow.md#13-promotionyaml-schema-reference-v011). The v0.1.1 verification record (gates, coverage delta, ADR-007 conformance, four-boundary process notes, the permanent `reconcile_matches` limitation) is at [`a1-v0-1-1-verification-2026-05-17.md`](../../../docs/_meta/a1-v0-1-1-verification-2026-05-17.md).

## Nine safety primitives

A.1's "production action" claim rests on nine layered gates:

1. **Pre-authorized allowlist** — only action_types named in `auth.authorized_actions` can build.
2. **Mode-escalation gate** — `dry_run` / `execute` require explicit `mode_*_authorized: true` flags; raises `AuthorizationError` if missing.
3. **Blast-radius cap** — `max_actions_per_run` (default 5; 1-50). Whole run refused if exceeded — no partial application.
4. **Mandatory dry-run** — Stage 4 always runs in `dry_run` + `execute` modes. Webhook / RBAC failures caught before Stage 5.
5. **Rollback timer** — Stage 6 waits `rollback_window_sec` (60-1800) and re-runs the source detector. If the rule is still firing, Stage 7 rolls back automatically.
6. **Hash-chained audit** — every stage emits an F.6 audit entry; chain head + tail hashes pinned in `report.md`.
7. **Idempotency** — `correlation_id` is SHA-256 of `(namespace/workload/container/rule_context)[:16]`; repeated runs collapse to the same id.
8. **Workspace-scoped state** — all 7 output files under `contract.workspace/`; the agent never writes elsewhere.
9. **3-way cluster-access exclusion** — `--manifest-target` (no execute) vs `--kubeconfig` vs `--in-cluster`. Surfaces as `click.UsageError` at the CLI.

## Tests

```bash
uv run pytest packages/agents/remediation -q
```

~445 tests (v0.1.1, +174 from v0.1); mypy strict clean. **15/15 eval acceptance gate** via the eval-framework entry-point:

```bash
uv run eval-framework run --runner remediation \
    --cases packages/agents/remediation/eval/cases \
    --output /tmp/a1-eval-out.json
# → 15/15 passed (100.0%)
```

The 15 eval cases cover the v0.1 surface (10 cases — clean, recommend / dry-run / execute-validated / execute-rolled-back single-action paths, unauthorized-action refusal, unauthorized-mode refusal, blast-radius cap, multi-finding batch, mixed-action-classes) plus the v0.1.1 earned-autonomy surface (5 cases — Stage-1-blocked dry_run, Stage-2-blocked execute, mixed-per-finding Stage 1/2/3 routing, advance-proposed evidence threshold, reconcile-round-trip chain replay). The runner parses `fixture.promotion` and plumbs into `agent.run(promotion=...)` so the pre-flight gate is ACTIVE on every case — no skip-lists, no filters.

## License

BSL 1.1 per [ADR-001](../../../docs/_meta/decisions/ADR-001-monorepo-bootstrap.md). Substrate this agent consumes (`charter`, `cloud-posture`, `k8s-posture`, `eval-framework`) is Apache 2.0; the agent itself is BSL.
