# A.1 `NEXUS_LIVE_K8S=1` integration lane — runbook

**What this is.** Operator-facing runbook for the gate-G3 integration lane: prove A.1's `execute` path against a real `kind` cluster.

**Why it exists.** A.1 v0.1's 271 unit tests + 10 eval cases all mock `kubectl`. They prove the contract; they do not prove the integration. Every safety claim that depends on a real K8s API (the rollback timer fires within reconcile latency, the inverse patch reverts the workload, post-validation re-detects the rule on the live cluster) is a hypothesis until this lane runs green.

**Gate G3 closure criterion:** all three tests in [`tests/integration/test_agent_kind_live.py`](../tests/integration/test_agent_kind_live.py) pass against a fresh `kind` v1.30+ cluster in a single `NEXUS_LIVE_K8S=1` run.

---

## Prerequisites

| Tool      | Min version | Install (macOS)              |
| --------- | ----------- | ---------------------------- |
| Docker    | 24+         | `brew install --cask docker` |
| `kind`    | 0.22+       | `brew install kind`          |
| `kubectl` | 1.28+       | `brew install kubectl`       |

Linux: equivalent package-manager commands; or download release binaries from `https://github.com/kubernetes-sigs/kind/releases` and `https://kubernetes.io/releases/download/`.

---

## One-time setup

```bash
# 1. Bring up a kind cluster the test fixtures reuse across runs.
kind create cluster --name nexus-remediation-test --image kindest/node:v1.30.0

# 2. Verify the cluster is reachable.
kubectl --context kind-nexus-remediation-test get nodes
# → 1 node Ready
```

Cluster lifecycle is **operator-owned** by design. The test fixtures only read from an existing cluster — they do not create or tear it down. This keeps fast-dev cycles cheap (no per-test cluster spin-up) and makes failures inspectable after the run.

---

## Running the lane

```bash
NEXUS_LIVE_K8S=1 uv run pytest \
    packages/agents/remediation/tests/integration/test_agent_kind_live.py -v
```

Expected output on a green run:

```
test_execute_validated_against_live_cluster PASSED       [ 33%]
test_execute_rolled_back_against_live_cluster XFAIL      [ 66%]   (webhook fixture pending — see module docstring)
test_rollback_window_matches_real_reconcile PASSED       [100%]
```

If `test_execute_validated_against_live_cluster` **passes**: gate G3 is closed for the happy path. The `execute` mode actually applies patches to a real cluster, the validator re-runs against the real cluster, and the outcome matches.

If `test_rollback_window_matches_real_reconcile` **passes**: gate G3 is closed for the timing claim. The default `rollback_window_sec=300` has been measured against a real cluster's reconcile latency with ≥30s cushion.

`test_execute_rolled_back_against_live_cluster` is currently `xfail` and **does not block G3 closure** — the rolled-back path requires a mutating-admission-webhook fixture (e.g. OPA Gatekeeper or a custom hook stripping `runAsNonRoot`). That fixture is the gate-G3-followup work and is tracked in the module docstring.

---

## Inspecting failures

The test workspace is `tmp_path` per test invocation — pytest's default. To inspect what A.1 wrote to disk after a failure, re-run with `--basetemp` to pin the workspace:

```bash
mkdir -p /tmp/nexus-rem-debug
NEXUS_LIVE_K8S=1 uv run pytest \
    packages/agents/remediation/tests/integration/test_agent_kind_live.py \
    --basetemp /tmp/nexus-rem-debug -v
# Then inspect:
ls /tmp/nexus-rem-debug/test_execute_validated_against_*/ws/
# → findings.json  report.md  audit.jsonl  dry_run_diffs.json
# → execution_results.json  rollback_decisions.json  artifacts/
```

The kind cluster's state from the failing test is **left in place** (the fixtures don't tear down the workload). Inspect via:

```bash
kubectl --context kind-nexus-remediation-test -n nexus-rem-test get deployments
kubectl --context kind-nexus-remediation-test -n nexus-rem-test describe deployment bad-app-...
kubectl --context kind-nexus-remediation-test -n nexus-rem-test get events --sort-by='.lastTimestamp'
```

When the test bed is too crowded:

```bash
kubectl --context kind-nexus-remediation-test delete namespace nexus-rem-test
# (the test will recreate it on next run)
```

---

## Tearing down

The cluster persists across runs by design. To remove it entirely:

```bash
kind delete cluster --name nexus-remediation-test
```

---

## CI integration (follow-up)

This lane is currently **manual-only**. The follow-up work for CI integration is one of:

1. **GitHub Actions self-hosted runner** with Docker-in-Docker, running `kind create cluster` per workflow. Higher cost; isolated state.
2. **GKE Autopilot ephemeral cluster** invoked per PR via `gcloud container clusters create-auto`. Higher latency; production-shaped network.
3. **Reusable kind cluster on a long-lived self-hosted runner**, gated by a label like `live-k8s-test`. Lowest cost; shared state requires careful namespace hygiene.

Recommendation: option 3 for the initial CI lane, with a per-run namespace prefix (`nexus-rem-test-${PR}-${SHA}`) so concurrent runs don't collide. Pull-request commenting includes the test output so reviewers see the green G3 gate explicitly.

CI integration is **not gate-G3 closure**. The local-run criterion above is sufficient. CI is a Phase-1c hardening task (track O.1 Observability).

---

## What "gate G3 closed" looks like

Three things, in order:

1. `test_execute_validated_against_live_cluster` passes (the happy-path integration claim).
2. `test_rollback_window_matches_real_reconcile` passes (the timing-default claim).
3. A short note appended to [`docs/_meta/a1-safety-verification-2026-05-16.md`](../../../../docs/_meta/a1-safety-verification-2026-05-16.md) records the date, the kind version, the cluster's measured reconcile latency, and the commit hash at which the lane ran green.

Until that note exists in the safety-verification record, **the `--i-understand-this-applies-patches-to-the-cluster` flag should not be supplied in any environment that holds real workloads.**
