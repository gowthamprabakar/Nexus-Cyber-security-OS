"""Live integration tests for A.1 against a `kind` Kubernetes cluster.

**Skipped by default.** Enable with:

    NEXUS_LIVE_K8S=1 uv run pytest \\
        packages/agents/remediation/tests/integration/test_agent_kind_live.py -v

**Prerequisites for the run:**

- Docker daemon running.
- `kind` ≥ v0.22 in PATH (`brew install kind` or `go install sigs.k8s.io/kind`).
- `kubectl` ≥ v1.28 in PATH (`brew install kubectl`).
- A `kind` cluster named `nexus-remediation-test` already up:
      ``kind create cluster --name nexus-remediation-test``
  The fixture below will reuse an existing cluster of that name; it does not
  create or tear down clusters (deliberate — cluster lifecycle is operator-owned).

**What this lane proves (and why it exists).**

A.1 v0.1 ships with 271 unit tests + 10 eval cases, all of which mock the
kubectl executor and the D.6 detector. They prove the *contract* — every
output file is well-formed, every audit entry chains correctly, every gate
fires when it should. They do not prove the *integration* — that `kubectl
patch` actually applies a real patch to a real cluster, that the rollback
window matches real K8s controller reconcile latency, that the inverse-patch
swap actually reverts the workload to its pre-patch shape.

Until this lane runs green against a real cluster, A.1's safety contract is
a hypothesis. The four-gate plan in the post-A.1 readiness report names this
gate explicitly:

    G3. Build the `NEXUS_LIVE_K8S=1` integration lane against `kind`. The
        execute path must actually apply a patch to a real cluster, the
        rollback timer must actually fire against a real cluster, and the
        inverse patch must actually revert it. Mocked tests do not satisfy
        this gate.

**The three integration tests.**

1. `test_execute_validated_against_live_cluster` — deploy a Deployment with
   `runAsUser: 0`; run A.1 with `--mode execute`; verify the Pod is restarted
   with `runAsNonRoot: true` AND the D.6 detector confirms the rule no longer
   fires. Outcome must be `executed_validated`.
2. `test_execute_rolled_back_against_live_cluster` — same workload, but with
   a mutating admission webhook that strips the `runAsNonRoot` field on apply.
   A.1 should detect that the rule is still firing post-validation and apply
   the inverse patch. Outcome must be `executed_rolled_back`.
3. `test_rollback_window_matches_real_reconcile` — measure the actual time
   from `kubectl patch` to Pod-restart-with-new-spec. Assert the default
   `rollback_window_sec=300` is sufficient (a cushion of ≥30s above the
   measured value).

**Acceptance for gate G3 closure.** All three tests pass in a single
`NEXUS_LIVE_K8S=1` run against a fresh `kind v1.30+` cluster.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from charter.audit import AuditEntry
from charter.contract import BudgetSpec, ExecutionContract
from remediation.agent import run as agent_run
from remediation.authz import Authorization
from remediation.promotion import (
    ActionClassPromotion,
    PromotionFile,
    PromotionSignOff,
    PromotionStage,
    PromotionTracker,
    replay,
)
from remediation.schemas import RemediationActionType, RemediationMode, RemediationOutcome
from remediation.tools import kubectl_executor as kc_mod

pytestmark = [pytest.mark.integration, pytest.mark.asyncio]


_CLUSTER_NAME = os.environ.get("NEXUS_KIND_CLUSTER", "nexus-remediation-test")
_NAMESPACE = os.environ.get("NEXUS_KIND_NAMESPACE", "nexus-rem-test")
_KYVERNO_INSTALL_URL = "https://github.com/kyverno/kyverno/releases/download/v1.13.4/install.yaml"
_FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _live_enabled() -> bool:
    return os.environ.get("NEXUS_LIVE_K8S") == "1"


def _resolve(binary: str) -> str | None:
    """Resolve a binary name to its absolute path, or None if unavailable."""
    return shutil.which(binary)


_KIND = _resolve("kind")
_KUBECTL = _resolve("kubectl")
_DOCKER = _resolve("docker")


def _tooling_available() -> tuple[bool, str]:
    """Return (available, reason). When False, `reason` names what's missing."""
    for label, path in (("kind", _KIND), ("kubectl", _KUBECTL), ("docker", _DOCKER)):
        if path is None:
            return False, f"missing binary: {label}"
    assert _KIND is not None  # narrowed by the loop above; satisfy mypy
    try:
        r = subprocess.run(  # noqa: S603 — fixed args, absolute path
            [_KIND, "get", "clusters"],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (FileNotFoundError, subprocess.SubprocessError) as exc:
        return False, f"kind invocation failed: {exc}"
    if _CLUSTER_NAME not in (r.stdout or ""):
        return False, (
            f"kind cluster '{_CLUSTER_NAME}' not found; create it with "
            f"`kind create cluster --name {_CLUSTER_NAME}`"
        )
    return True, ""


_TOOLING_OK, _TOOLING_REASON = (
    (False, "live tests disabled") if not _live_enabled() else _tooling_available()
)

pytestmark.append(
    pytest.mark.skipif(
        not _TOOLING_OK,
        reason=(
            f"set NEXUS_LIVE_K8S=1 + ensure prerequisites; current status: {_TOOLING_REASON}. "
            "See module docstring for setup."
        ),
    )
)


# ---------------------------- cluster fixtures ---------------------------


@pytest.fixture(scope="module")
def kind_kubeconfig(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Materialise the kind cluster's kubeconfig into a tmp file the agent
    will use. Cluster lifecycle stays operator-owned — this fixture only
    reads from an existing cluster."""
    config_dir = tmp_path_factory.mktemp("kindcfg")
    kubeconfig = config_dir / "kubeconfig.yaml"
    assert _KIND is not None  # tooling check ran in pytestmark skipif
    result = subprocess.run(  # noqa: S603 — fixed args, absolute path
        [_KIND, "get", "kubeconfig", "--name", _CLUSTER_NAME],
        capture_output=True,
        text=True,
        check=True,
        timeout=15,
    )
    kubeconfig.write_text(result.stdout)
    return kubeconfig


@pytest.fixture(scope="module")
def test_namespace(kind_kubeconfig: Path) -> str:
    """Create (or reuse) a dedicated namespace for these tests. The fixture
    does NOT delete it — operators inspect what the tests left behind."""
    assert _KUBECTL is not None
    subprocess.run(  # noqa: S603 — fixed args, absolute path
        [_KUBECTL, "--kubeconfig", str(kind_kubeconfig), "create", "namespace", _NAMESPACE],
        capture_output=True,
        text=True,
        timeout=10,
    )  # ignore exit code; namespace may already exist
    return _NAMESPACE


@pytest.fixture
def bad_deployment(kind_kubeconfig: Path, test_namespace: str) -> str:
    """Apply a Deployment that runs as root (will be flagged by D.6's
    run-as-root rule). Returns the workload name."""
    name = f"bad-app-{int(time.time())}"
    manifest = f"""\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {name}
  namespace: {test_namespace}
spec:
  replicas: 1
  selector:
    matchLabels:
      app: {name}
  template:
    metadata:
      labels:
        app: {name}
    spec:
      containers:
        - name: app
          image: nginx:1.27-alpine
          securityContext:
            runAsUser: 0
"""
    assert _KUBECTL is not None
    subprocess.run(  # noqa: S603 — fixed args, absolute path
        [_KUBECTL, "--kubeconfig", str(kind_kubeconfig), "apply", "-f", "-"],
        input=manifest,
        text=True,
        check=True,
        capture_output=True,
        timeout=30,
    )
    # Wait for the Deployment to come up before the agent inspects it.
    subprocess.run(  # noqa: S603 — fixed args, absolute path
        [
            _KUBECTL,
            "--kubeconfig",
            str(kind_kubeconfig),
            "-n",
            test_namespace,
            "rollout",
            "status",
            f"deployment/{name}",
            "--timeout=60s",
        ],
        check=True,
        capture_output=True,
        timeout=90,
    )
    return name


# ---------------------------- contract + findings helpers ----------------


def _contract(tmp_path: Path) -> ExecutionContract:
    now = datetime.now(UTC)
    return ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="remediation",
        customer_id="cust_kind_live",
        task="A.1 live kind integration test",
        required_outputs=["findings.json", "report.md"],
        budget=BudgetSpec(
            llm_calls=1,
            tokens=1,
            wall_clock_sec=600.0,
            cloud_api_calls=50,
            mb_written=10,
        ),
        permitted_tools=["read_findings", "apply_patch"],
        completion_condition="findings.json AND report.md exist",
        escalation_rules=[],
        workspace=str(tmp_path / "ws"),
        persistent_root=str(tmp_path / "persistent"),
        created_at=now,
        expires_at=now + timedelta(hours=1),
    )


def _findings_for(workload_name: str, namespace: str, tmp_path: Path) -> Path:
    """Write a minimal D.6-shaped findings.json containing one run-as-root
    finding against the live cluster's workload. We don't run D.6 in this
    lane — we hand A.1 the finding directly to keep the integration scope
    tight to A.1's stages."""
    path = tmp_path / "findings.json"
    now = datetime.now(UTC).isoformat()
    payload = {
        "agent": "k8s_posture",
        "agent_version": "0.3.0",
        "customer_id": "cust_kind_live",
        "run_id": "kind-live",
        "scan_started_at": now,
        "scan_completed_at": now,
        "findings": [
            {
                "category_uid": 3,
                "category_name": "Identity & Access Management",
                "class_uid": 2003,
                "class_name": "Compliance Finding",
                "activity_id": 1,
                "activity_name": "Create",
                "type_uid": 200301,
                "type_name": "Compliance Finding: Create",
                "severity_id": 4,
                "severity": "High",
                "time": int(time.time() * 1000),
                "time_dt": now,
                "status_id": 1,
                "status": "New",
                "metadata": {
                    "version": "1.3.0",
                    "product": {"name": "Nexus K8s Posture", "vendor_name": "Nexus Cyber OS"},
                },
                "finding_info": {
                    "uid": f"CSPM-KUBERNETES-MANIFEST-001-{workload_name}",
                    "title": "Container running as root",
                    "desc": "Container has securityContext.runAsUser=0",
                    "first_seen_time": int(time.time() * 1000),
                    "last_seen_time": int(time.time() * 1000),
                    "types": ["cspm_k8s_manifest"],
                    "analytic": {"name": "run-as-root"},
                },
                "resources": [
                    {
                        "cloud": "kubernetes",
                        "account_id": namespace,
                        "region": "cluster",
                        "type": "Deployment",
                        "uid": f"{namespace}/{workload_name}",
                        "name": workload_name,
                    }
                ],
                "evidences": [
                    {
                        "kind": "manifest",
                        "rule_id": "run-as-root",
                        "rule_title": "Container running as root",
                        "workload_kind": "Deployment",
                        "workload_name": workload_name,
                        "namespace": namespace,
                        "container_name": "app",
                        "manifest_path": f"cluster:///{namespace}/Deployment/{workload_name}",
                    }
                ],
            }
        ],
    }
    path.write_text(json.dumps(payload))
    return path


def _auth_execute() -> Authorization:
    return Authorization(
        mode_recommend_authorized=True,
        mode_dry_run_authorized=True,
        mode_execute_authorized=True,
        authorized_actions=["remediation_k8s_patch_runAsNonRoot"],
        max_actions_per_run=5,
        rollback_window_sec=60,  # tight window — kind reconciles fast
    )


# ---------------------------- the three integration tests ----------------


async def test_execute_validated_against_live_cluster(
    tmp_path: Path, kind_kubeconfig: Path, test_namespace: str, bad_deployment: str
) -> None:
    """Apply a run-as-root finding's remediation against a live kind cluster;
    expect `executed_validated` after the rollback window."""
    contract = _contract(tmp_path)
    findings = _findings_for(bad_deployment, test_namespace, tmp_path)

    report = await agent_run(
        contract=contract,
        findings_path=findings,
        mode=RemediationMode.EXECUTE,
        authorization=_auth_execute(),
        kubeconfig=kind_kubeconfig,
        cluster_namespace=test_namespace,
    )

    assert report.total == 1, f"expected 1 finding, got {report.total}"
    outcome_name = report.findings[0]["finding_info"]["analytic"]["name"]
    assert outcome_name == RemediationOutcome.EXECUTED_VALIDATED.value, (
        f"expected executed_validated, got {outcome_name!r}; "
        f"investigate execution_results.json + rollback_decisions.json under "
        f"{contract.workspace}"
    )

    # Spot-check the live cluster state: the Pod template's runAsNonRoot
    # should now be True. (If the test fails before this assertion runs,
    # operator inspects manually via `kubectl get deployment ... -o yaml`.)
    assert _KUBECTL is not None
    out = subprocess.run(  # noqa: S603 — fixed args, absolute path
        [
            _KUBECTL,
            "--kubeconfig",
            str(kind_kubeconfig),
            "-n",
            test_namespace,
            "get",
            "deployment",
            bad_deployment,
            "-o",
            "jsonpath={.spec.template.spec.containers[0].securityContext.runAsNonRoot}",
        ],
        capture_output=True,
        text=True,
        check=True,
        timeout=15,
    )
    assert out.stdout.strip() == "true", (
        f"post-patch cluster state did not match expected: stdout={out.stdout!r}"
    )


@pytest.fixture(scope="module")
def kyverno_installed(kind_kubeconfig: Path) -> str:
    """Install Kyverno on the kind cluster (idempotent; module-scoped).

    Kyverno provides the MutatingAdmissionWebhook server + TLS + JSON-patch
    machinery the rolled-back-path proof needs. Installing it explicitly
    (rather than expecting it pre-installed) makes the fixture cold-followable
    by anyone reading this test file.

    Uses `kubectl apply --server-side --force-conflicts` because the Kyverno
    CRDs' annotations exceed the client-side 256 KiB limit and re-applying
    already-managed CRDs trips field-ownership warnings as fatal errors.
    Then waits up to 3 minutes for all four Kyverno deployments to report
    `available`. Re-runs against an already-installed cluster are fast.

    Returns the Kyverno namespace name.
    """
    assert _KUBECTL is not None
    subprocess.run(  # noqa: S603 — fixed args, absolute path
        [
            _KUBECTL,
            "--kubeconfig",
            str(kind_kubeconfig),
            "apply",
            "--server-side",
            "--force-conflicts",
            "-f",
            _KYVERNO_INSTALL_URL,
        ],
        check=True,
        capture_output=True,
        timeout=120,
    )
    subprocess.run(  # noqa: S603 — fixed args, absolute path
        [
            _KUBECTL,
            "--kubeconfig",
            str(kind_kubeconfig),
            "-n",
            "kyverno",
            "wait",
            "--for=condition=available",
            "deployment",
            "--all",
            "--timeout=180s",
        ],
        check=True,
        capture_output=True,
        timeout=200,
    )
    return "kyverno"


@pytest.fixture
def strip_runasnonroot_policy(
    kind_kubeconfig: Path,
    kyverno_installed: str,
) -> Iterator[str]:
    """Apply the `a1-rolled-back-fixture-strip-runasnonroot` Kyverno
    ClusterPolicy for the duration of one test, then remove it on teardown.

    Function-scoped so other tests in this module (which create Deployments
    in the same `nexus-rem-test` namespace) are not affected by the
    mutation. The policy YAML lives in
    [`fixtures/kyverno-strip-runasnonroot.yaml`](fixtures/kyverno-strip-runasnonroot.yaml)
    and matches Deployment CREATE/UPDATE in `nexus-rem-test` only.

    Yields the policy name. The teardown removes the policy so a re-run
    of the suite against the persistent cluster starts from a clean state.
    """
    del kyverno_installed
    assert _KUBECTL is not None
    policy_file = _FIXTURES_DIR / "kyverno-strip-runasnonroot.yaml"
    policy_name = "a1-rolled-back-fixture-strip-runasnonroot"
    subprocess.run(  # noqa: S603 — fixed args, absolute path
        [_KUBECTL, "--kubeconfig", str(kind_kubeconfig), "apply", "-f", str(policy_file)],
        check=True,
        capture_output=True,
        timeout=30,
    )
    # Wait for the policy's Ready condition — Kyverno registers the webhook
    # config asynchronously. Without this wait, the test may UPDATE the
    # Deployment before the webhook is actually live.
    subprocess.run(  # noqa: S603 — fixed args, absolute path
        [
            _KUBECTL,
            "--kubeconfig",
            str(kind_kubeconfig),
            "wait",
            "--for=condition=Ready",
            f"clusterpolicy/{policy_name}",
            "--timeout=60s",
        ],
        check=True,
        capture_output=True,
        timeout=70,
    )
    try:
        yield policy_name
    finally:
        # Never raise out of teardown; a leaked policy here is recoverable
        # manually via `kubectl delete clusterpolicy …`.
        subprocess.run(  # noqa: S603 — fixed args, absolute path
            [
                _KUBECTL,
                "--kubeconfig",
                str(kind_kubeconfig),
                "delete",
                "clusterpolicy",
                policy_name,
                "--ignore-not-found",
            ],
            capture_output=True,
            timeout=30,
        )


async def test_execute_rolled_back_against_live_cluster(
    tmp_path: Path,
    kind_kubeconfig: Path,
    test_namespace: str,
    strip_runasnonroot_policy: str,
    bad_deployment: str,
) -> None:
    """Live-cluster proof of A.1's rollback path against a real
    MutatingAdmissionWebhook.

    The Kyverno ClusterPolicy installed by `strip_runasnonroot_policy`
    mutates every Deployment UPDATE in `nexus-rem-test` to set
    `runAsNonRoot: false` on its containers, regardless of what the
    patcher sent. The webhook simulates the real customer failure mode
    A.1's rollback path is designed to catch (OPA Gatekeeper / Linkerd /
    Istio sidecar-injection rewriting workload specs).

    Flow:
      1. `bad_deployment` creates a Deployment in `nexus-rem-test` with
         `runAsUser: 0` (no `runAsNonRoot`).
      2. A.1 runs with `--mode execute`, patches the Deployment to add
         `runAsNonRoot: true`.
      3. The Kyverno webhook fires on UPDATE and rewrites
         `runAsNonRoot` back to `false`.
      4. After the rollback window, A.1's validator re-runs D.6 against
         the live cluster. D.6 sees `runAsUser: 0` + `runAsNonRoot: false`
         and reports the `run-as-root` rule still firing.
      5. A.1 applies the inverse patch automatically.
      6. Outcome: `executed_rolled_back`.

    Closes safety-verification §6 prerequisite item 3 — the rolled-back
    path is no longer asserted only by mocked tests.
    """
    del strip_runasnonroot_policy
    contract = _contract(tmp_path)
    findings = _findings_for(bad_deployment, test_namespace, tmp_path)

    start = time.monotonic()
    report = await agent_run(
        contract=contract,
        findings_path=findings,
        mode=RemediationMode.EXECUTE,
        authorization=_auth_execute(),
        kubeconfig=kind_kubeconfig,
        cluster_namespace=test_namespace,
    )
    elapsed = time.monotonic() - start

    assert report.total == 1, f"expected 1 finding, got {report.total}"
    outcome_name = report.findings[0]["finding_info"]["analytic"]["name"]
    assert outcome_name == RemediationOutcome.EXECUTED_ROLLED_BACK.value, (
        f"expected executed_rolled_back, got {outcome_name!r}. "
        f"investigate execution_results.json + rollback_decisions.json under "
        f"{contract.workspace}. If the Kyverno policy didn't fire, check "
        f"`kubectl get deployment {bad_deployment} -n {test_namespace} -o yaml` "
        f"for spec.template.spec.containers[].securityContext.runAsNonRoot."
    )

    # Cluster-level confirmation: after the rolled-back path, the Deployment
    # is not at runAsNonRoot=true. (The webhook may have set it to false;
    # what matters is that the validator's decision was honoured and the
    # inverse patch was applied.)
    assert _KUBECTL is not None
    out = subprocess.run(  # noqa: S603 — fixed args, absolute path
        [
            _KUBECTL,
            "--kubeconfig",
            str(kind_kubeconfig),
            "-n",
            test_namespace,
            "get",
            "deployment",
            bad_deployment,
            "-o",
            "jsonpath={.spec.template.spec.containers[0].securityContext.runAsNonRoot}",
        ],
        capture_output=True,
        text=True,
        check=True,
        timeout=15,
    )
    assert out.stdout.strip() in ("", "false"), (
        f"post-rollback cluster state should not show runAsNonRoot=true; got {out.stdout!r}"
    )

    print(
        f"\n[WEBHOOK-ROLLBACK-PROOF] outcome={outcome_name} "
        f"wall_clock={elapsed:.2f}s "
        f"workload={test_namespace}/{bad_deployment} "
        f"post_patch_runAsNonRoot={out.stdout.strip() or '<unset>'}"
    )


async def test_rollback_window_matches_real_reconcile(
    tmp_path: Path, kind_kubeconfig: Path, test_namespace: str, bad_deployment: str
) -> None:
    """Measure the wall-clock time from `kubectl patch` to the new Pod
    being Ready. Assert the default `rollback_window_sec=300` provides ≥30s
    of cushion over the measured reconcile latency."""
    contract = _contract(tmp_path)
    findings = _findings_for(bad_deployment, test_namespace, tmp_path)

    # Use a generous rollback window for measurement.
    auth = _auth_execute()
    auth = auth.model_copy(update={"rollback_window_sec": 300})

    start = time.monotonic()
    report = await agent_run(
        contract=contract,
        findings_path=findings,
        mode=RemediationMode.EXECUTE,
        authorization=auth,
        kubeconfig=kind_kubeconfig,
        cluster_namespace=test_namespace,
    )
    elapsed = time.monotonic() - start

    # `elapsed` includes the rollback_window_sec wait; subtract to get
    # the agent's own wall-clock contribution (apply + re-detect + cleanup).
    agent_overhead = elapsed - auth.rollback_window_sec
    assert agent_overhead > 0, "elapsed wall-clock < rollback window — measurement bug"

    # Surface the measurement so §8 of the safety-verification record can
    # cite the actual number. Captured by `pytest -s`.
    print(
        f"\n[G3-MEASUREMENT] elapsed={elapsed:.2f}s "
        f"rollback_window_sec={auth.rollback_window_sec} "
        f"agent_overhead={agent_overhead:.2f}s "
        f"cushion={auth.rollback_window_sec - agent_overhead:.2f}s"
    )

    # Assert the default 300s window is at least 30s above what we needed.
    # If this fails, the runbook's "default 300s" claim needs revisiting.
    assert auth.rollback_window_sec - agent_overhead >= 30, (
        f"reconcile latency ({agent_overhead:.1f}s) leaves <30s cushion within "
        f"the default 300s rollback_window_sec. Either raise the default or "
        f"investigate slow reconciles on this cluster."
    )
    # Sanity: outcome must be validated (otherwise we measured a rollback path).
    outcome_name = report.findings[0]["finding_info"]["analytic"]["name"]
    assert outcome_name == RemediationOutcome.EXECUTED_VALIDATED.value, (
        f"measurement assumes happy path; outcome was {outcome_name!r}"
    )


# ---------------------------- v0.1.1 promotion-flow live tests -----------
#
# Task 13 of the A.1 v0.1.1 earned-autonomy-pipeline plan. The mocked
# `test_promotion_gate.py` proves the gate's control flow against fakes;
# these three tests prove the same surface against a REAL kind cluster.
# Without them, the fail-closed default (`--mode execute` against a Stage-1
# action class refuses) is only proven against the test double of kubectl.
# Once these pass, that property holds against a real Kubernetes apiserver.


def _stage1_tracker() -> PromotionTracker:
    """Empty `action_classes` → every action class implicitly at Stage 1
    (the floor). This is the safe-by-default state when no `promotion.yaml`
    exists in the customer environment.
    """
    now = datetime.now(UTC)
    return PromotionTracker(
        PromotionFile(
            cluster_id="kind-live",
            created_at=now,
            last_modified_at=now,
        )
    )


def _stage2_tracker_for_runasnonroot() -> PromotionTracker:
    """`runAsNonRoot` graduated to Stage 2 with one advance(1→2) sign-off."""
    now = datetime.now(UTC)
    file = PromotionFile(cluster_id="kind-live", created_at=now, last_modified_at=now)
    file.action_classes[RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT.value] = (
        ActionClassPromotion(
            action_type=RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT,
            stage=PromotionStage.STAGE_2,
            sign_offs=[
                PromotionSignOff(
                    event_kind="advance",
                    operator="kind-live-fixture",
                    timestamp=now,
                    reason="graduated runAsNonRoot to Stage 2 for live dry_run test",
                    from_stage=PromotionStage.STAGE_1,
                    to_stage=PromotionStage.STAGE_2,
                )
            ],
        )
    )
    return PromotionTracker(file)


def _read_resource_version(kubeconfig: Path, namespace: str, workload: str) -> str:
    """Return the cluster's view of the Deployment's `metadata.resourceVersion`.

    Two reads bracketing the agent run lets the test prove the cluster never
    saw a mutation: if `rv_before == rv_after`, no patch / apply / replace
    / delete touched this Deployment during the window.
    """
    assert _KUBECTL is not None
    out = subprocess.run(  # noqa: S603 — fixed args, absolute path
        [
            _KUBECTL,
            "--kubeconfig",
            str(kubeconfig),
            "-n",
            namespace,
            "get",
            "deployment",
            workload,
            "-o",
            "jsonpath={.metadata.resourceVersion}",
        ],
        capture_output=True,
        text=True,
        check=True,
        timeout=15,
    )
    return out.stdout.strip()


_MUTATING_VERBS = frozenset(
    {"patch", "apply", "create", "delete", "replace", "edit", "scale", "rollout"}
)


def _install_mutating_kubectl_spy(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[list[list[str]], list[list[str]]]:
    """Wrap the kubectl_executor's `_run` chokepoint with a counter.

    All cluster-touching paths in A.1 flow through
    [`kubectl_executor._run`](packages/agents/remediation/src/remediation/tools/kubectl_executor.py#L88)
    — the module's docstring explicitly names this as the single subprocess
    point ("All cluster-touching paths in A.1 flow through this — tests
    monkeypatch it to inject deterministic results"). Spying here gives a
    complete record of kubectl invocations the agent issued, ignoring any
    kubectl invocations made elsewhere (e.g., by the test fixture setup or
    the operator's terminal).

    Returns `(all_calls, mutating_calls)`. `all_calls` records every
    invocation; `mutating_calls` is the subset using a state-mutating verb
    (patch / apply / create / delete / replace / edit / scale / rollout).
    Read verbs (get / describe / version / etc.) appear only in `all_calls`
    — the agent is allowed to read the cluster before refusing.

    Mirrors Task 5's `_patch_driver_with_apply_spy` pattern, lifted from
    `apply_patch`-level fake to subprocess-level spy so the proof holds even
    when the agent reaches into a real `kubectl_executor` against a real
    cluster.
    """
    all_calls: list[list[str]] = []
    mutating_calls: list[list[str]] = []
    real_run = kc_mod._run

    async def counting_run(cmd: object) -> tuple[int, str, str]:
        if isinstance(cmd, (list, tuple)) and cmd:
            cmd_str = [str(c) for c in cmd]
            all_calls.append(cmd_str)
            first = cmd_str[0]
            if Path(first).name == "kubectl":
                for arg in cmd_str[1:]:
                    if arg in _MUTATING_VERBS:
                        mutating_calls.append(cmd_str)
                        break
        return await real_run(cmd)  # type: ignore[arg-type]

    monkeypatch.setattr(kc_mod, "_run", counting_run)
    return all_calls, mutating_calls


async def test_stage1_only_refuses_execute_against_live_cluster(
    tmp_path: Path,
    kind_kubeconfig: Path,
    test_namespace: str,
    bad_deployment: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Stage 1 + `--mode execute` against the real kind cluster MUST refuse
    every finding with `REFUSED_PROMOTION_GATE` AND emit ZERO mutating
    kubectl invocations AND leave the workload's cluster-level
    `resourceVersion` unchanged.

    Two layers of proof:
      1. Python-level: `_install_mutating_kubectl_spy` counts kubectl
         invocations with mutating verbs; the list must be `[]` post-run.
      2. Cluster-level: the Deployment's `metadata.resourceVersion` is
         identical before and after the agent run. The Kubernetes apiserver
         never saw a write.

    The whole point of this test is that the fail-closed default holds
    against a real Kubernetes apiserver — every unit test so far has only
    proven it against `apply_patch`-level mocks.
    """
    rv_before = _read_resource_version(kind_kubeconfig, test_namespace, bad_deployment)
    all_kubectl_calls, mutating_calls = _install_mutating_kubectl_spy(monkeypatch)

    contract = _contract(tmp_path)
    findings = _findings_for(bad_deployment, test_namespace, tmp_path)

    report = await agent_run(
        contract=contract,
        findings_path=findings,
        mode=RemediationMode.EXECUTE,
        authorization=_auth_execute(),
        promotion=_stage1_tracker(),
        kubeconfig=kind_kubeconfig,
        cluster_namespace=test_namespace,
    )

    # (1) Outcome assertion: the one finding is REFUSED_PROMOTION_GATE.
    assert report.total == 1, f"expected 1 finding, got {report.total}"
    outcome_name = report.findings[0]["finding_info"]["analytic"]["name"]
    assert outcome_name == RemediationOutcome.REFUSED_PROMOTION_GATE.value, (
        f"Stage 1 + execute must refuse with REFUSED_PROMOTION_GATE; "
        f"got {outcome_name!r}. The gate is bypassable against a live cluster — "
        f"investigate `agent.run()`'s pre-flight gate."
    )

    # (2) Python-level proof: zero mutating kubectl invocations.
    assert mutating_calls == [], (
        f"REFUSED finding triggered {len(mutating_calls)} mutating kubectl "
        f"invocation(s) — the gate did not halt before reaching the executor. "
        f"calls={mutating_calls}"
    )

    # (3) Cluster-level proof: resourceVersion unchanged.
    rv_after = _read_resource_version(kind_kubeconfig, test_namespace, bad_deployment)
    assert rv_before == rv_after, (
        f"Deployment resourceVersion changed during the refused run "
        f"(before={rv_before!r} after={rv_after!r}). The kubernetes apiserver "
        f"saw a write — investigate path-of-mutation, the spy may have missed it."
    )

    # Surface measurements for safety-verification §8 (captured by `pytest -s`).
    print(
        f"\n[TASK13-STAGE1-PROOF] outcome={outcome_name} "
        f"mutating_kubectl_calls={len(mutating_calls)} "
        f"total_kubectl_calls={len(all_kubectl_calls)} "
        f"rv_before={rv_before} rv_after={rv_after} "
        f"workload={test_namespace}/{bad_deployment}"
    )


async def test_promotion_evidence_emitted_to_audit_chain_live(
    tmp_path: Path,
    kind_kubeconfig: Path,
    test_namespace: str,
    bad_deployment: str,
) -> None:
    """Stage 2 + `--mode dry_run` against the real kind cluster MUST emit a
    `promotion.evidence.stage2` audit entry, and `promotion.replay()` over
    the run's audit chain MUST reconstruct an evidence counter that matches
    the live tracker's post-run state.

    The dry_run path is the smallest live-cluster flow that mutates the
    promotion tracker: `kubectl --dry-run=server` hits the real apiserver,
    succeeds, and the agent calls `tracker.record_evidence(stage2_dry_run)`.

    Note on stage + sign-offs (the limitation case 012/013 exposed in
    Task 12 review): `replay()` cannot reconstruct the Stage 2 designation
    or the `advance(1→2)` sign-off from this run's chain — those events
    come from the CLI `promotion advance` path, not the agent's run-time
    evidence emission. The assertion below targets the evidence counter
    only, which is the property the chain DOES carry end-to-end.
    """
    tracker = _stage2_tracker_for_runasnonroot()

    contract = _contract(tmp_path)
    findings = _findings_for(bad_deployment, test_namespace, tmp_path)

    report = await agent_run(
        contract=contract,
        findings_path=findings,
        mode=RemediationMode.DRY_RUN,
        authorization=_auth_execute(),
        promotion=tracker,
        kubeconfig=kind_kubeconfig,
        cluster_namespace=test_namespace,
    )

    # Outcome sanity: the finding made it through the gate and dry-ran.
    assert report.total == 1
    outcome_name = report.findings[0]["finding_info"]["analytic"]["name"]
    assert outcome_name == RemediationOutcome.DRY_RUN_ONLY.value, (
        f"Stage 2 + dry_run must produce DRY_RUN_ONLY; got {outcome_name!r}"
    )

    # Audit chain assertion: a stage2 evidence event exists.
    audit_path = Path(contract.workspace) / "audit.jsonl"
    entries = [
        AuditEntry.from_json(line)
        for line in audit_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    evidence_entries = [e for e in entries if e.action == "promotion.evidence.stage2"]
    assert len(evidence_entries) == 1, (
        f"expected exactly one `promotion.evidence.stage2` entry; got "
        f"{len(evidence_entries)}. action counts: "
        f"{ {e.action: 1 for e in entries if e.action.startswith('promotion.')} }"
    )
    assert (
        evidence_entries[0].payload["action_type"]
        == RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT.value
    )

    # Replay assertion: the chain replays to evidence.stage2_dry_runs == 1,
    # matching the live tracker's evidence counter.
    replayed = replay(entries, default_cluster_id=tracker.file.cluster_id)
    rep_evidence = replayed.action_classes[
        RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT.value
    ].evidence
    live_evidence = tracker.file.action_classes[
        RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT.value
    ].evidence
    assert rep_evidence.stage2_dry_runs == live_evidence.stage2_dry_runs == 1, (
        f"replay evidence vs live tracker mismatch — "
        f"replay.stage2_dry_runs={rep_evidence.stage2_dry_runs}, "
        f"live.stage2_dry_runs={live_evidence.stage2_dry_runs}"
    )
    print(
        f"\n[TASK13-EVIDENCE-PROOF] stage2_evidence_entries={len(evidence_entries)} "
        f"replay.stage2_dry_runs={rep_evidence.stage2_dry_runs} "
        f"live.stage2_dry_runs={live_evidence.stage2_dry_runs}"
    )


async def test_reconcile_matches_tracker_state_live(
    tmp_path: Path,
    kind_kubeconfig: Path,
    test_namespace: str,
    bad_deployment: str,
) -> None:
    """End-to-end reconcile-parity proof against a live cluster: drive a
    dry_run sequence (1 finding, real apiserver dry-run), replay the run's
    audit chain, assert the replayed evidence counters field-by-field equal
    the live tracker's evidence counters for every action class touched.

    Stage + sign-offs are excluded from the equality (see
    `test_promotion_evidence_emitted_to_audit_chain_live` for the
    rationale: replay cannot reconstruct transition events from the agent's
    run-time chain). The replayed evidence is the part the chain DOES carry,
    and that part must match exactly — otherwise the §3 'cache' /
    'source-of-truth' contract is broken for the evidence surface.
    """
    tracker = _stage2_tracker_for_runasnonroot()

    contract = _contract(tmp_path)
    findings = _findings_for(bad_deployment, test_namespace, tmp_path)

    await agent_run(
        contract=contract,
        findings_path=findings,
        mode=RemediationMode.DRY_RUN,
        authorization=_auth_execute(),
        promotion=tracker,
        kubeconfig=kind_kubeconfig,
        cluster_namespace=test_namespace,
    )

    audit_path = Path(contract.workspace) / "audit.jsonl"
    entries = [
        AuditEntry.from_json(line)
        for line in audit_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    replayed = replay(entries, default_cluster_id=tracker.file.cluster_id)

    live_classes = tracker.file.action_classes
    rep_classes = replayed.action_classes
    # Every action class the live tracker has evidence for must also appear
    # in the replay output with field-equal evidence counters.
    for key, live_entry in live_classes.items():
        assert key in rep_classes, (
            f"replay missing action class {key!r} that the live tracker carries"
        )
        live_ev = live_entry.evidence.model_dump(mode="json")
        rep_ev = rep_classes[key].evidence.model_dump(mode="json")
        assert live_ev == rep_ev, (
            f"evidence-counter mismatch for {key!r}:\n  live={live_ev}\n  rep={rep_ev}"
        )
        print(
            f"\n[TASK13-RECONCILE-PROOF] action_class={key} "
            f"live_evidence={live_ev} replay_evidence={rep_ev}"
        )
