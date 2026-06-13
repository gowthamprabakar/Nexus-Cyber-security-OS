"""Tests for `remediation.agent.run` — the 7-stage pipeline driver."""

from __future__ import annotations

import json
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from charter import BudgetExhausted, DirectInvocationBlocked, ToolForbidden, ToolNotPermitted
from charter.contract import BudgetSpec, ExecutionContract
from k8s_posture.tools.manifests import ManifestFinding
from remediation import agent as agent_mod
from remediation.agent import build_registry, run
from remediation.authz import Authorization, AuthorizationError
from remediation.schemas import (
    RemediationActionType,
    RemediationMode,
    RemediationOutcome,
)
from remediation.tools import kubectl_executor as kc_mod
from remediation.tools.kubectl_executor import PatchResult

NOW = datetime(2026, 5, 16, 12, 0, 0, tzinfo=UTC)


# ---------------------------- fixtures ------------------------------------


def _contract(tmp_path: Path) -> ExecutionContract:
    return ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="remediation",
        customer_id="cust_test",
        task="A.1 unit test",
        required_outputs=["findings.json", "report.md"],
        budget=BudgetSpec(
            llm_calls=1,
            tokens=1,
            wall_clock_sec=60.0,
            cloud_api_calls=20,
            mb_written=10,
        ),
        permitted_tools=["read_findings", "apply_patch"],
        completion_condition="findings.json AND report.md exist",
        escalation_rules=[],
        workspace=str(tmp_path / "ws"),
        persistent_root=str(tmp_path / "persistent"),
        created_at=NOW,
        expires_at=NOW + timedelta(hours=1),
    )


def _manifest_finding(
    *,
    rule_id: str = "run-as-root",
    workload_name: str = "frontend",
    namespace: str = "production",
    container_name: str = "nginx",
) -> ManifestFinding:
    return ManifestFinding(
        rule_id=rule_id,
        rule_title=rule_id.replace("-", " ").title(),
        severity="high",
        workload_kind="Deployment",
        workload_name=workload_name,
        namespace=namespace,
        container_name=container_name,
        manifest_path="cluster:///production/Deployment/frontend",
        detected_at=NOW,
    )


def _patch_findings(
    monkeypatch: pytest.MonkeyPatch,
    findings: tuple[ManifestFinding, ...],
) -> None:
    """Replace Stage-1 ingest with deterministic output."""

    async def fake_read(*, path: Path | str) -> tuple[ManifestFinding, ...]:
        del path
        return findings

    monkeypatch.setattr(agent_mod, "read_findings", fake_read)


def _patch_executor(
    monkeypatch: pytest.MonkeyPatch,
    *,
    dry_run_result: PatchResult | None = None,
    execute_result: PatchResult | None = None,
    rollback_result: PatchResult | None = None,
) -> dict[str, list[Any]]:
    """Replace kubectl executor with scripted results. Returns a capture dict."""
    captured: dict[str, list[Any]] = {"calls": []}
    dr = dry_run_result or _result_ok(dry_run=True)
    ex = execute_result or _result_ok()
    rb = rollback_result or _result_ok()

    async def fake_apply(artifact: Any, *, dry_run: bool, **_: Any) -> PatchResult:
        captured["calls"].append({"correlation_id": artifact.correlation_id, "dry_run": dry_run})
        if dry_run:
            return dr
        # Distinguish execute vs rollback by checking correlation_id suffix.
        if artifact.correlation_id.endswith("-rollback"):
            return rb
        return ex

    monkeypatch.setattr(agent_mod, "apply_patch", fake_apply)
    # Stage-5 EXECUTE and Stage-7 ROLLBACK both dispatch apply_patch via the
    # charter registry (which closes over agent_mod.apply_patch at build time),
    # so patching agent_mod is sufficient for both paths. (validator no longer
    # imports apply_patch directly — PR-A1 routed rollback through ctx.call_tool.)
    monkeypatch.setattr(kc_mod, "apply_patch", fake_apply)
    # Also stub the binary check so absence of kubectl doesn't fail tests.
    monkeypatch.setattr(kc_mod, "_kubectl_binary", lambda: "/usr/local/bin/kubectl")
    return captured


def _patch_detector(
    monkeypatch: pytest.MonkeyPatch,
    *,
    detector_output: tuple[ManifestFinding, ...] = (),
) -> None:
    """Replace the validator's detector closure factory. The driver wires its own
    closure via build_d6_detector, so we override that factory."""

    async def fake_detect() -> tuple[ManifestFinding, ...]:
        return detector_output

    def fake_factory(*, namespace: str, kubeconfig: Path | None, in_cluster: bool) -> Any:
        del namespace, kubeconfig, in_cluster
        return fake_detect

    monkeypatch.setattr(agent_mod, "build_d6_detector", fake_factory)


@pytest.fixture(autouse=True)
def fast_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stage-6 validator sleeps rollback_window_sec — make that instant for tests."""
    import remediation.validator as validator_mod

    async def _instant(_seconds: float) -> None:
        return None

    monkeypatch.setattr(validator_mod.asyncio, "sleep", _instant)


def _result_ok(*, dry_run: bool = False) -> PatchResult:
    return PatchResult(
        exit_code=0,
        stdout="deployment.apps/frontend patched",
        stderr="",
        dry_run=dry_run,
        pre_patch_hash="a" * 64 if not dry_run else None,
        post_patch_hash="b" * 64 if not dry_run else None,
        pre_patch_resource={"kind": "Deployment"} if not dry_run else None,
        post_patch_resource={"kind": "Deployment", "patched": True} if not dry_run else None,
    )


def _result_fail(*, dry_run: bool = False) -> PatchResult:
    return PatchResult(
        exit_code=1,
        stdout="",
        stderr="error: admission webhook denied",
        dry_run=dry_run,
        pre_patch_hash=None,
        post_patch_hash=None,
        pre_patch_resource=None,
        post_patch_resource=None,
    )


# ---------------------------- registry ------------------------------------


def test_registry_includes_read_findings_and_apply_patch() -> None:
    reg = build_registry()
    tools = reg.known_tools()
    assert "read_findings" in tools
    assert "apply_patch" in tools


# ---------------------------- mode-escalation gate -----------------------


@pytest.mark.asyncio
async def test_run_refuses_dry_run_without_authorization(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Default Authorization() refuses dry-run. The gate fires BEFORE Charter context
    is even constructed — the driver must surface the AuthorizationError to the caller."""
    _patch_findings(monkeypatch, ())
    with pytest.raises(AuthorizationError, match=r"dry_run.*not authorized"):
        await run(
            _contract(tmp_path),
            findings_path=tmp_path / "findings.json",
            mode=RemediationMode.DRY_RUN,
            authorization=Authorization.recommend_only(),
        )


@pytest.mark.asyncio
async def test_run_refuses_execute_without_authorization(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _patch_findings(monkeypatch, ())
    with pytest.raises(AuthorizationError, match=r"execute.*not authorized"):
        await run(
            _contract(tmp_path),
            findings_path=tmp_path / "findings.json",
            mode=RemediationMode.EXECUTE,
            enable_execute=True,
            authorization=Authorization.recommend_only(),
        )


@pytest.mark.asyncio
async def test_run_rejects_kubeconfig_and_in_cluster_together(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _patch_findings(monkeypatch, ())
    with pytest.raises(ValueError, match="mutually exclusive"):
        await run(
            _contract(tmp_path),
            findings_path=tmp_path / "findings.json",
            mode=RemediationMode.RECOMMEND,
            kubeconfig=tmp_path / "kc.yaml",
            in_cluster=True,
        )


# ---------------------------- Stage 1+2: recommend (empty) ---------------


@pytest.mark.asyncio
async def test_recommend_with_no_findings_emits_empty_report(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _patch_findings(monkeypatch, ())
    report = await run(
        _contract(tmp_path),
        findings_path=tmp_path / "findings.json",
        mode=RemediationMode.RECOMMEND,
    )
    assert report.total == 0
    workspace = Path(_contract(tmp_path).workspace)
    assert (workspace / "findings.json").exists()
    assert (workspace / "report.md").exists()


@pytest.mark.asyncio
async def test_unauthorized_findings_become_refused_outcomes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A finding with a known rule_id but not in allowlist surfaces as
    REFUSED_UNAUTHORIZED in the report."""
    _patch_findings(monkeypatch, (_manifest_finding(rule_id="run-as-root"),))
    report = await run(
        _contract(tmp_path),
        findings_path=tmp_path / "findings.json",
        mode=RemediationMode.RECOMMEND,
        authorization=Authorization(authorized_actions=[]),  # empty allowlist
    )
    assert report.total == 1
    counts = report.count_by_outcome()
    assert counts[RemediationOutcome.REFUSED_UNAUTHORIZED.value] == 1


@pytest.mark.asyncio
async def test_blast_radius_exceeded_emits_refused_outcome(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Five+ authorized findings against a cap-of-2 authorization triggers
    REFUSED_BLAST_RADIUS with no partial-apply."""
    _patch_findings(
        monkeypatch,
        tuple(_manifest_finding(workload_name=f"w{i}") for i in range(5)),
    )
    auth = Authorization(
        authorized_actions=[RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT.value],
        max_actions_per_run=2,
    )
    report = await run(
        _contract(tmp_path),
        findings_path=tmp_path / "findings.json",
        mode=RemediationMode.RECOMMEND,
        authorization=auth,
    )
    counts = report.count_by_outcome()
    assert counts[RemediationOutcome.REFUSED_BLAST_RADIUS.value] >= 1


# ---------------------------- recommend mode happy path -------------------


@pytest.mark.asyncio
async def test_recommend_mode_generates_artifact_without_executing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    captured = _patch_executor(monkeypatch)
    _patch_findings(monkeypatch, (_manifest_finding(rule_id="run-as-root"),))
    auth = Authorization(
        authorized_actions=[RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT.value],
    )
    report = await run(
        _contract(tmp_path),
        findings_path=tmp_path / "findings.json",
        mode=RemediationMode.RECOMMEND,
        authorization=auth,
    )
    # No kubectl calls in recommend mode.
    assert captured["calls"] == []
    assert report.count_by_outcome()[RemediationOutcome.RECOMMENDED_ONLY.value] == 1


@pytest.mark.asyncio
async def test_recommend_mode_writes_per_artifact_json(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """One JSON file per artifact under workspace/artifacts/."""
    _patch_findings(monkeypatch, (_manifest_finding(workload_name="frontend"),))
    _patch_executor(monkeypatch)
    auth = Authorization(
        authorized_actions=[RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT.value],
    )
    await run(
        _contract(tmp_path),
        findings_path=tmp_path / "findings.json",
        mode=RemediationMode.RECOMMEND,
        authorization=auth,
    )
    artifacts_dir = tmp_path / "ws" / "artifacts"
    assert artifacts_dir.is_dir()
    files = list(artifacts_dir.glob("*.json"))
    assert len(files) == 1
    payload = json.loads(files[0].read_text())
    assert payload["action_type"] == RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT.value
    assert payload["target"]["name"] == "frontend"


# ---------------------------- dry-run mode --------------------------------


@pytest.mark.asyncio
async def test_dry_run_calls_kubectl_with_dry_run_flag(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    captured = _patch_executor(monkeypatch)
    _patch_findings(monkeypatch, (_manifest_finding(),))
    auth = Authorization(
        mode_dry_run_authorized=True,
        authorized_actions=[RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT.value],
    )
    report = await run(
        _contract(tmp_path),
        findings_path=tmp_path / "findings.json",
        mode=RemediationMode.DRY_RUN,
        authorization=auth,
    )
    # Exactly one dry-run call; no execute.
    assert len(captured["calls"]) == 1
    assert captured["calls"][0]["dry_run"] is True
    assert report.count_by_outcome()[RemediationOutcome.DRY_RUN_ONLY.value] == 1


@pytest.mark.asyncio
async def test_dry_run_failure_surfaces_as_dry_run_failed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _patch_findings(monkeypatch, (_manifest_finding(),))
    _patch_executor(monkeypatch, dry_run_result=_result_fail(dry_run=True))
    auth = Authorization(
        mode_dry_run_authorized=True,
        authorized_actions=[RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT.value],
    )
    report = await run(
        _contract(tmp_path),
        findings_path=tmp_path / "findings.json",
        mode=RemediationMode.DRY_RUN,
        authorization=auth,
    )
    assert report.count_by_outcome()[RemediationOutcome.DRY_RUN_FAILED.value] == 1


# ---------------------------- execute mode --------------------------------


@pytest.mark.asyncio
async def test_execute_mode_validated_runs_full_pipeline(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The happy path: dry-run + execute + validate (no rollback)."""
    captured = _patch_executor(monkeypatch)
    _patch_findings(monkeypatch, (_manifest_finding(),))
    _patch_detector(monkeypatch, detector_output=())  # clean detector → validated
    auth = Authorization(
        mode_execute_authorized=True,
        authorized_actions=[RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT.value],
    )
    report = await run(
        _contract(tmp_path),
        findings_path=tmp_path / "findings.json",
        mode=RemediationMode.EXECUTE,
        enable_execute=True,
        authorization=auth,
    )
    # 2 kubectl calls: dry-run + execute. No rollback.
    assert len(captured["calls"]) == 2
    assert captured["calls"][0]["dry_run"] is True
    assert captured["calls"][1]["dry_run"] is False
    assert report.count_by_outcome()[RemediationOutcome.EXECUTED_VALIDATED.value] == 1


@pytest.mark.asyncio
async def test_execute_mode_rollback_when_finding_persists(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Stage 6 sees the rule_id still firing → Stage 7 applies the inverse."""
    captured = _patch_executor(monkeypatch)
    _patch_findings(monkeypatch, (_manifest_finding(rule_id="run-as-root"),))
    _patch_detector(
        monkeypatch,
        detector_output=(_manifest_finding(rule_id="run-as-root"),),
    )
    auth = Authorization(
        mode_execute_authorized=True,
        authorized_actions=[RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT.value],
    )
    report = await run(
        _contract(tmp_path),
        findings_path=tmp_path / "findings.json",
        mode=RemediationMode.EXECUTE,
        enable_execute=True,
        authorization=auth,
    )
    # 3 kubectl calls: dry-run, execute, rollback.
    assert len(captured["calls"]) == 3
    assert report.count_by_outcome()[RemediationOutcome.EXECUTED_ROLLED_BACK.value] == 1


@pytest.mark.asyncio
async def test_run_invokes_safety_invariants_on_execute_rollback_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Phase C SS6 (Option alpha): an execute run that rolls back invokes the seven universal
    safety invariants - tenant scope, the H1 dual-layer, blast-radius, action allowlist,
    dry-run-first, tool-proxy, and mandatory rollback. Spy on names bound in remediation.agent."""
    _patch_executor(monkeypatch)
    _patch_findings(monkeypatch, (_manifest_finding(rule_id="run-as-root"),))
    _patch_detector(monkeypatch, detector_output=(_manifest_finding(rule_id="run-as-root"),))
    auth = Authorization(
        mode_execute_authorized=True,
        authorized_actions=[RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT.value],
    )

    seen: list[str] = []
    for name in (
        "assert_tenant_scoped",
        "assert_default_recommend",
        "assert_blast_radius_capped",
        "assert_action_allowlisted",
        "assert_dry_run_before_execute",
        "assert_tool_proxy_for_execute",
        "assert_rollback_on_failed_validation",
    ):
        real = getattr(agent_mod, name)

        def _spy(*args: object, _name: str = name, _real: object = real, **kwargs: object) -> None:
            seen.append(_name)
            _real(*args, **kwargs)  # type: ignore[operator]

        monkeypatch.setattr(agent_mod, name, _spy)

    await run(
        _contract(tmp_path),
        findings_path=tmp_path / "findings.json",
        mode=RemediationMode.EXECUTE,
        enable_execute=True,
        authorization=auth,
    )

    assert {
        "assert_tenant_scoped",
        "assert_default_recommend",
        "assert_blast_radius_capped",
        "assert_action_allowlisted",
        "assert_dry_run_before_execute",
        "assert_tool_proxy_for_execute",
        "assert_rollback_on_failed_validation",
    } <= set(seen)


@pytest.mark.asyncio
async def test_run_execute_without_kill_switch_hard_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Phase C SS6: even with auth.yaml authorizing execute, run() refuses to mutate without the
    kill-switch (enable_execute=False) — the H1 dual-layer is now load-bearing inside run()."""
    from remediation.invariants.default_recommend import DefaultRecommendViolationError

    _patch_executor(monkeypatch)
    _patch_findings(monkeypatch, (_manifest_finding(),))
    auth = Authorization(
        mode_execute_authorized=True,
        authorized_actions=[RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT.value],
    )
    with pytest.raises(DefaultRecommendViolationError):
        await run(
            _contract(tmp_path),
            findings_path=tmp_path / "findings.json",
            mode=RemediationMode.EXECUTE,
            enable_execute=False,
            authorization=auth,
        )


@pytest.mark.asyncio
async def test_execute_mode_execute_failure_skips_validate(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """If kubectl patch hard-fails, Stage 6 should NOT run (no point validating
    a patch that didn't apply)."""
    captured = _patch_executor(monkeypatch, execute_result=_result_fail())
    _patch_findings(monkeypatch, (_manifest_finding(),))
    _patch_detector(monkeypatch, detector_output=())
    auth = Authorization(
        mode_execute_authorized=True,
        authorized_actions=[RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT.value],
    )
    report = await run(
        _contract(tmp_path),
        findings_path=tmp_path / "findings.json",
        mode=RemediationMode.EXECUTE,
        enable_execute=True,
        authorization=auth,
    )
    # 2 kubectl calls: dry-run + execute (no rollback; validate never ran).
    assert len(captured["calls"]) == 2
    assert report.count_by_outcome()[RemediationOutcome.EXECUTE_FAILED.value] == 1


# ---------------------------- workspace outputs --------------------------


@pytest.mark.asyncio
async def test_all_seven_output_files_written(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _patch_findings(monkeypatch, (_manifest_finding(),))
    _patch_executor(monkeypatch)
    _patch_detector(monkeypatch, detector_output=())
    auth = Authorization(
        mode_execute_authorized=True,
        authorized_actions=[RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT.value],
    )
    await run(
        _contract(tmp_path),
        findings_path=tmp_path / "findings.json",
        mode=RemediationMode.EXECUTE,
        enable_execute=True,
        authorization=auth,
    )
    workspace = tmp_path / "ws"
    for filename in (
        "findings.json",
        "report.md",
        "dry_run_diffs.json",
        "execution_results.json",
        "rollback_decisions.json",
        "audit.jsonl",
    ):
        assert (workspace / filename).is_file(), f"missing output: {filename}"
    assert (workspace / "artifacts").is_dir()


@pytest.mark.asyncio
async def test_audit_chain_has_run_started_and_run_completed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Driver bookends its own contribution with run_started + run_completed.

    Charter may write its own framework entries; we only check ours are present
    and in the right order.
    """
    _patch_findings(monkeypatch, ())
    await run(
        _contract(tmp_path),
        findings_path=tmp_path / "findings.json",
        mode=RemediationMode.RECOMMEND,
    )
    chain = (tmp_path / "ws" / "audit.jsonl").read_text().splitlines()
    actions = [json.loads(line)["action"] for line in chain if line.strip()]
    remediation_actions = [a for a in actions if a.startswith("remediation.")]
    assert remediation_actions[0] == "remediation.run_started"
    assert remediation_actions[-1] == "remediation.run_completed"


# ---------------------------- chain integrity ---------------------------


@pytest.mark.asyncio
async def test_findings_json_matches_report_total(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The OCSF 2007 array length matches the returned report's `total`."""
    _patch_findings(
        monkeypatch,
        (
            _manifest_finding(workload_name="a"),
            _manifest_finding(workload_name="b"),
        ),
    )
    auth = Authorization(
        authorized_actions=[RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT.value],
    )
    report = await run(
        _contract(tmp_path),
        findings_path=tmp_path / "findings.json",
        mode=RemediationMode.RECOMMEND,
        authorization=auth,
    )
    payload = json.loads((tmp_path / "ws" / "findings.json").read_text())
    # `total` is a property on RemediationReport — not serialised; check the list.
    assert len(payload["findings"]) == report.total == 2


# ---------------------------- C-1: charter-gated mutation -----------------
# ADR-016 / audit #316 C-1: the live-mutation tool (apply_patch) must be
# dispatched through the charter (permitted_tools + budget + audit), never
# called directly. These tests prove the hard boundary at the mutation edge.


def _gated_contract(
    tmp_path: Path,
    *,
    permitted: list[str],
    forbidden: tuple[str, ...] = (),
    cloud_api_calls: int = 20,
) -> ExecutionContract:
    return ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="remediation",
        customer_id="cust_test",
        task="A.1 gate test",
        required_outputs=["findings.json", "report.md"],
        budget=BudgetSpec(
            llm_calls=1,
            tokens=1,
            wall_clock_sec=60.0,
            cloud_api_calls=cloud_api_calls,
            mb_written=10,
        ),
        permitted_tools=permitted,
        forbidden_tools=list(forbidden),
        completion_condition="findings.json AND report.md exist",
        escalation_rules=[],
        workspace=str(tmp_path / "ws"),
        persistent_root=str(tmp_path / "persistent"),
        created_at=NOW,
        expires_at=NOW + timedelta(hours=1),
    )


def _execute_auth() -> Authorization:
    return Authorization(
        mode_execute_authorized=True,
        authorized_actions=[RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT.value],
    )


def _audit_lines(contract: ExecutionContract) -> list[dict[str, Any]]:
    path = Path(contract.workspace) / "audit.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def test_apply_patch_proxy_blocks_direct_invocation() -> None:
    """The registry-held apply_patch cannot run outside a charter dispatch."""
    reg = build_registry()
    proxy = reg._tools["apply_patch"].proxy
    with pytest.raises(DirectInvocationBlocked) as exc:
        proxy(artifact=None, dry_run=False)
    assert exc.value.tool == "apply_patch"


@pytest.mark.asyncio
async def test_execute_routes_apply_patch_through_charter_audit(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """EXECUTE-mode mutation emits charter tool_call events for both apply_patch
    calls (dry-run + execute) and for the read_findings ingest."""
    _patch_executor(monkeypatch)
    _patch_findings(monkeypatch, (_manifest_finding(),))
    _patch_detector(monkeypatch, detector_output=())
    contract = _contract(tmp_path)
    await run(
        contract,
        findings_path=tmp_path / "findings.json",
        mode=RemediationMode.EXECUTE,
        enable_execute=True,
        authorization=_execute_auth(),
    )
    tool_calls = [e for e in _audit_lines(contract) if e.get("action") == "tool_call"]
    tools_called = [e["payload"]["tool"] for e in tool_calls]
    assert tools_called.count("apply_patch") == 2  # dry-run + execute, both gated
    assert "read_findings" in tools_called


@pytest.mark.asyncio
async def test_execute_pipeline_auditor_still_records(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Defense-in-depth: the domain PipelineAuditor chain still records the
    execute stage alongside the new charter tool_call events."""
    _patch_executor(monkeypatch)
    _patch_findings(monkeypatch, (_manifest_finding(),))
    _patch_detector(monkeypatch, detector_output=())
    contract = _contract(tmp_path)
    await run(
        contract,
        findings_path=tmp_path / "findings.json",
        mode=RemediationMode.EXECUTE,
        enable_execute=True,
        authorization=_execute_auth(),
    )
    actions = {e.get("action") for e in _audit_lines(contract)}
    assert "tool_call" in actions  # charter gate
    assert any("execute" in a for a in actions if isinstance(a, str))  # pipeline chain


@pytest.mark.asyncio
async def test_execute_consumes_cloud_budget_and_can_exhaust(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Routing through the charter means apply_patch now spends cloud_api_calls
    budget — proven by exhausting a 1-call budget on the 2nd (execute) call."""
    _patch_executor(monkeypatch)
    _patch_findings(monkeypatch, (_manifest_finding(),))
    _patch_detector(monkeypatch, detector_output=())
    contract = _gated_contract(
        tmp_path, permitted=["read_findings", "apply_patch"], cloud_api_calls=1
    )
    with pytest.raises(BudgetExhausted) as exc:
        await run(
            contract,
            findings_path=tmp_path / "findings.json",
            mode=RemediationMode.EXECUTE,
            enable_execute=True,
            authorization=_execute_auth(),
        )
    assert exc.value.dimension == "cloud_api_calls"


@pytest.mark.asyncio
async def test_execute_refused_when_apply_patch_not_permitted(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """If apply_patch is not in permitted_tools, the mutation is blocked by the
    charter whitelist (raised at the first gated apply_patch call)."""
    _patch_executor(monkeypatch)
    _patch_findings(monkeypatch, (_manifest_finding(),))
    contract = _gated_contract(tmp_path, permitted=["read_findings"])
    with pytest.raises(ToolNotPermitted) as exc:
        await run(
            contract,
            findings_path=tmp_path / "findings.json",
            mode=RemediationMode.EXECUTE,
            enable_execute=True,
            authorization=_execute_auth(),
        )
    assert exc.value.tool == "apply_patch"


@pytest.mark.asyncio
async def test_execute_refused_when_apply_patch_forbidden(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """forbidden_tools explicitly denies apply_patch — checked first in call_tool."""
    _patch_executor(monkeypatch)
    _patch_findings(monkeypatch, (_manifest_finding(),))
    contract = _gated_contract(tmp_path, permitted=["read_findings"], forbidden=("apply_patch",))
    with pytest.raises(ToolForbidden) as exc:
        await run(
            contract,
            findings_path=tmp_path / "findings.json",
            mode=RemediationMode.EXECUTE,
            enable_execute=True,
            authorization=_execute_auth(),
        )
    assert exc.value.tool == "apply_patch"


@pytest.mark.asyncio
async def test_dry_run_routes_apply_patch_through_charter(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """DRY-RUN mode also dispatches apply_patch through the gate (one tool_call)."""
    _patch_executor(monkeypatch)
    _patch_findings(monkeypatch, (_manifest_finding(),))
    contract = _contract(tmp_path)
    await run(
        contract,
        findings_path=tmp_path / "findings.json",
        mode=RemediationMode.DRY_RUN,
        authorization=Authorization(
            mode_dry_run_authorized=True,
            authorized_actions=[RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT.value],
        ),
    )
    tool_calls = [e for e in _audit_lines(contract) if e.get("action") == "tool_call"]
    assert [e["payload"]["tool"] for e in tool_calls].count("apply_patch") == 1


_ = Sequence  # silence unused-import linter (Sequence is used by _patch_executor typing)
