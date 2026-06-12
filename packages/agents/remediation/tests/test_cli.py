"""Tests for the `remediation` CLI.

Two subcommands (eval / run) and the mutual-exclusion + mode-escalation gates
they surface as `click.UsageError`.
"""

from __future__ import annotations

import json
import textwrap
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml
from charter.contract import BudgetSpec, ExecutionContract
from click.testing import CliRunner
from remediation.cli import main


@pytest.fixture
def shipped_cases_dir() -> Path:
    return Path(__file__).resolve().parents[1] / "eval" / "cases"


def _contract_yaml(tmp_path: Path) -> Path:
    contract = ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="remediation",
        customer_id="cust_test",
        task="Remediation v0.1 CLI test",
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
        persistent_root=str(tmp_path / "p"),
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )
    path = tmp_path / "contract.yaml"
    path.write_text(yaml.safe_dump(contract.model_dump(mode="json")))
    return path


def _empty_findings_json(tmp_path: Path) -> Path:
    """Write a D.6-shaped `findings.json` with zero records.

    The agent's Stage-1 ingest tolerates an empty array; recommend-mode runs
    against this need no D.6 detector or kubectl mocking.
    """
    path = tmp_path / "findings.json"
    path.write_text(
        json.dumps(
            {
                "agent": "k8s_posture",
                "agent_version": "0.3.0",
                "customer_id": "cust_test",
                "run_id": "test-run",
                "scan_started_at": datetime.now(UTC).isoformat(),
                "scan_completed_at": datetime.now(UTC).isoformat(),
                "findings": [],
            }
        )
    )
    return path


def _auth_yaml(tmp_path: Path, **fields: object) -> Path:
    path = tmp_path / "auth.yaml"
    path.write_text(yaml.safe_dump(fields))
    return path


# ---------------------------- --help / --version -------------------------


def test_cli_help_lists_subcommands() -> None:
    result = CliRunner().invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "eval" in result.output
    assert "run" in result.output


def test_cli_version_flag() -> None:
    result = CliRunner().invoke(main, ["--version"])
    assert result.exit_code == 0
    assert "0.2.0" in result.output


# ---------------------------- eval ---------------------------------------


def test_eval_with_shipped_cases_passes_15_of_15(shipped_cases_dir: Path) -> None:
    """The 15/15 acceptance gate via the CLI.

    Mirrors `test_run_suite_15_of_15` in test_eval_runner.py. Runs against
    the full `eval/cases/` directory with no filtering or tmp-copy fixture --
    the parser is live, every case executes, every case must pass.
    """
    result = CliRunner().invoke(main, ["eval", str(shipped_cases_dir)])
    assert result.exit_code == 0, result.output
    assert "15/15 passed" in result.output


def test_eval_exits_nonzero_on_failure(tmp_path: Path) -> None:
    cases_dir = tmp_path / "cases"
    cases_dir.mkdir()
    (cases_dir / "001_bogus.yaml").write_text(
        textwrap.dedent(
            """
            case_id: 001_bogus
            description: deliberately wrong expectation
            fixture:
              mode: recommend
              authorization:
                mode_recommend_authorized: true
              findings: []
            expected:
              finding_count: 99
            """
        ).strip()
    )

    result = CliRunner().invoke(main, ["eval", str(cases_dir)])
    assert result.exit_code == 1
    assert "FAIL 001_bogus" in result.output


def test_eval_missing_cases_dir_exits_nonzero(tmp_path: Path) -> None:
    result = CliRunner().invoke(main, ["eval", str(tmp_path / "does_not_exist")])
    assert result.exit_code != 0


# ---------------------------- run: recommend mode (no cluster) -----------


def test_run_recommend_mode_no_cluster_needed(tmp_path: Path) -> None:
    """Recommend mode is the only one that runs without --kubeconfig/--in-cluster."""
    contract = _contract_yaml(tmp_path)
    findings = _empty_findings_json(tmp_path)
    auth = _auth_yaml(tmp_path, mode_recommend_authorized=True)

    result = CliRunner().invoke(
        main,
        [
            "run",
            "--contract",
            str(contract),
            "--findings",
            str(findings),
            "--auth",
            str(auth),
            "--mode",
            "recommend",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "mode: recommend" in result.output
    assert "findings: 0" in result.output


def test_run_default_mode_is_recommend(tmp_path: Path) -> None:
    contract = _contract_yaml(tmp_path)
    findings = _empty_findings_json(tmp_path)

    result = CliRunner().invoke(
        main,
        [
            "run",
            "--contract",
            str(contract),
            "--findings",
            str(findings),
        ],
    )
    assert result.exit_code == 0, result.output
    assert "mode: recommend" in result.output


def test_run_writes_required_outputs(tmp_path: Path) -> None:
    contract = _contract_yaml(tmp_path)
    findings = _empty_findings_json(tmp_path)

    CliRunner().invoke(
        main,
        [
            "run",
            "--contract",
            str(contract),
            "--findings",
            str(findings),
        ],
    )
    workspace = tmp_path / "ws"
    assert (workspace / "findings.json").is_file()
    assert (workspace / "report.md").is_file()
    assert (workspace / "audit.jsonl").is_file()


# ---------------------------- run: mutual-exclusion gates ---------------


def test_run_refuses_both_kubeconfig_and_in_cluster(tmp_path: Path) -> None:
    contract = _contract_yaml(tmp_path)
    findings = _empty_findings_json(tmp_path)
    kubeconfig = tmp_path / "kc.yaml"
    kubeconfig.write_text("apiVersion: v1\nkind: Config\nclusters: []\n")

    result = CliRunner().invoke(
        main,
        [
            "run",
            "--contract",
            str(contract),
            "--findings",
            str(findings),
            "--mode",
            "dry_run",
            "--kubeconfig",
            str(kubeconfig),
            "--in-cluster",
        ],
    )
    assert result.exit_code != 0
    assert "mutually exclusive" in result.output


def test_run_refuses_dry_run_without_cluster_access(tmp_path: Path) -> None:
    """`--mode dry_run` or `--mode execute` requires --kubeconfig or --in-cluster."""
    contract = _contract_yaml(tmp_path)
    findings = _empty_findings_json(tmp_path)
    auth = _auth_yaml(
        tmp_path,
        mode_recommend_authorized=True,
        mode_dry_run_authorized=True,
    )

    result = CliRunner().invoke(
        main,
        [
            "run",
            "--contract",
            str(contract),
            "--findings",
            str(findings),
            "--auth",
            str(auth),
            "--mode",
            "dry_run",
        ],
    )
    assert result.exit_code != 0
    assert "requires cluster access" in result.output


def test_run_refuses_execute_without_cluster_access(tmp_path: Path) -> None:
    contract = _contract_yaml(tmp_path)
    findings = _empty_findings_json(tmp_path)

    result = CliRunner().invoke(
        main,
        [
            "run",
            "--contract",
            str(contract),
            "--findings",
            str(findings),
            "--mode",
            "execute",
        ],
    )
    assert result.exit_code != 0
    assert "requires cluster access" in result.output


# ---------------------------- run: execute lockdown (operational gate) --


def test_run_refuses_execute_without_operational_flag(tmp_path: Path) -> None:
    """`--mode execute` is locked OFF by default. The operational
    `--i-understand-this-applies-patches-to-the-cluster` flag must be supplied
    in addition to whatever `auth.yaml` says.

    This is gate G2 of the four-gate plan in the post-A.1 readiness report.
    Even an over-broad `auth.yaml` (mode_execute_authorized: true + every
    action class in the allowlist) cannot bypass the CLI-level lockdown.
    """
    contract = _contract_yaml(tmp_path)
    findings = _empty_findings_json(tmp_path)
    kubeconfig = tmp_path / "kc.yaml"
    kubeconfig.write_text("apiVersion: v1\nkind: Config\nclusters: []\n")
    # auth.yaml that DOES authorise execute — the test proves the CLI flag
    # blocks even when auth.yaml would otherwise allow.
    auth = _auth_yaml(
        tmp_path,
        mode_recommend_authorized=True,
        mode_dry_run_authorized=True,
        mode_execute_authorized=True,
        authorized_actions=[
            "remediation_k8s_patch_runAsNonRoot",
            "remediation_k8s_patch_resource_limits",
        ],
    )

    result = CliRunner().invoke(
        main,
        [
            "run",
            "--contract",
            str(contract),
            "--findings",
            str(findings),
            "--auth",
            str(auth),
            "--mode",
            "execute",
            "--kubeconfig",
            str(kubeconfig),
        ],
    )
    assert result.exit_code != 0
    assert "locked OFF by default" in result.output
    assert "i-understand-this-applies-patches-to-the-cluster" in result.output


def test_run_recommend_mode_does_not_require_operational_flag(tmp_path: Path) -> None:
    """The lockdown only applies to `--mode execute`; recommend mode is free."""
    contract = _contract_yaml(tmp_path)
    findings = _empty_findings_json(tmp_path)

    result = CliRunner().invoke(
        main,
        [
            "run",
            "--contract",
            str(contract),
            "--findings",
            str(findings),
            "--mode",
            "recommend",
        ],
    )
    assert result.exit_code == 0, result.output


def test_run_dry_run_mode_does_not_require_operational_flag(tmp_path: Path) -> None:
    """The lockdown only applies to `--mode execute`; dry_run mode is free."""
    contract = _contract_yaml(tmp_path)
    findings = _empty_findings_json(tmp_path)
    kubeconfig = tmp_path / "kc.yaml"
    kubeconfig.write_text("apiVersion: v1\nkind: Config\nclusters: []\n")
    auth = _auth_yaml(
        tmp_path,
        mode_recommend_authorized=True,
        mode_dry_run_authorized=True,
    )

    result = CliRunner().invoke(
        main,
        [
            "run",
            "--contract",
            str(contract),
            "--findings",
            str(findings),
            "--auth",
            str(auth),
            "--mode",
            "dry_run",
            "--kubeconfig",
            str(kubeconfig),
        ],
    )
    # Dry-run will try to call kubectl; we don't expect success against a stub
    # kubeconfig, but the CLI must NOT reject for missing operational flag.
    assert "locked OFF by default" not in result.output


# ---------------------------- run: mode-escalation gates ----------------


def test_run_surfaces_mode_escalation_as_usage_error(tmp_path: Path) -> None:
    """Default Authorization() refuses dry_run; the CLI surfaces it as UsageError."""
    contract = _contract_yaml(tmp_path)
    findings = _empty_findings_json(tmp_path)
    kubeconfig = tmp_path / "kc.yaml"
    kubeconfig.write_text("apiVersion: v1\nkind: Config\nclusters: []\n")
    # Auth doesn't opt into dry_run.
    auth = _auth_yaml(tmp_path, mode_recommend_authorized=True)

    result = CliRunner().invoke(
        main,
        [
            "run",
            "--contract",
            str(contract),
            "--findings",
            str(findings),
            "--auth",
            str(auth),
            "--mode",
            "dry_run",
            "--kubeconfig",
            str(kubeconfig),
        ],
    )
    assert result.exit_code != 0
    assert "mode_dry_run_authorized: true" in result.output


# ---------------------------- run: rollback window override -------------


def test_run_accepts_rollback_window_override(tmp_path: Path) -> None:
    """`--rollback-window-sec` overrides the auth.yaml value (still recommend mode)."""
    contract = _contract_yaml(tmp_path)
    findings = _empty_findings_json(tmp_path)
    auth = _auth_yaml(
        tmp_path,
        mode_recommend_authorized=True,
        rollback_window_sec=600,
    )

    result = CliRunner().invoke(
        main,
        [
            "run",
            "--contract",
            str(contract),
            "--findings",
            str(findings),
            "--auth",
            str(auth),
            "--rollback-window-sec",
            "120",
        ],
    )
    assert result.exit_code == 0, result.output


def test_run_rejects_rollback_window_outside_range(tmp_path: Path) -> None:
    contract = _contract_yaml(tmp_path)
    findings = _empty_findings_json(tmp_path)

    result = CliRunner().invoke(
        main,
        [
            "run",
            "--contract",
            str(contract),
            "--findings",
            str(findings),
            "--rollback-window-sec",
            "30",
        ],
    )
    assert result.exit_code != 0
    # Click's IntRange formats the message as "30 is not in the range 60<=x<=1800".
    assert "60" in result.output


# ---------------------------- run: required-arg / file checks -----------


def test_run_missing_contract_exits_nonzero(tmp_path: Path) -> None:
    findings = _empty_findings_json(tmp_path)
    result = CliRunner().invoke(
        main,
        ["run", "--contract", str(tmp_path / "no.yaml"), "--findings", str(findings)],
    )
    assert result.exit_code != 0


def test_run_missing_findings_exits_nonzero(tmp_path: Path) -> None:
    contract = _contract_yaml(tmp_path)
    result = CliRunner().invoke(
        main,
        ["run", "--contract", str(contract), "--findings", str(tmp_path / "no.json")],
    )
    assert result.exit_code != 0


# ---------------------------- run: --promotion (v0.1.2) -----------------


def _run_as_root_findings_json(tmp_path: Path) -> Path:
    """Write a D.6-shaped `findings.json` with one `run-as-root` finding that
    maps to the `remediation_k8s_patch_runAsNonRoot` action class."""
    path = tmp_path / "findings.json"
    now = datetime.now(UTC).isoformat()
    payload = {
        "agent": "k8s_posture",
        "agent_version": "0.3.0",
        "customer_id": "cust_test",
        "run_id": "test-run",
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
                "time": 1700000000000,
                "time_dt": now,
                "status_id": 1,
                "status": "New",
                "metadata": {
                    "version": "1.3.0",
                    "product": {"name": "Nexus K8s Posture", "vendor_name": "Nexus"},
                },
                "finding_info": {
                    "uid": "CSPM-KUBERNETES-MANIFEST-001-api",
                    "title": "Container running as root",
                    "desc": "runAsUser=0",
                    "first_seen_time": 1700000000000,
                    "last_seen_time": 1700000000000,
                    "types": ["cspm_k8s_manifest"],
                    "analytic": {"name": "run-as-root"},
                },
                "resources": [
                    {
                        "cloud": "kubernetes",
                        "account_id": "production",
                        "region": "cluster",
                        "type": "Deployment",
                        "uid": "production/api",
                        "name": "api",
                    }
                ],
                "evidences": [
                    {
                        "kind": "manifest",
                        "rule_id": "run-as-root",
                        "rule_title": "Container running as root",
                        "workload_kind": "Deployment",
                        "workload_name": "api",
                        "namespace": "production",
                        "container_name": "app",
                        "manifest_path": "cluster:///production/Deployment/api",
                    }
                ],
            }
        ],
    }
    path.write_text(json.dumps(payload))
    return path


def _stage1_promotion_yaml(tmp_path: Path) -> Path:
    """Write a `promotion.yaml` with empty `action_classes` (every action is
    implicitly at Stage 1 — the safe-by-default floor)."""
    path = tmp_path / "promotion.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "schema_version": "0.1",
                "cluster_id": "cli-promotion-test",
                "created_at": "2026-05-17T00:00:00Z",
                "last_modified_at": "2026-05-17T00:00:00Z",
                "action_classes": {},
            }
        )
    )
    return path


def test_run_promotion_flag_loads_tracker_and_fires_gate(tmp_path: Path) -> None:
    """v0.1.2: `--promotion <path>` plumbs a `PromotionTracker` through to
    `agent.run`, which fires the pre-flight stage gate. Stage 1 (empty
    `action_classes`) + `--mode execute` against an action class the gate
    would refuse must produce `refused_promotion_gate` outcome.

    Uses an empty file as `--kubeconfig` only to satisfy the CLI's
    cluster-access precheck; the agent halts at the pre-flight gate
    before reaching the executor, so the kubeconfig is never actually
    used. This isolation is the same property the live-cluster proof in
    `test_stage1_only_refuses_execute_against_live_cluster` recorded —
    here we exercise it through the CLI surface instead.
    """
    contract = _contract_yaml(tmp_path)
    findings = _run_as_root_findings_json(tmp_path)
    auth = _auth_yaml(
        tmp_path,
        mode_recommend_authorized=True,
        mode_dry_run_authorized=True,
        mode_execute_authorized=True,
        authorized_actions=["remediation_k8s_patch_runAsNonRoot"],
        max_actions_per_run=5,
        rollback_window_sec=300,
    )
    promotion = _stage1_promotion_yaml(tmp_path)
    fake_kubeconfig = tmp_path / "kubeconfig"
    fake_kubeconfig.write_text("")  # exists; never actually read

    result = CliRunner().invoke(
        main,
        [
            "run",
            "--contract",
            str(contract),
            "--findings",
            str(findings),
            "--auth",
            str(auth),
            "--mode",
            "execute",
            "--kubeconfig",
            str(fake_kubeconfig),
            "--i-understand-this-applies-patches-to-the-cluster",
            "--promotion",
            str(promotion),
        ],
    )
    assert result.exit_code == 0, result.output
    assert "refused_promotion_gate: 1" in result.output, (
        f"expected refused_promotion_gate in CLI output; got:\n{result.output}"
    )


def test_run_promotion_flag_absent_preserves_v0_1_behaviour(tmp_path: Path) -> None:
    """v0.1.2 compatibility-contract assertion: omitting `--promotion` MUST
    preserve v0.1.1's behaviour exactly — the gate is skipped (legacy
    safe default), and recommend-mode runs against an empty findings file
    still succeed without any promotion-related output.

    The other direction of this contract (the prior version's full test
    surface staying green) is asserted by `uv run pytest -q` returning
    the same passed count modulo the new tests added in this file. This
    test specifically pins the "absent flag, default behaviour" property
    as a regression marker.
    """
    contract = _contract_yaml(tmp_path)
    findings = _empty_findings_json(tmp_path)

    result = CliRunner().invoke(
        main,
        ["run", "--contract", str(contract), "--findings", str(findings)],
    )
    assert result.exit_code == 0, result.output
    assert "mode: recommend" in result.output
    assert "refused_promotion_gate" not in result.output, (
        f"absent --promotion must NOT produce promotion-gate output; got:\n{result.output}"
    )


def test_run_promotion_flag_invalid_path_errors_via_click(tmp_path: Path) -> None:
    """v0.1.2: a non-existent `--promotion` path must be rejected by
    Click's `exists=True` type check before the agent runs — no
    half-started run, no partial output, just a usage error.

    This mirrors the existing `--auth`, `--contract`, and `--findings`
    file-check semantics; consistency with the prior version's CLI
    surface is one of ADR-010's six eligibility conditions.
    """
    contract = _contract_yaml(tmp_path)
    findings = _empty_findings_json(tmp_path)
    nonexistent_promotion = tmp_path / "no-such-promotion.yaml"
    assert not nonexistent_promotion.exists()

    result = CliRunner().invoke(
        main,
        [
            "run",
            "--contract",
            str(contract),
            "--findings",
            str(findings),
            "--promotion",
            str(nonexistent_promotion),
        ],
    )
    assert result.exit_code != 0
    assert "does not exist" in result.output.lower() or "no such" in result.output.lower(), (
        f"expected file-not-found-style usage error; got:\n{result.output}"
    )
