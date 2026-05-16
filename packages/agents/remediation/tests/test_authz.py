"""Tests for `remediation.authz` — Stage-2 gates."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml
from k8s_posture.tools.manifests import ManifestFinding
from remediation.authz import (
    Authorization,
    AuthorizationError,
    authorized_action_types,
    enforce_blast_radius,
    enforce_mode,
    filter_authorized_findings,
)
from remediation.schemas import RemediationActionType, RemediationMode

NOW = datetime(2026, 5, 16, 12, 0, 0, tzinfo=UTC)


def _finding(
    *,
    rule_id: str = "run-as-root",
    severity: str = "high",
    workload_name: str = "frontend",
    namespace: str = "production",
    container_name: str = "nginx",
) -> ManifestFinding:
    return ManifestFinding(
        rule_id=rule_id,
        rule_title=rule_id.replace("-", " ").title(),
        severity=severity,
        workload_kind="Deployment",
        workload_name=workload_name,
        namespace=namespace,
        container_name=container_name,
        manifest_path="cluster:///production/Deployment/frontend",
        detected_at=NOW,
    )


# ---------------------------- defaults (recommend-only) -------------------


def test_default_authorization_is_recommend_only() -> None:
    """The safest default — no flags set means `recommend` is the only authorized mode."""
    auth = Authorization()
    assert auth.mode_recommend_authorized is True
    assert auth.mode_dry_run_authorized is False
    assert auth.mode_execute_authorized is False
    assert auth.authorized_actions == []
    assert auth.max_actions_per_run == 5
    assert auth.rollback_window_sec == 300


def test_recommend_only_classmethod_matches_defaults() -> None:
    assert Authorization.recommend_only() == Authorization()


# ---------------------------- validation ----------------------------------


def test_max_actions_per_run_lower_bound() -> None:
    """The blast-radius cap can't be 0 — at least one action per run."""
    with pytest.raises(ValueError, match="greater than or equal to 1"):
        Authorization(max_actions_per_run=0)


def test_max_actions_per_run_upper_bound() -> None:
    """v0.1 hard-caps blast radius at 50 — sanity guard."""
    with pytest.raises(ValueError, match="less than or equal to 50"):
        Authorization(max_actions_per_run=51)


def test_rollback_window_lower_bound() -> None:
    """Rollback window can't drop below 60s — D.6 re-run takes >60s."""
    with pytest.raises(ValueError, match="greater than or equal to 60"):
        Authorization(rollback_window_sec=59)


def test_rollback_window_upper_bound() -> None:
    """Rollback window capped at 1800s — operators shouldn't wait 30+ minutes."""
    with pytest.raises(ValueError, match="less than or equal to 1800"):
        Authorization(rollback_window_sec=1801)


# ---------------------------- enforce_mode --------------------------------


def test_enforce_mode_recommend_passes_with_default_auth() -> None:
    enforce_mode(Authorization(), RemediationMode.RECOMMEND)


def test_enforce_mode_dry_run_refused_with_default_auth() -> None:
    with pytest.raises(AuthorizationError, match=r"dry_run.*not authorized"):
        enforce_mode(Authorization(), RemediationMode.DRY_RUN)


def test_enforce_mode_execute_refused_with_default_auth() -> None:
    with pytest.raises(AuthorizationError, match=r"execute.*not authorized"):
        enforce_mode(Authorization(), RemediationMode.EXECUTE)


def test_enforce_mode_dry_run_passes_when_authorized() -> None:
    enforce_mode(
        Authorization(mode_dry_run_authorized=True),
        RemediationMode.DRY_RUN,
    )


def test_enforce_mode_execute_passes_when_authorized() -> None:
    enforce_mode(
        Authorization(mode_execute_authorized=True),
        RemediationMode.EXECUTE,
    )


def test_enforce_mode_error_message_names_flag() -> None:
    """The error guides the operator to the exact flag they need to flip."""
    with pytest.raises(AuthorizationError, match="mode_execute_authorized"):
        enforce_mode(Authorization(), RemediationMode.EXECUTE)


# ---------------------------- filter_authorized_findings ------------------


def test_unknown_rule_id_is_refused() -> None:
    """A rule that has no v0.1 action class (e.g. privileged-container) is refused."""
    auth = Authorization(
        authorized_actions=["remediation_k8s_patch_runAsNonRoot"],
    )
    findings = [_finding(rule_id="privileged-container")]
    authorized, refused = filter_authorized_findings(auth, findings)
    assert authorized == []
    assert len(refused) == 1
    assert "no v0.1 action class" in refused[0][1]


def test_action_not_in_allowlist_is_refused() -> None:
    """A rule_id with a known action class but not allowlisted in auth → refused."""
    auth = Authorization(authorized_actions=[])  # empty allowlist
    findings = [_finding(rule_id="run-as-root")]
    authorized, refused = filter_authorized_findings(auth, findings)
    assert authorized == []
    assert len(refused) == 1
    assert "not in authorized_actions allowlist" in refused[0][1]


def test_allowlisted_action_is_authorized() -> None:
    auth = Authorization(
        authorized_actions=[RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT.value],
    )
    findings = [_finding(rule_id="run-as-root")]
    authorized, refused = filter_authorized_findings(auth, findings)
    assert len(authorized) == 1
    assert refused == []


def test_filter_partitions_mixed_findings_correctly() -> None:
    """Some authorized, some refused (action not allowlisted), some refused
    (no action class) — all three buckets surface correctly."""
    auth = Authorization(
        authorized_actions=[RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT.value],
    )
    findings = [
        _finding(rule_id="run-as-root", workload_name="a"),  # authorized
        _finding(rule_id="missing-resource-limits", workload_name="b"),  # not allowlisted
        _finding(rule_id="privileged-container", workload_name="c"),  # no action class
        _finding(rule_id="run-as-root", workload_name="d"),  # authorized
    ]
    authorized, refused = filter_authorized_findings(auth, findings)
    assert len(authorized) == 2
    assert {f.workload_name for f in authorized} == {"a", "d"}
    assert len(refused) == 2


# ---------------------------- enforce_blast_radius ------------------------


def test_blast_radius_within_cap_passes() -> None:
    auth = Authorization(max_actions_per_run=5)
    enforce_blast_radius(auth, 3)
    enforce_blast_radius(auth, 5)  # exactly at cap


def test_blast_radius_exceeded_raises() -> None:
    auth = Authorization(max_actions_per_run=3)
    with pytest.raises(AuthorizationError, match="exceeds max_actions_per_run=3"):
        enforce_blast_radius(auth, 4)


# ---------------------------- authorized_action_types ---------------------


def test_authorized_action_types_returns_enum_set() -> None:
    auth = Authorization(
        authorized_actions=[
            RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT.value,
            RemediationActionType.K8S_PATCH_RESOURCE_LIMITS.value,
        ]
    )
    result = authorized_action_types(auth)
    assert RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT in result
    assert RemediationActionType.K8S_PATCH_RESOURCE_LIMITS in result
    assert RemediationActionType.K8S_PATCH_READ_ONLY_ROOT_FS not in result


def test_authorized_action_types_drops_unknown_strings() -> None:
    """An unknown string in the allowlist is silently dropped (unknown actions
    can't execute anyway, so the allowlist entry is benign)."""
    auth = Authorization(
        authorized_actions=[
            RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT.value,
            "remediation_made_up_action",
        ]
    )
    result = authorized_action_types(auth)
    assert len(result) == 1
    assert RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT in result


# ---------------------------- from_path -----------------------------------


def test_from_path_loads_full_authorization_from_yaml(tmp_path: Path) -> None:
    auth_yaml = tmp_path / "auth.yaml"
    auth_yaml.write_text(
        yaml.safe_dump(
            {
                "mode_recommend_authorized": True,
                "mode_dry_run_authorized": True,
                "mode_execute_authorized": True,
                "authorized_actions": [
                    "remediation_k8s_patch_runAsNonRoot",
                    "remediation_k8s_patch_resource_limits",
                ],
                "max_actions_per_run": 3,
                "rollback_window_sec": 600,
            }
        )
    )
    auth = Authorization.from_path(auth_yaml)
    assert auth.mode_execute_authorized is True
    assert auth.authorized_actions == [
        "remediation_k8s_patch_runAsNonRoot",
        "remediation_k8s_patch_resource_limits",
    ]
    assert auth.max_actions_per_run == 3
    assert auth.rollback_window_sec == 600


def test_from_path_empty_yaml_yields_defaults(tmp_path: Path) -> None:
    """An empty YAML file should produce the recommend-only default — not an error."""
    auth_yaml = tmp_path / "auth.yaml"
    auth_yaml.write_text("")
    auth = Authorization.from_path(auth_yaml)
    assert auth.mode_recommend_authorized is True
    assert auth.mode_dry_run_authorized is False
    assert auth.mode_execute_authorized is False
