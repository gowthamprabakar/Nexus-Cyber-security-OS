"""Tests for the Slack posture rules (D.10 SSPM PR4)."""

from __future__ import annotations

from datetime import UTC, datetime

from shared.fabric.envelope import NexusEnvelope
from sspm.posture.slack import SlackFindingType, evaluate_slack_workspace
from sspm.tools.slack import SlackOAuthApp, SlackWorkspaceInventory

_NOW = datetime(2026, 6, 17, 12, 0, 0, tzinfo=UTC)


def _envelope() -> NexusEnvelope:
    return NexusEnvelope(
        correlation_id="c",
        tenant_id="cust_test",
        agent_id="sspm",
        nlah_version="0.1.0",
        model_pin="deterministic",
        charter_invocation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
    )


def _types(findings: list) -> set[str]:
    return {f.finding_type for f in findings}


def test_all_five_checks_fire() -> None:
    inv = SlackWorkspaceInventory(
        team_id="T01",
        team_name="Acme",
        owners=9,
        admins=9,
        guests=2,
        members_without_2fa=3,
        oauth_apps=(SlackOAuthApp(app_id="A1", name="Risky", scopes=("admin",)),),
    )
    findings = evaluate_slack_workspace(inv, envelope=_envelope(), detected_at=_NOW)
    assert _types(findings) == {t.value for t in SlackFindingType}  # all 5
    ids = {f.finding_id for f in findings}
    assert "SSPM-SLACK-001-t01" in ids
    assert "SSPM-SLACK-005-t01-a1" in ids
    assert all(f.to_dict()["class_uid"] == 2003 for f in findings)


def test_clean_workspace_yields_no_findings() -> None:
    inv = SlackWorkspaceInventory(
        team_id="T01",
        team_name="Acme",
        owners=2,
        admins=3,
        guests=0,
        members_without_2fa=0,
        oauth_apps=(SlackOAuthApp(app_id="A2", name="Safe", scopes=("chat:write",)),),
    )
    assert evaluate_slack_workspace(inv, envelope=_envelope(), detected_at=_NOW) == []


def test_2fa_unknown_skips() -> None:
    inv = SlackWorkspaceInventory(
        team_id="T01",
        team_name="Acme",
        owners=1,
        admins=1,
        guests=0,
        members_without_2fa=None,  # unexposed → never flags
        oauth_apps=(),
    )
    assert evaluate_slack_workspace(inv, envelope=_envelope(), detected_at=_NOW) == []
