"""Tests for the M365 posture rules (D.10 SSPM PR3)."""

from __future__ import annotations

from datetime import UTC, datetime

from shared.fabric.envelope import NexusEnvelope
from sspm.posture.m365 import M365FindingType, evaluate_m365_tenant
from sspm.tools.m365 import M365Inventory, M365OAuthGrant

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


def test_all_six_checks_fire_on_a_bad_tenant() -> None:
    inv = M365Inventory(
        tenant_id="Contoso",
        security_defaults_enabled=False,
        allow_invites_from="everyone",
        user_consent_allowed=True,
        conditional_access_policy_count=0,
        global_admin_count=9,
        oauth_grants=(M365OAuthGrant(client_id="app-1", scopes=("Mail.Read",)),),
    )
    findings = evaluate_m365_tenant(inv, envelope=_envelope(), detected_at=_NOW)
    assert _types(findings) == {t.value for t in M365FindingType}  # all 6
    ids = {f.finding_id for f in findings}
    assert "SSPM-M365-001-contoso" in ids  # sanitized context
    assert "SSPM-M365-006-contoso-app-1" in ids
    assert all(f.to_dict()["class_uid"] == 2003 for f in findings)


def test_clean_tenant_yields_no_findings() -> None:
    inv = M365Inventory(
        tenant_id="contoso",
        security_defaults_enabled=True,
        allow_invites_from="adminsAndGuestInviters",
        user_consent_allowed=False,
        conditional_access_policy_count=3,
        global_admin_count=2,
        oauth_grants=(M365OAuthGrant(client_id="app-2", scopes=("User.Read",)),),
    )
    assert evaluate_m365_tenant(inv, envelope=_envelope(), detected_at=_NOW) == []


def test_unknown_tristate_and_safe_oauth_skip() -> None:
    inv = M365Inventory(
        tenant_id="contoso",
        security_defaults_enabled=None,  # unreadable → skip
        allow_invites_from="unknown",
        user_consent_allowed=None,  # unreadable → skip
        conditional_access_policy_count=2,
        global_admin_count=None,  # unreadable → skip
        oauth_grants=(M365OAuthGrant(client_id="app", scopes=("User.Read",)),),  # not risky
    )
    assert evaluate_m365_tenant(inv, envelope=_envelope(), detected_at=_NOW) == []


def test_global_admin_threshold_is_inclusive_boundary() -> None:
    inv = M365Inventory(
        tenant_id="contoso",
        security_defaults_enabled=True,
        allow_invites_from="none",
        user_consent_allowed=False,
        conditional_access_policy_count=1,
        global_admin_count=5,  # == default max → not flagged (only > fires)
        oauth_grants=(),
    )
    assert evaluate_m365_tenant(inv, envelope=_envelope(), detected_at=_NOW) == []
