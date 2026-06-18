"""Tests for the GitHub-org posture rules (D.10 SSPM PR2)."""

from __future__ import annotations

from datetime import UTC, datetime

from shared.fabric.envelope import NexusEnvelope
from sspm.posture.github import GitHubFindingType, evaluate_github_org
from sspm.tools.github_org import GitHubOrgInventory, GitHubRepo

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


def test_all_eight_checks_fire_on_a_bad_org() -> None:
    inv = GitHubOrgInventory(
        org="Acme-Corp",
        two_factor_required=False,
        default_repository_permission="admin",
        members_can_create_public_repos=True,
        repos=(
            GitHubRepo(
                name="web",
                private=False,
                default_branch="main",
                secret_scanning="disabled",
                secret_scanning_push_protection="disabled",
                dependabot_security_updates="disabled",
                default_branch_protected=False,
            ),
        ),
    )
    findings = evaluate_github_org(inv, envelope=_envelope(), detected_at=_NOW)
    assert _types(findings) == {t.value for t in GitHubFindingType}  # all 8
    # finding_id format + context sanitization (uppercase/space → lowercase-hyphen).
    ids = {f.finding_id for f in findings}
    assert "SSPM-GH-001-acme-corp" in ids
    assert "SSPM-GH-005-acme-corp-web" in ids
    # Every finding is valid OCSF 2003 with the envelope.
    assert all(f.to_dict()["class_uid"] == 2003 for f in findings)


def test_clean_org_yields_no_findings() -> None:
    inv = GitHubOrgInventory(
        org="acme",
        two_factor_required=True,
        default_repository_permission="read",
        members_can_create_public_repos=False,
        repos=(
            GitHubRepo(
                name="api",
                private=True,
                default_branch="main",
                secret_scanning="enabled",
                secret_scanning_push_protection="enabled",
                dependabot_security_updates="enabled",
                default_branch_protected=True,
            ),
        ),
    )
    assert evaluate_github_org(inv, envelope=_envelope(), detected_at=_NOW) == []


def test_unknown_tristate_never_flags() -> None:
    # two_factor_required None (not visible) + branch protection None (403) → no findings.
    inv = GitHubOrgInventory(
        org="acme",
        two_factor_required=None,
        default_repository_permission="read",
        members_can_create_public_repos=False,
        repos=(
            GitHubRepo(
                name="api",
                private=True,
                default_branch="main",
                secret_scanning="unknown",
                secret_scanning_push_protection="unknown",
                dependabot_security_updates="unknown",
                default_branch_protected=None,
            ),
        ),
    )
    assert evaluate_github_org(inv, envelope=_envelope(), detected_at=_NOW) == []
