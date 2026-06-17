"""GitHub-org posture rules (D.10 SSPM PR2).

Evaluates a typed :class:`~sspm.tools.github_org.GitHubOrgInventory` into OCSF 2003
findings — 8 real posture checks (3 org-level + 5 repo-level). Honest tri-state: a
``None`` (unknown / not visible to the token) NEVER produces a finding — only an explicit
violation does. ``finding_id`` follows ``SSPM-GH-<NNN>-<context>`` (operator format).
"""

from __future__ import annotations

import re
from datetime import datetime
from enum import StrEnum
from typing import TYPE_CHECKING

from sspm.schemas import SaaSAffectedResource, SaaSFinding, Severity, build_finding

if TYPE_CHECKING:
    from shared.fabric.envelope import NexusEnvelope

    from sspm.tools.github_org import GitHubOrgInventory, GitHubRepo


class GitHubFindingType(StrEnum):
    """Stable per-check discriminators (wired into ``finding_info.types[0]``)."""

    ORG_2FA_DISABLED = "sspm_github_org_2fa_disabled"
    DEFAULT_PERMISSION_PERMISSIVE = "sspm_github_default_permission_permissive"
    PUBLIC_REPO_CREATION_ALLOWED = "sspm_github_public_repo_creation_allowed"
    REPO_PUBLIC = "sspm_github_repo_public"
    SECRET_SCANNING_DISABLED = "sspm_github_secret_scanning_disabled"
    PUSH_PROTECTION_DISABLED = "sspm_github_push_protection_disabled"
    DEPENDABOT_UPDATES_DISABLED = "sspm_github_dependabot_updates_disabled"
    DEFAULT_BRANCH_UNPROTECTED = "sspm_github_default_branch_unprotected"


_PERMISSIVE_DEFAULT_PERMS = {"write", "admin"}


def _ctx(*parts: str) -> str:
    """Sanitize ARN/name parts into a finding_id context ([a-z0-9_-])."""
    joined = "-".join(parts)
    return re.sub(r"[^a-z0-9_-]+", "-", joined.lower()).strip("-") or "org"


def _org_resource(org: str) -> SaaSAffectedResource:
    return SaaSAffectedResource(
        provider="github", tenant_id=org, resource_type="saas_tenant", resource_id=org
    )


def _repo_resource(org: str, repo: str) -> SaaSAffectedResource:
    return SaaSAffectedResource(
        provider="github", tenant_id=org, resource_type="repository", resource_id=repo
    )


def evaluate_github_org(
    inventory: GitHubOrgInventory,
    *,
    envelope: NexusEnvelope,
    detected_at: datetime,
) -> list[SaaSFinding]:
    """Run the 8 GitHub-org posture checks over the typed inventory."""
    out: list[SaaSFinding] = []
    org = inventory.org

    # --- org-level (3) ---
    if inventory.two_factor_required is False:  # None (unknown) → skip
        out.append(
            build_finding(
                finding_id=f"SSPM-GH-001-{_ctx(org)}",
                rule_id="GH-ORG-2FA",
                finding_type=GitHubFindingType.ORG_2FA_DISABLED,
                severity=Severity.HIGH,
                title="GitHub org does not require two-factor authentication",
                description=f"Org {org!r} does not enforce 2FA for members.",
                affected=[_org_resource(org)],
                detected_at=detected_at,
                envelope=envelope,
            )
        )
    if inventory.default_repository_permission in _PERMISSIVE_DEFAULT_PERMS:
        out.append(
            build_finding(
                finding_id=f"SSPM-GH-002-{_ctx(org)}",
                rule_id="GH-ORG-DEFAULT-PERM",
                finding_type=GitHubFindingType.DEFAULT_PERMISSION_PERMISSIVE,
                severity=Severity.MEDIUM,
                title="GitHub org default repository permission is permissive",
                description=(
                    f"Org {org!r} grants members "
                    f"{inventory.default_repository_permission!r} by default."
                ),
                affected=[_org_resource(org)],
                detected_at=detected_at,
                envelope=envelope,
            )
        )
    if inventory.members_can_create_public_repos:
        out.append(
            build_finding(
                finding_id=f"SSPM-GH-003-{_ctx(org)}",
                rule_id="GH-ORG-PUBLIC-REPO-CREATE",
                finding_type=GitHubFindingType.PUBLIC_REPO_CREATION_ALLOWED,
                severity=Severity.LOW,
                title="GitHub org members can create public repositories",
                description=f"Org {org!r} allows members to create public repos.",
                affected=[_org_resource(org)],
                detected_at=detected_at,
                envelope=envelope,
            )
        )

    # --- repo-level (5) ---
    for repo in inventory.repos:
        out.extend(_evaluate_repo(org, repo, envelope=envelope, detected_at=detected_at))
    return out


def _evaluate_repo(
    org: str, repo: GitHubRepo, *, envelope: NexusEnvelope, detected_at: datetime
) -> list[SaaSFinding]:
    out: list[SaaSFinding] = []
    ctx = _ctx(org, repo.name)
    res = [_repo_resource(org, repo.name)]

    if not repo.private:
        out.append(
            build_finding(
                finding_id=f"SSPM-GH-004-{ctx}",
                rule_id="GH-REPO-PUBLIC",
                finding_type=GitHubFindingType.REPO_PUBLIC,
                severity=Severity.LOW,
                title="GitHub repository is public",
                description=f"Repository {org}/{repo.name} is public.",
                affected=res,
                detected_at=detected_at,
                envelope=envelope,
            )
        )
    if repo.secret_scanning == "disabled":
        out.append(
            build_finding(
                finding_id=f"SSPM-GH-005-{ctx}",
                rule_id="GH-REPO-SECRET-SCANNING",
                finding_type=GitHubFindingType.SECRET_SCANNING_DISABLED,
                severity=Severity.HIGH,
                title="GitHub repository secret scanning is disabled",
                description=f"Repository {org}/{repo.name} has secret scanning disabled.",
                affected=res,
                detected_at=detected_at,
                envelope=envelope,
            )
        )
    if repo.secret_scanning_push_protection == "disabled":
        out.append(
            build_finding(
                finding_id=f"SSPM-GH-006-{ctx}",
                rule_id="GH-REPO-PUSH-PROTECTION",
                finding_type=GitHubFindingType.PUSH_PROTECTION_DISABLED,
                severity=Severity.MEDIUM,
                title="GitHub repository push protection is disabled",
                description=f"Repository {org}/{repo.name} has secret-scanning push protection off.",
                affected=res,
                detected_at=detected_at,
                envelope=envelope,
            )
        )
    if repo.dependabot_security_updates == "disabled":
        out.append(
            build_finding(
                finding_id=f"SSPM-GH-007-{ctx}",
                rule_id="GH-REPO-DEPENDABOT",
                finding_type=GitHubFindingType.DEPENDABOT_UPDATES_DISABLED,
                severity=Severity.MEDIUM,
                title="GitHub repository Dependabot security updates are disabled",
                description=f"Repository {org}/{repo.name} has Dependabot security updates off.",
                affected=res,
                detected_at=detected_at,
                envelope=envelope,
            )
        )
    if repo.default_branch_protected is False:  # None (unknown) → skip
        out.append(
            build_finding(
                finding_id=f"SSPM-GH-008-{ctx}",
                rule_id="GH-REPO-BRANCH-PROTECTION",
                finding_type=GitHubFindingType.DEFAULT_BRANCH_UNPROTECTED,
                severity=Severity.HIGH,
                title="GitHub repository default branch is unprotected",
                description=(
                    f"Repository {org}/{repo.name} default branch "
                    f"{repo.default_branch!r} has no branch protection."
                ),
                affected=res,
                detected_at=detected_at,
                envelope=envelope,
            )
        )
    return out


__all__ = ["GitHubFindingType", "evaluate_github_org"]
