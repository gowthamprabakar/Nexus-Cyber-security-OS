"""NEX-402 — GCP privesc method depth: 3 distinct escalation techniques (was 1)."""

from identity.tools.gcp_iam import GcpIamBinding, escalation_grants

_ATTACKER = "user:attacker@corp.example"
_OWNER = "user:owner@corp.example"


def _b(role, *members):
    return GcpIamBinding(bucket="projects/prod", role=role, members=members)


def _methods(bindings):
    return {(m, v) for (p, _t, m, v) in escalation_grants(tuple(bindings)) if p == _ATTACKER}


def test_self_grant_admin_still_detected():
    m = _methods([_b("roles/iam.securityAdmin", _ATTACKER), _b("roles/owner", _OWNER)])
    assert ("self_grant_admin", "resourcemanager.projects.setIamPolicy") in m


def test_role_rewrite_method():
    m = _methods([_b("roles/iam.roleAdmin", _ATTACKER), _b("roles/owner", _OWNER)])
    assert ("role_rewrite", "iam.roles.update") in m


def test_credential_mint_method():
    m = _methods([_b("roles/iam.serviceAccountKeyAdmin", _ATTACKER), _b("roles/owner", _OWNER)])
    assert ("credential_mint", "iam.serviceAccountKeys.create") in m


def test_multiple_roles_yield_multiple_methods():
    m = _methods(
        [
            _b("roles/iam.securityAdmin", _ATTACKER),
            _b("roles/iam.roleAdmin", _ATTACKER),
            _b("roles/owner", _OWNER),
        ]
    )
    assert {"self_grant_admin", "role_rewrite"} <= {method for method, _v in m}


def test_trap_no_owner_still_no_edge():
    assert (
        escalation_grants((_b("roles/iam.roleAdmin", _ATTACKER), _b("roles/editor", _OWNER))) == []
    )


def test_sa_impersonation_method():
    m = _methods([_b("roles/iam.serviceAccountTokenCreator", _ATTACKER), _b("roles/owner", _OWNER)])
    assert ("sa_impersonation", "iam.serviceAccounts.getOpenIdToken") in m


def test_trap_compute_viewer_not_sa_impersonation():
    m = _methods([_b("roles/compute.viewer", _ATTACKER), _b("roles/owner", _OWNER)])
    assert not any(method == "sa_impersonation" for method, _v in m)
