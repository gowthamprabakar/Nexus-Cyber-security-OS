"""Red-team bank for GCP CAN_ESCALATE_TO — the same edge contract as AWS/Azure, on GCP project IAM.

Same precision crux: an escalation edge is emitted ONLY when a project-IAM-policy-write role AND a
resolvable ``roles/owner`` target are both present. Traps (write capability but no owner / read-only
role / storage role) prove precision on the third cloud.
"""

from identity.tools.gcp_iam import GcpIamBinding, escalation_grants

_ATTACKER = "user:attacker@corp.example"
_OWNER = "user:owner@corp.example"
_PROJECT = "projects/prod"


def _b(role: str, *members: str) -> GcpIamBinding:
    return GcpIamBinding(bucket=_PROJECT, role=role, members=members)


def _methods(bindings) -> set[tuple[str, str]]:
    return {(t, m) for (p, t, m, _v) in escalation_grants(tuple(bindings)) if p == _ATTACKER}


# ----------------------------- standard violations → edge -----------------------------


def test_security_admin_can_become_owner():
    b = [_b("roles/iam.securityAdmin", _ATTACKER), _b("roles/owner", _OWNER)]
    assert (_OWNER, "self_grant_admin") in _methods(b)


def test_project_iam_admin_can_become_owner():
    b = [_b("roles/resourcemanager.projectIamAdmin", _ATTACKER), _b("roles/owner", _OWNER)]
    assert (_OWNER, "self_grant_admin") in _methods(b)


def test_via_action_is_set_iam_policy():
    b = (_b("roles/iam.securityAdmin", _ATTACKER), _b("roles/owner", _OWNER))
    via = {v for (_p, _t, _m, v) in escalation_grants(b)}
    assert via == {"resourcemanager.projects.setIamPolicy"}


# ----------------------------- false-positive traps → NO edge -----------------------------


def test_trap_no_owner_to_become():
    b = [_b("roles/iam.securityAdmin", _ATTACKER), _b("roles/editor", _OWNER)]
    assert escalation_grants(tuple(b)) == []


def test_trap_viewer_is_not_a_source():
    b = [_b("roles/viewer", _ATTACKER), _b("roles/owner", _OWNER)]
    assert _methods(b) == set()


def test_trap_storage_role_is_not_iam_escalation():
    # A data-plane storage role does not grant setIamPolicy → not an escalation source.
    b = [_b("roles/storage.objectViewer", _ATTACKER), _b("roles/owner", _OWNER)]
    assert _methods(b) == set()


def test_trap_owner_is_not_its_own_escalation_source():
    # A member that is BOTH owner and securityAdmin is already admin → not a source.
    b = [_b("roles/iam.securityAdmin", _ATTACKER, _OWNER), _b("roles/owner", _ATTACKER)]
    assert all(t != _ATTACKER for t, _m in _methods(b))
    assert _ATTACKER not in {p for (p, _t, _m, _v) in escalation_grants(tuple(b))}
