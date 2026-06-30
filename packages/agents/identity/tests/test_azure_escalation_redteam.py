"""Red-team bank for Azure CAN_ESCALATE_TO — the same edge contract as AWS, on Azure RBAC.

Same precision crux: an escalation edge is emitted ONLY when a role-assignment-write capability AND a
resolvable Owner target are both present. The traps (capability but no Owner / read-only roles) prove
precision on the second cloud.
"""

from identity.tools.azure_rbac import AzureRoleAssignment, escalation_grants

_ATTACKER = "11111111-1111-1111-1111-111111111111"
_OWNER = "22222222-2222-2222-2222-222222222222"
_SCOPE = "/subscriptions/sub-1"


def _ra(principal: str, role: str, scope: str = _SCOPE) -> AzureRoleAssignment:
    return AzureRoleAssignment(principal_id=principal, role_name=role, scope=scope)


def _methods(assignments) -> set[tuple[str, str]]:
    return {(t, m) for (p, t, m, _v) in escalation_grants(tuple(assignments)) if p == _ATTACKER}


# ----------------------------- standard violations → edge -----------------------------


def test_user_access_administrator_can_become_owner():
    a = [_ra(_ATTACKER, "User Access Administrator"), _ra(_OWNER, "Owner")]
    assert (_OWNER, "self_grant_admin") in _methods(a)


def test_rbac_administrator_can_become_owner():
    a = [_ra(_ATTACKER, "Role Based Access Control Administrator"), _ra(_OWNER, "Owner")]
    assert (_OWNER, "self_grant_admin") in _methods(a)


def test_via_action_is_role_assignment_write():
    a = (_ra(_ATTACKER, "User Access Administrator"), _ra(_OWNER, "Owner"))
    via = {v for (_p, _t, _m, v) in escalation_grants(a)}
    assert via == {"Microsoft.Authorization/roleAssignments/write"}


# ----------------------------- false-positive traps → NO edge -----------------------------


def test_trap_no_owner_to_become():
    # Role-assignment-write capability but NO Owner exists to escalate to → not a confirmed edge.
    a = [_ra(_ATTACKER, "User Access Administrator"), _ra(_OWNER, "Reader")]
    assert escalation_grants(tuple(a)) == []


def test_trap_reader_is_not_a_source():
    a = [_ra(_ATTACKER, "Reader"), _ra(_OWNER, "Owner")]
    assert _methods(a) == set()


def test_trap_blob_data_reader_is_not_control_plane_escalation():
    # A data-plane role does not grant role-assignment write → not an escalation source.
    a = [_ra(_ATTACKER, "Storage Blob Data Reader"), _ra(_OWNER, "Owner")]
    assert _methods(a) == set()


def test_trap_owner_is_not_its_own_escalation_source():
    # A principal that is BOTH Owner and UAA is already admin → not a source (no self-edge).
    a = [_ra(_ATTACKER, "Owner"), _ra(_ATTACKER, "User Access Administrator"), _ra(_OWNER, "Owner")]
    assert all(t != _ATTACKER for t, _m in _methods(a))
    # ...and it isn't emitted as a source at all (it's already admin).
    assert _ATTACKER not in {p for (p, _t, _m, _v) in escalation_grants(tuple(a))}
