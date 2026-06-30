"""Red-team bank for CAN_ESCALATE_TO (slice #1) — privilege-escalation detection.

Built around the precision crux: an escalation edge is emitted ONLY when a trigger action AND a
resolvable ADMIN target are both present. The false-positive traps (action present, no real target)
are the heavy set — they prove the detector is precise, not just loud.
"""

from datetime import UTC, datetime

from identity.agent import _escalation_grants
from identity.tools.aws_iam import IamPolicy, IamRole, IamUser, IdentityListing

_DATE = datetime(2026, 6, 29, tzinfo=UTC)
_ACCT = "111122223333"
_ATTACKER = f"arn:aws:iam::{_ACCT}:user/attacker"
_ADMIN_ROLE = f"arn:aws:iam::{_ACCT}:role/admin"
_ADMIN_USER = f"arn:aws:iam::{_ACCT}:user/root-admin"
_PLAIN_ROLE = f"arn:aws:iam::{_ACCT}:role/readonly"
_ADMIN_ATTACHED = ("arn:aws:iam::aws:policy/AdministratorAccess",)


def _doc(statements: list[tuple[object, object]]) -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": a, "Resource": r} for a, r in statements],
    }


def _admin_role(arn: str = _ADMIN_ROLE, attached: tuple[str, ...] = _ADMIN_ATTACHED) -> IamRole:
    return IamRole(
        arn=arn,
        name=arn.rsplit("/", 1)[-1],
        role_id="AROAADMIN",
        create_date=_DATE,
        last_used_at=None,
        assume_role_policy_document={},
        attached_policy_arns=attached,
    )


def _admin_user() -> IamUser:
    return IamUser(
        arn=_ADMIN_USER,
        name="root-admin",
        user_id="AIDAADMIN",
        create_date=_DATE,
        last_used_at=None,
        attached_policy_arns=_ADMIN_ATTACHED,
    )


def _attacker(statements: list[tuple[object, object]], *, boundary_arn: str = "") -> IamUser:
    return IamUser(
        arn=_ATTACKER,
        name="attacker",
        user_id="AIDAATTACKER",
        create_date=_DATE,
        last_used_at=None,
        inline_policies=(("inline", _doc(statements)),),
        permission_boundary_arn=boundary_arn,
    )


def _listing(attacker: IamUser, *, roles=(), users=(), policies=()) -> IdentityListing:
    return IdentityListing(
        users=(attacker, *users), roles=tuple(roles), groups=(), policies=tuple(policies)
    )


def _methods(listing: IdentityListing) -> set[tuple[str, str]]:
    """(target_arn, method) edges originating from the attacker."""
    return {(t, m) for (p, t, m, _v) in _escalation_grants(listing) if p == _ATTACKER}


# ----------------------------- standard violations (each method → edge) -----------------------------


def test_self_grant_admin():
    listing = _listing(_attacker([("iam:AttachUserPolicy", "*")]), roles=(_admin_role(),))
    assert (_ADMIN_ROLE, "self_grant_admin") in _methods(listing)


def test_policy_rewrite_on_admin_attached_policy():
    cust = IamPolicy(
        arn=f"arn:aws:iam::{_ACCT}:policy/shared",
        name="shared",
        policy_id="ANPASHARED",
        default_version_id="v1",
        document=_doc([("*", "*")]),
    )
    admin = _admin_role(
        attached=(_ADMIN_ATTACHED[0], cust.arn)
    )  # admin AND holds the versionable policy
    listing = _listing(
        _attacker([("iam:CreatePolicyVersion", "*")]), roles=(admin,), policies=(cust,)
    )
    assert (_ADMIN_ROLE, "policy_rewrite") in _methods(listing)


def test_trust_rewrite_on_admin_role():
    listing = _listing(
        _attacker([("iam:UpdateAssumeRolePolicy", _ADMIN_ROLE)]), roles=(_admin_role(),)
    )
    assert (_ADMIN_ROLE, "trust_rewrite") in _methods(listing)


def test_credential_mint_on_admin_user():
    listing = _listing(_attacker([("iam:CreateAccessKey", _ADMIN_USER)]), users=(_admin_user(),))
    assert (_ADMIN_USER, "credential_mint") in _methods(listing)


def test_pass_privileged_role_with_launch():
    listing = _listing(
        _attacker([("iam:PassRole", _ADMIN_ROLE), ("lambda:CreateFunction", "*")]),
        roles=(_admin_role(),),
    )
    assert (_ADMIN_ROLE, "pass_privileged_role") in _methods(listing)


# ----------------------------- false-positive traps (the heavy set → NO edge) -----------------------


def test_trap_policy_rewrite_on_unattached_policy():
    # CreatePolicyVersion, but the policy is attached to NOTHING → not escalation.
    cust = IamPolicy(
        arn=f"arn:aws:iam::{_ACCT}:policy/orphan",
        name="orphan",
        policy_id="ANPAORPHAN",
        default_version_id="v1",
        document=_doc([("*", "*")]),
    )
    listing = _listing(
        _attacker([("iam:CreatePolicyVersion", "*")]), roles=(_admin_role(),), policies=(cust,)
    )
    assert _methods(listing) == set()


def test_trap_pass_non_admin_role():
    # PassRole + launch, but the passable role is NOT admin → no escalation.
    listing = _listing(
        _attacker([("iam:PassRole", _PLAIN_ROLE), ("lambda:CreateFunction", "*")]),
        roles=(
            _admin_role(),
            IamRole(
                arn=_PLAIN_ROLE,
                name="readonly",
                role_id="AROARO",
                create_date=_DATE,
                last_used_at=None,
                assume_role_policy_document={},
            ),
        ),
    )
    assert all(t != _PLAIN_ROLE for t, _m in _methods(listing))


def test_trap_attach_scoped_to_other_specific_resource():
    # AttachUserPolicy scoped to a specific OTHER non-admin resource (not * / not self) → no self-admin.
    other = f"arn:aws:iam::{_ACCT}:user/intern"
    listing = _listing(_attacker([("iam:AttachUserPolicy", other)]), roles=(_admin_role(),))
    assert "self_grant_admin" not in {m for _t, m in _methods(listing)}


def test_trap_read_only_actions():
    listing = _listing(
        _attacker([(["iam:GetPolicy", "iam:ListRoles"], "*")]), roles=(_admin_role(),)
    )
    assert _methods(listing) == set()


def test_trap_no_admin_in_account():
    # No admin exists → nothing to escalate to, even with every dangerous action.
    listing = _listing(_attacker([("iam:*", "*")]))
    assert _escalation_grants(listing) == []


# ----------------------------- edge cases -----------------------------


def test_permission_boundary_caps_escalation():
    # AttachUserPolicy on *, but a boundary that only allows S3 → the action is capped, no edge.
    boundary = IamPolicy(
        arn=f"arn:aws:iam::{_ACCT}:policy/s3only",
        name="s3only",
        policy_id="ANPAS3",
        default_version_id="v1",
        document=_doc([("s3:GetObject", "*")]),
    )
    attacker = _attacker([("iam:AttachUserPolicy", "*")], boundary_arn=boundary.arn)
    listing = _listing(attacker, roles=(_admin_role(),), policies=(boundary,))
    assert _methods(listing) == set()


def test_already_admin_principal_does_not_escalate():
    # An admin with privesc actions is not an escalation source (skipped).
    admin_attacker = IamUser(
        arn=_ATTACKER,
        name="attacker",
        user_id="AIDAATTACKER",
        create_date=_DATE,
        last_used_at=None,
        attached_policy_arns=_ADMIN_ATTACHED,
        inline_policies=(("inline", _doc([("iam:*", "*")])),),
    )
    listing = _listing(admin_attacker, roles=(_admin_role(),))
    assert _methods(listing) == set()
