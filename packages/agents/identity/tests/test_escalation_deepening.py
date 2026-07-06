"""Red-team bank for CAN_ESCALATE_TO slice #2 — 13 new methods (methods 6-11, 13-18).

One positive test per new method (trigger action → edge emitted) plus one false-positive trap
(action present, no resolvable target / boundary-capped / wrong action → NO edge).

Also covers:
- refactor-safety: admin_arns empty + non-admin method (create_access_key_on_other) → edge IS emitted.
- moto pipeline: end-to-end via boto3 IAM (moto) → run() → CAN_ESCALATE_TO attacker→bob exists.
- data-path e2e: attacker --create_access_key_on_other--> bob --HAS_ACCESS_TO--> bucket
  --EXPOSES_DATA--> data → find_escalation_method_to_data fires with method=create_access_key_on_other.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from identity.agent import _escalation_grants
from identity.tools.aws_iam import IamGroup, IamPolicy, IamRole, IamUser, IdentityListing

_DATE = datetime(2026, 6, 29, tzinfo=UTC)
_ACCT = "111122223333"
_ATTACKER = f"arn:aws:iam::{_ACCT}:user/attacker"
_ADMIN_ROLE = f"arn:aws:iam::{_ACCT}:role/admin"
_ADMIN_USER = f"arn:aws:iam::{_ACCT}:user/root-admin"
_ADMIN_GROUP = f"arn:aws:iam::{_ACCT}:group/admins"
_BOB = f"arn:aws:iam::{_ACCT}:user/bob"
_PLAIN_ROLE = f"arn:aws:iam::{_ACCT}:role/readonly"
_PLAIN_ROLE2 = f"arn:aws:iam::{_ACCT}:role/readonly2"
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


def _admin_group() -> IamGroup:
    return IamGroup(
        arn=_ADMIN_GROUP,
        name="admins",
        group_id="AGPAADMIN",
        create_date=_DATE,
        attached_policy_arns=_ADMIN_ATTACHED,
    )


def _bob() -> IamUser:
    return IamUser(
        arn=_BOB,
        name="bob",
        user_id="AIDABOB",
        create_date=_DATE,
        last_used_at=None,
    )


def _plain_role(arn: str = _PLAIN_ROLE) -> IamRole:
    return IamRole(
        arn=arn,
        name=arn.rsplit("/", 1)[-1],
        role_id="AROARO",
        create_date=_DATE,
        last_used_at=None,
        assume_role_policy_document={},
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


def _listing(
    attacker: IamUser,
    *,
    roles: tuple = (),
    users: tuple = (),
    groups: tuple = (),
    policies: tuple = (),
) -> IdentityListing:
    return IdentityListing(
        users=(attacker, *users),
        roles=tuple(roles),
        groups=tuple(groups),
        policies=tuple(policies),
    )


def _methods(listing: IdentityListing) -> set[tuple[str, str]]:
    """(target_arn, method) edges originating from the attacker."""
    return {(t, m) for (p, t, m, _v) in _escalation_grants(listing) if p == _ATTACKER}


# ====================== Method 6: set_default_policy_version ======================


def test_set_default_policy_version_emits_to_admin():
    cust = IamPolicy(
        arn=f"arn:aws:iam::{_ACCT}:policy/shared",
        name="shared",
        policy_id="ANPASHARED",
        default_version_id="v1",
        document=_doc([("*", "*")]),
    )
    admin = _admin_role(attached=(_ADMIN_ATTACHED[0], cust.arn))
    listing = _listing(
        _attacker([("iam:SetDefaultPolicyVersion", "*")]),
        roles=(admin,),
        policies=(cust,),
    )
    assert (_ADMIN_ROLE, "set_default_policy_version") in _methods(listing)


def test_trap_set_default_policy_version_aws_managed():
    # AWS-managed policy cannot be versioned by customers — no edge even if action is granted.
    listing = _listing(
        _attacker([("iam:SetDefaultPolicyVersion", "*")]),
        roles=(_admin_role(),),
    )
    # _ADMIN_ROLE only has the AWS-managed policy (AdministratorAccess), not a customer one.
    assert "set_default_policy_version" not in {m for _t, m in _methods(listing)}


# ====================== Method 7: create_access_key_on_other ======================


def test_create_access_key_on_other_non_admin_user():
    listing = _listing(
        _attacker([("iam:CreateAccessKey", _BOB)]),
        users=(_bob(),),
        roles=(_admin_role(),),  # admin exists but attacker targets bob
    )
    assert (_BOB, "create_access_key_on_other") in _methods(listing)


def test_trap_create_access_key_non_existent_user():
    # Resource scoped to a user not in the listing → no target resolves.
    ghost = f"arn:aws:iam::{_ACCT}:user/ghost"
    listing = _listing(
        _attacker([("iam:CreateAccessKey", ghost)]),
        roles=(_admin_role(),),
    )
    assert "create_access_key_on_other" not in {m for _t, m in _methods(listing)}


# ====================== Method 8: update_login_profile ======================


def test_update_login_profile_emits_for_any_user():
    listing = _listing(
        _attacker([("iam:UpdateLoginProfile", _BOB)]),
        users=(_bob(),),
        roles=(_admin_role(),),
    )
    assert (_BOB, "update_login_profile") in _methods(listing)


def test_trap_update_login_profile_scoped_to_nonexistent():
    ghost = f"arn:aws:iam::{_ACCT}:user/ghost"
    listing = _listing(
        _attacker([("iam:UpdateLoginProfile", ghost)]),
        roles=(_admin_role(),),
    )
    assert "update_login_profile" not in {m for _t, m in _methods(listing)}


def test_update_login_profile_also_adds_to_credential_mint_for_admin():
    # UpdateLoginProfile on an admin user should emit credential_mint (method 4 extended).
    listing = _listing(
        _attacker([("iam:UpdateLoginProfile", _ADMIN_USER)]),
        users=(_admin_user(),),
    )
    assert (_ADMIN_USER, "credential_mint") in _methods(listing)


# ====================== Method 9: attach_group_policy ======================


def test_attach_group_policy_on_admin_group():
    listing = _listing(
        _attacker([("iam:AttachGroupPolicy", _ADMIN_GROUP)]),
        roles=(_admin_role(),),
        groups=(_admin_group(),),
    )
    assert (_ADMIN_GROUP, "attach_group_policy") in _methods(listing)


def test_trap_attach_group_policy_non_admin_group():
    plain_group_arn = f"arn:aws:iam::{_ACCT}:group/developers"
    plain_group = IamGroup(
        arn=plain_group_arn,
        name="developers",
        group_id="AGPADEV",
        create_date=_DATE,
    )
    listing = _listing(
        _attacker([("iam:AttachGroupPolicy", plain_group_arn)]),
        roles=(_admin_role(),),
        groups=(plain_group,),
    )
    assert "attach_group_policy" not in {m for _t, m in _methods(listing)}


# ====================== Method 10: put_group_policy ======================


def test_put_group_policy_on_admin_group():
    listing = _listing(
        _attacker([("iam:PutGroupPolicy", _ADMIN_GROUP)]),
        roles=(_admin_role(),),
        groups=(_admin_group(),),
    )
    assert (_ADMIN_GROUP, "put_group_policy") in _methods(listing)


def test_trap_put_group_policy_non_admin_group():
    plain_group_arn = f"arn:aws:iam::{_ACCT}:group/developers"
    plain_group = IamGroup(
        arn=plain_group_arn,
        name="developers",
        group_id="AGPADEV",
        create_date=_DATE,
    )
    listing = _listing(
        _attacker([("iam:PutGroupPolicy", plain_group_arn)]),
        roles=(_admin_role(),),
        groups=(plain_group,),
    )
    assert "put_group_policy" not in {m for _t, m in _methods(listing)}


# ====================== Method 11: add_user_to_group ======================


def test_add_user_to_group_admin_group():
    listing = _listing(
        _attacker([("iam:AddUserToGroup", _ADMIN_GROUP)]),
        roles=(_admin_role(),),
        groups=(_admin_group(),),
    )
    assert (_ADMIN_GROUP, "add_user_to_group") in _methods(listing)


def test_trap_add_user_to_non_admin_group():
    plain_group_arn = f"arn:aws:iam::{_ACCT}:group/developers"
    plain_group = IamGroup(
        arn=plain_group_arn,
        name="developers",
        group_id="AGPADEV",
        create_date=_DATE,
    )
    listing = _listing(
        _attacker([("iam:AddUserToGroup", plain_group_arn)]),
        roles=(_admin_role(),),
        groups=(plain_group,),
    )
    assert "add_user_to_group" not in {m for _t, m in _methods(listing)}


# ====================== Methods 13-16: per-service pass_role to non-admin role ======================


def test_lambda_pass_role_non_admin_role():
    listing = _listing(
        _attacker([("iam:PassRole", _PLAIN_ROLE), ("lambda:CreateFunction", "*")]),
        roles=(_admin_role(), _plain_role()),
    )
    assert (_PLAIN_ROLE, "lambda_pass_role") in _methods(listing)


def test_lambda_pass_role_via_update_function_code():
    # lambda:UpdateFunctionCode is also a valid lambda trigger.
    listing = _listing(
        _attacker([("iam:PassRole", _PLAIN_ROLE), ("lambda:UpdateFunctionCode", "*")]),
        roles=(_admin_role(), _plain_role()),
    )
    assert (_PLAIN_ROLE, "lambda_pass_role") in _methods(listing)


def test_ec2_pass_role_non_admin_role():
    listing = _listing(
        _attacker([("iam:PassRole", _PLAIN_ROLE), ("ec2:RunInstances", "*")]),
        roles=(_admin_role(), _plain_role()),
    )
    assert (_PLAIN_ROLE, "ec2_pass_role") in _methods(listing)


def test_glue_pass_role_non_admin_role():
    listing = _listing(
        _attacker([("iam:PassRole", _PLAIN_ROLE), ("glue:CreateDevEndpoint", "*")]),
        roles=(_admin_role(), _plain_role()),
    )
    assert (_PLAIN_ROLE, "glue_pass_role") in _methods(listing)


def test_cloudformation_pass_role_non_admin_role():
    listing = _listing(
        _attacker([("iam:PassRole", _PLAIN_ROLE), ("cloudformation:CreateStack", "*")]),
        roles=(_admin_role(), _plain_role()),
    )
    assert (_PLAIN_ROLE, "cloudformation_pass_role") in _methods(listing)


def test_trap_pass_role_without_launch_action():
    # PassRole alone, no launch action → none of the pass_role methods fire.
    listing = _listing(
        _attacker([("iam:PassRole", _PLAIN_ROLE)]),
        roles=(_admin_role(), _plain_role()),
    )
    assert not any(
        m in {"lambda_pass_role", "ec2_pass_role", "glue_pass_role", "cloudformation_pass_role"}
        for _t, m in _methods(listing)
    )


def test_trap_pass_role_admin_role_not_in_non_admin_methods():
    # When PassRole + lambda on an admin role, only pass_privileged_role fires (not lambda_pass_role).
    listing = _listing(
        _attacker([("iam:PassRole", _ADMIN_ROLE), ("lambda:CreateFunction", "*")]),
        roles=(_admin_role(),),
    )
    methods = _methods(listing)
    assert (_ADMIN_ROLE, "pass_privileged_role") in methods
    # The admin role should NOT get a lambda_pass_role edge (it's in non_admin_roles only).
    assert (_ADMIN_ROLE, "lambda_pass_role") not in methods


# ====================== Method 17: create_instance_profile ======================


def test_create_instance_profile_all_three_actions():
    listing = _listing(
        _attacker(
            [
                ("iam:CreateInstanceProfile", "*"),
                ("iam:AddRoleToInstanceProfile", "*"),
                ("ec2:RunInstances", "*"),
            ]
        ),
        roles=(_admin_role(), _plain_role()),
    )
    methods = _methods(listing)
    assert any(m == "create_instance_profile" for _t, m in methods)


def test_trap_create_instance_profile_missing_ec2():
    # Missing ec2:RunInstances → method 17 does not fire.
    listing = _listing(
        _attacker(
            [
                ("iam:CreateInstanceProfile", "*"),
                ("iam:AddRoleToInstanceProfile", "*"),
                # ec2:RunInstances absent
            ]
        ),
        roles=(_admin_role(), _plain_role()),
    )
    assert "create_instance_profile" not in {m for _t, m in _methods(listing)}


def test_trap_create_instance_profile_missing_add_role():
    # Missing iam:AddRoleToInstanceProfile → method 17 does not fire.
    listing = _listing(
        _attacker(
            [
                ("iam:CreateInstanceProfile", "*"),
                # iam:AddRoleToInstanceProfile absent
                ("ec2:RunInstances", "*"),
            ]
        ),
        roles=(_admin_role(), _plain_role()),
    )
    assert "create_instance_profile" not in {m for _t, m in _methods(listing)}


# ====================== Method 18: update_assume_role_policy_any ======================


def test_update_assume_role_policy_any_non_admin_role():
    listing = _listing(
        _attacker([("iam:UpdateAssumeRolePolicy", _PLAIN_ROLE)]),
        roles=(_admin_role(), _plain_role()),
    )
    assert (_PLAIN_ROLE, "update_assume_role_policy_any") in _methods(listing)


def test_trust_rewrite_admin_and_update_assume_non_admin_coexist():
    # When UpdateAssumeRolePolicy is granted on *, trust_rewrite fires for admin roles
    # and update_assume_role_policy_any fires for non-admin roles.
    listing = _listing(
        _attacker([("iam:UpdateAssumeRolePolicy", "*")]),
        roles=(_admin_role(), _plain_role()),
    )
    methods = _methods(listing)
    assert (_ADMIN_ROLE, "trust_rewrite") in methods
    assert (_PLAIN_ROLE, "update_assume_role_policy_any") in methods


def test_trap_update_assume_role_policy_non_existent_role():
    ghost_role = f"arn:aws:iam::{_ACCT}:role/ghost"
    listing = _listing(
        _attacker([("iam:UpdateAssumeRolePolicy", ghost_role)]),
        roles=(_admin_role(),),
    )
    assert "update_assume_role_policy_any" not in {m for _t, m in _methods(listing)}


# ====================== Refactor-safety test ======================


def test_refactor_safety_non_admin_method_fires_without_any_admin():
    # No admin user/role in the listing — admin_arns is empty.
    # Method 7 (create_access_key_on_other) must still fire.
    listing = IdentityListing(
        users=(
            _attacker([("iam:CreateAccessKey", _BOB)]),
            _bob(),
        ),
        roles=(),
        groups=(),
    )
    edges = _escalation_grants(listing)
    assert any(
        p == _ATTACKER and t == _BOB and m == "create_access_key_on_other" for p, t, m, _v in edges
    ), "non-admin escalation method must fire even when admin_arns is empty"


# ====================== Moto pipeline test ======================


@pytest.mark.asyncio
async def test_moto_pipeline_create_access_key_emits_can_escalate_to(tmp_path: Path) -> None:
    """End-to-end: attacker with iam:CreateAccessKey on bob → CAN_ESCALATE_TO edge in the graph."""
    import json

    import boto3
    from charter.contract import BudgetSpec, ExecutionContract
    from charter.memory.graph_types import EdgeType, NodeCategory
    from fleet_testkit import in_memory_semantic_store
    from identity.agent import run
    from moto import mock_aws

    _ADMIN_DOC = (
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'
    )
    # Use "*" scope so it resolves correctly regardless of the moto account id (123456789012).
    _ATTACKER_POLICY = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "iam:CreateAccessKey",
                    "Resource": "*",
                }
            ],
        }
    )

    def _contract(path: Path) -> ExecutionContract:
        return ExecutionContract(
            schema_version="0.1",
            delegation_id="01J7M3X9Z1K8RPVQNH2T8ABCDE",
            source_agent="supervisor",
            target_agent="identity",
            customer_id="cust_cycle7",
            task="Cycle7 privesc deepening pipeline test",
            required_outputs=["findings.json", "summary.md"],
            budget=BudgetSpec(
                llm_calls=5,
                tokens=10_000,
                wall_clock_sec=60.0,
                cloud_api_calls=500,
                mb_written=10,
            ),
            permitted_tools=[
                "aws_iam_list_identities",
                "aws_iam_simulate_principal_policy",
                "aws_access_analyzer_findings",
            ],
            completion_condition="findings.json AND summary.md exist",
            escalation_rules=[],
            workspace=str(path / "ws"),
            persistent_root=str(path / "p"),
            created_at=datetime.now(UTC),
            expires_at=datetime.now(UTC) + timedelta(minutes=5),
        )

    async with in_memory_semantic_store() as store:
        with mock_aws():
            iam = boto3.client("iam", region_name="us-east-1")
            # Create a realistic account: admin user + bob + attacker
            admin_pol = iam.create_policy(
                PolicyName="AdministratorAccess", PolicyDocument=_ADMIN_DOC
            )["Policy"]["Arn"]
            iam.create_user(UserName="alice")
            iam.attach_user_policy(UserName="alice", PolicyArn=admin_pol)
            iam.create_user(UserName="bob")
            atk_pol = iam.create_policy(
                PolicyName="AttackerCreateKey", PolicyDocument=_ATTACKER_POLICY
            )["Policy"]["Arn"]
            iam.create_user(UserName="attacker")
            iam.attach_user_policy(UserName="attacker", PolicyArn=atk_pol)

            report = await run(_contract(tmp_path), semantic_store=store)

        # The run should succeed
        assert report.total >= 1

        # Confirm a CAN_ESCALATE_TO edge from attacker to bob exists in the graph
        all_idents = await store.list_entities_by_type(
            tenant_id="cust_cycle7", entity_type=NodeCategory.IDENTITY.value
        )
        arn_to_id: dict[str, str] = {e.external_id: e.entity_id for e in all_idents}

        attacker_arn = next((a for a in arn_to_id if "attacker" in a and ":user/" in a), None)
        bob_arn = next((a for a in arn_to_id if "bob" in a and ":user/" in a), None)
        assert attacker_arn is not None, "attacker identity not found in graph"
        assert bob_arn is not None, "bob identity not found in graph"

        attacker_id = arn_to_id[attacker_arn]
        bob_id = arn_to_id[bob_arn]

        relationships = await store.get_relationships_from(
            tenant_id="cust_cycle7",
            src_entity_id=attacker_id,
            edge_types=(EdgeType.CAN_ESCALATE_TO.value,),
        )
        assert any(r.dst_entity_id == bob_id for r in relationships), (
            "CAN_ESCALATE_TO edge from attacker to bob must exist"
        )


# ====================== Data-path e2e test ======================


@pytest.mark.asyncio
async def test_data_path_create_access_key_find_escalation_method_to_data() -> None:
    """attacker --create_access_key_on_other--> bob --HAS_ACCESS_TO--> bucket --EXPOSES_DATA-->
    data → find_escalation_method_to_data returns a hit with method='create_access_key_on_other'.
    """
    from charter.memory.graph_types import EdgeType, NodeCategory
    from fleet_testkit import in_memory_semantic_store
    from identity.kg_writer import KnowledgeGraphWriter as IdentityKgWriter
    from meta_harness.kg_query import KgQuery

    _T = "tenant-cycle7-data"
    _ATK = "arn:aws:iam::111122223333:user/attacker"
    _BOB_ARN = "arn:aws:iam::111122223333:user/bob"

    async with in_memory_semantic_store() as store:
        # 1) Write the escalation edge attacker → bob (non-admin target).
        await IdentityKgWriter(store, _T).record_escalation_grants(
            [(_ATK, _BOB_ARN, "create_access_key_on_other", "iam:CreateAccessKey")]
        )

        # 2) Find node IDs for bob.
        all_idents = await store.list_entities_by_type(
            tenant_id=_T, entity_type=NodeCategory.IDENTITY.value
        )
        bob_id = next(e.entity_id for e in all_idents if e.external_id == _BOB_ARN)

        # 3) Attach data to bob: bob --HAS_ACCESS_TO--> bucket --EXPOSES_DATA--> data.
        bucket = await store.upsert_entity(
            tenant_id=_T,
            entity_type=NodeCategory.CLOUD_RESOURCE.value,
            external_id="arn:aws:s3:::crown-bucket",
            properties={},
        )
        data = await store.upsert_entity(
            tenant_id=_T,
            entity_type=NodeCategory.DATA_CLASSIFICATION.value,
            external_id="arn:aws:s3:::crown-bucket/pii",
            properties={"data_type": "pii"},
        )
        await store.add_relationship(
            tenant_id=_T,
            src_entity_id=bob_id,
            dst_entity_id=bucket,
            relationship_type=EdgeType.HAS_ACCESS_TO.value,
            properties={},
        )
        await store.add_relationship(
            tenant_id=_T,
            src_entity_id=bucket,
            dst_entity_id=data,
            relationship_type=EdgeType.EXPOSES_DATA.value,
            properties={},
        )

        # 4) The named detector must surface the path.
        kq = KgQuery(store, _T)
        hits = await kq.find_escalation_method_to_data()
        assert hits, "find_escalation_method_to_data must surface the non-admin data path"
        # There should be a hit with method == create_access_key_on_other.
        assert any(h.method == "create_access_key_on_other" for h in hits), (
            f"expected create_access_key_on_other in hits, got: {[h.method for h in hits]}"
        )
        hit = next(h for h in hits if h.method == "create_access_key_on_other")
        assert hit.data_type == "pii"
