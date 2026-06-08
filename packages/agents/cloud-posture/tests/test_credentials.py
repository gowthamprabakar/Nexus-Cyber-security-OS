"""F.3 v0.2 Task 2 — CredentialResolver seam + --aws-profile wiring tests."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import cloud_posture.credentials as creds_mod
from click.testing import CliRunner
from cloud_posture import cli
from cloud_posture.credentials import CredentialResolver

# ---------------------- resolver: session construction ----------------------


def test_default_chain_when_no_profile() -> None:
    """No profile → boto3.Session() with no args (preserves v0.1 default chain)."""
    with patch.object(creds_mod.boto3, "Session") as session_cls:
        CredentialResolver().resolve_session()
        session_cls.assert_called_once_with()


def test_named_profile_builds_session_with_profile_name() -> None:
    with patch.object(creds_mod.boto3, "Session") as session_cls:
        CredentialResolver(profile="prod").resolve_session()
        session_cls.assert_called_once_with(profile_name="prod")


def test_profile_property_returns_named_profile() -> None:
    assert CredentialResolver(profile="dev").profile == "dev"


def test_profile_property_is_none_by_default() -> None:
    assert CredentialResolver().profile is None


# ---------------------- resolver: client construction -----------------------


def test_client_global_service_omits_region() -> None:
    fake_session = MagicMock()
    with patch.object(creds_mod.boto3, "Session", return_value=fake_session):
        CredentialResolver().client("iam")
        fake_session.client.assert_called_once_with("iam")


def test_client_with_region_threads_region_name() -> None:
    fake_session = MagicMock()
    with patch.object(creds_mod.boto3, "Session", return_value=fake_session):
        CredentialResolver(profile="prod").client("s3", region="us-west-2")
        fake_session.client.assert_called_once_with("s3", region_name="us-west-2")


def test_client_uses_the_resolved_session() -> None:
    fake_session = MagicMock()
    with patch.object(CredentialResolver, "resolve_session", return_value=fake_session) as rs:
        CredentialResolver(profile="p").client("ec2")
        rs.assert_called_once_with()
        fake_session.client.assert_called_once_with("ec2")


# ---------------------- resolver: invariants --------------------------------


def test_resolvers_are_independent() -> None:
    a = CredentialResolver(profile="a")
    b = CredentialResolver()
    assert (a.profile, b.profile) == ("a", None)


def test_seam_lives_in_cloud_posture_not_charter() -> None:
    """ADR-007 Q7: establish the shape in-package; hoist to charter at #3 consumer."""
    assert CredentialResolver.__module__ == "cloud_posture.credentials"


def test_resolver_only_state_is_the_profile_name() -> None:
    """Secret-safety is structural: the resolver holds only the profile name —
    no secret key material is ever stored on it."""
    resolver = CredentialResolver(profile="prod")
    state = {slot: getattr(resolver, slot) for slot in CredentialResolver.__slots__}
    assert state == {"_profile": "prod"}


# ---------------------- CLI: --aws-profile wiring ---------------------------


def _fake_report() -> MagicMock:
    report = MagicMock()
    report.agent = "cloud_posture"
    report.agent_version = "0.2.0"
    report.customer_id = "cust"
    report.run_id = "run-1"
    report.total = 0
    report.count_by_severity.return_value = {}
    return report


def test_cli_run_threads_aws_profile() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        Path("contract.yaml").write_text("placeholder")
        with (
            patch.object(cli, "load_contract", return_value=MagicMock(workspace=Path("."))),
            patch.object(cli, "agent_run", new=AsyncMock(return_value=_fake_report())) as ar,
        ):
            result = runner.invoke(
                cli.main,
                ["run", "--contract", "contract.yaml", "--aws-profile", "prod"],
            )
        assert result.exit_code == 0, result.output
        assert ar.call_args.kwargs.get("aws_profile") == "prod"


def test_cli_run_default_profile_is_none() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        Path("contract.yaml").write_text("placeholder")
        with (
            patch.object(cli, "load_contract", return_value=MagicMock(workspace=Path("."))),
            patch.object(cli, "agent_run", new=AsyncMock(return_value=_fake_report())) as ar,
        ):
            result = runner.invoke(cli.main, ["run", "--contract", "contract.yaml"])
        assert result.exit_code == 0, result.output
        assert ar.call_args.kwargs.get("aws_profile") is None
