"""D.2 Identity v0.2 — bootstrap smoke tests (Milestone 1, Task 1).

The version-extension eligibility guards (ADR-010): the v0.2 bump must not perturb
the v0.1 contracts. They assert the version moved to 0.2.0 and that the OCSF 2004
wire shape + the 10 offline eval cases are byte-stable — the "no breaking changes to
the prior version's contracts" invariant, checked at bootstrap **before** the
SAFETY-CRITICAL charter hoist (Tasks 2-4) or any live multi-cloud surface.
"""

from __future__ import annotations

from pathlib import Path

import identity
from eval_framework.cases import load_cases
from identity import schemas

_CASES_DIR = Path(__file__).resolve().parents[1] / "eval" / "cases"


def test_version_bumped_to_v0_2() -> None:
    """Package version is 0.2.0 (the bootstrap's reason for existing)."""
    assert identity.__version__ == "0.2.0"


def test_core_modules_still_import() -> None:
    """v0.2 import surface is intact — driver, CLI, schemas, eval runner, normalizer."""
    import identity.agent
    import identity.cli
    import identity.eval_runner
    import identity.normalizer
    import identity.schemas  # noqa: F401


def test_ocsf_class_uid_unchanged() -> None:
    """OCSF Detection Finding class_uid stays 2004 — the wire contract."""
    assert schemas.OCSF_CLASS_UID == 2004
    assert schemas.OCSF_CLASS_NAME == "Detection Finding"


def test_ocsf_envelope_constants_unchanged() -> None:
    """The rest of the OCSF envelope is byte-stable vs v0.1."""
    assert schemas.OCSF_VERSION == "1.3.0"
    assert schemas.OCSF_CATEGORY_UID == 2


def test_ten_offline_eval_cases_still_load() -> None:
    """The 10 offline eval cases still load — no regression from the bump (these
    remain the deterministic gate; live AWS/Azure lanes are added later)."""
    assert len(load_cases(_CASES_DIR)) == 10


def test_offline_eval_case_filenames_byte_stable() -> None:
    """The 10 case filenames are exactly the v0.1 set — guards against an
    accidental case add/drop during the version bump."""
    names = sorted(p.name for p in _CASES_DIR.glob("*.yaml"))
    assert names == [
        "001_clean_account.yaml",
        "002_admin_no_mfa.yaml",
        "003_dormant_admin_role.yaml",
        "004_public_bucket_access.yaml",
        "005_cross_account_role.yaml",
        "006_group_transitive_admin.yaml",
        "007_admin_with_mfa.yaml",
        "008_dormant_human_user.yaml",
        "009_multiple_dormant_roles.yaml",
        "010_mixed_findings.yaml",
    ]


def test_eval_runner_agent_name_stable() -> None:
    """The eval-runner registration name is unchanged (entry-point stability)."""
    from identity.eval_runner import IdentityEvalRunner

    assert IdentityEvalRunner().agent_name == "identity"


def test_build_finding_public_api_present() -> None:
    """The finding builder is intact."""
    assert hasattr(schemas, "build_finding")
    assert callable(schemas.build_finding)
