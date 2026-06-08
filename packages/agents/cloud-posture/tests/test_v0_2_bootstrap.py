"""F.3 Cloud Posture v0.2 — bootstrap smoke tests (Milestone 1, Task 1).

These are the version-extension eligibility guards (ADR-010): the v0.2 bump
must not perturb the v0.1 contracts. They assert the version moved to 0.2.0 and
that the OCSF 2003 wire shape + the 10 offline eval cases are byte-stable — the
"no breaking changes to the prior version's contracts" invariant, checked at
bootstrap before any live-AWS surface is added.
"""

from __future__ import annotations

from pathlib import Path

import cloud_posture
from cloud_posture import schemas
from eval_framework.cases import load_cases

_CASES_DIR = Path(__file__).resolve().parents[1] / "eval" / "cases"


def test_version_bumped_to_v0_2() -> None:
    """Package version is 0.2.0 (the bootstrap's reason for existing)."""
    assert cloud_posture.__version__ == "0.2.0"


def test_core_modules_still_import() -> None:
    """v0.2 import surface is intact — driver, CLI, schemas, eval runner."""
    import cloud_posture.agent
    import cloud_posture.cli
    import cloud_posture.eval_runner
    import cloud_posture.schemas  # noqa: F401


def test_ocsf_class_uid_unchanged() -> None:
    """OCSF Compliance Finding class_uid stays 2003 — the shared wire contract
    five agents re-export (ADR-010 invariant #3)."""
    assert schemas.OCSF_CLASS_UID == 2003
    assert schemas.OCSF_CLASS_NAME == "Compliance Finding"


def test_ocsf_envelope_constants_unchanged() -> None:
    """The rest of the OCSF envelope is byte-stable vs v0.1."""
    assert schemas.OCSF_VERSION == "1.3.0"
    assert schemas.OCSF_CATEGORY_UID == 2
    assert schemas.OCSF_CATEGORY_NAME == "Findings"


def test_ten_offline_eval_cases_still_load() -> None:
    """The 10 offline eval cases still load — no regression from the bump
    (these remain the deterministic gate; the live lane is added later)."""
    cases = load_cases(_CASES_DIR)
    assert len(cases) == 10


def test_offline_eval_case_filenames_byte_stable() -> None:
    """The 10 case filenames are exactly the v0.1 set — guards against an
    accidental case add/drop during the version bump."""
    names = sorted(p.name for p in _CASES_DIR.glob("*.yaml"))
    assert names == [
        "001_public_s3_bucket.yaml",
        "002_iam_user_admin_no_mfa.yaml",
        "003_unencrypted_rds.yaml",
        "004_open_security_group.yaml",
        "005_no_cloudtrail.yaml",
        "006_root_account_used.yaml",
        "007_kms_key_no_rotation.yaml",
        "008_overprivileged_role.yaml",
        "009_public_rds_snapshot.yaml",
        "010_unencrypted_ebs_volume.yaml",
    ]


def test_eval_runner_agent_name_stable() -> None:
    """The eval-runner registration name is unchanged (entry-point stability)."""
    from cloud_posture.eval_runner import CloudPostureEvalRunner

    assert CloudPostureEvalRunner().agent_name == "cloud_posture"


def test_build_finding_public_api_present() -> None:
    """The shared finding builder re-exported by downstream agents is intact."""
    assert hasattr(schemas, "build_finding")
    assert callable(schemas.build_finding)
