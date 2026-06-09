"""D.5 Multi-Cloud Posture v0.2 — bootstrap smoke tests (Milestone 1, Task 1).

The version-extension eligibility guards (ADR-010): the v0.2 bump must not
perturb the v0.1 contracts. They assert the version moved to 0.2.0 and that the
OCSF 2003 wire shape + the 10 offline eval cases are byte-stable — the "no
breaking changes to the prior version's contracts" invariant, checked at
bootstrap before any live Azure/GCP surface is added.
"""

from __future__ import annotations

from pathlib import Path

import multi_cloud_posture
from eval_framework.cases import load_cases
from multi_cloud_posture import schemas

_CASES_DIR = Path(__file__).resolve().parents[1] / "eval" / "cases"


def test_version_bumped_to_v0_2() -> None:
    """Package version is 0.2.0 (the bootstrap's reason for existing)."""
    assert multi_cloud_posture.__version__ == "0.2.0"


def test_core_modules_still_import() -> None:
    """v0.2 import surface is intact — driver, CLI, schemas, eval runner,
    both normalizers."""
    import multi_cloud_posture.agent
    import multi_cloud_posture.cli
    import multi_cloud_posture.eval_runner
    import multi_cloud_posture.normalizers.azure
    import multi_cloud_posture.normalizers.gcp
    import multi_cloud_posture.schemas  # noqa: F401


def test_ocsf_class_uid_unchanged() -> None:
    """OCSF Compliance Finding class_uid stays 2003 — the shared wire contract
    re-exported from cloud_posture (ADR-010 invariant #3)."""
    assert schemas.OCSF_CLASS_UID == 2003
    assert schemas.OCSF_CLASS_NAME == "Compliance Finding"


def test_ocsf_envelope_constants_unchanged() -> None:
    """The rest of the OCSF envelope is byte-stable vs v0.1."""
    assert schemas.OCSF_VERSION == "1.3.0"
    assert schemas.OCSF_CATEGORY_UID == 2
    assert schemas.OCSF_CATEGORY_NAME == "Findings"


def test_ten_offline_eval_cases_still_load() -> None:
    """The 10 offline eval cases still load — no regression from the bump
    (these remain the deterministic gate; the live lanes are added later)."""
    assert len(load_cases(_CASES_DIR)) == 10


def test_offline_eval_case_filenames_byte_stable() -> None:
    """The 10 case filenames are exactly the v0.1 set — guards against an
    accidental case add/drop during the version bump."""
    names = sorted(p.name for p in _CASES_DIR.glob("*.yaml"))
    assert names == [
        "001_clean_multicloud.yaml",
        "002_azure_defender_high.yaml",
        "003_azure_iam_overpermissive.yaml",
        "004_azure_compute_filtered.yaml",
        "005_gcp_scc_critical.yaml",
        "006_gcp_iam_public_impersonation.yaml",
        "007_gcp_scc_inactive_dropped.yaml",
        "008_mixed_clouds.yaml",
        "009_defender_healthy_dropped.yaml",
        "010_gcp_iam_editor_medium.yaml",
    ]


def test_eval_runner_agent_name_stable() -> None:
    """The eval-runner registration name is unchanged (entry-point stability)."""
    from multi_cloud_posture.eval_runner import MultiCloudPostureEvalRunner

    assert MultiCloudPostureEvalRunner().agent_name == "multi_cloud_posture"


def test_build_finding_public_api_present() -> None:
    """The shared finding builder re-exported from cloud_posture is intact."""
    assert hasattr(schemas, "build_finding")
    assert callable(schemas.build_finding)
