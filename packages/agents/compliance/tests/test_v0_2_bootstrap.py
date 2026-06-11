"""compliance v0.2 — bootstrap smoke tests (Milestone 1, Task 1).

The version-extension eligibility guards (ADR-010): the v0.2 bump must not perturb the
v0.1 contracts. They assert the version moved to 0.2.0 and that the OCSF 2003 wire shape
+ the 10 offline eval cases are byte-stable — the "no breaking changes to the prior
version's contracts" invariant, checked at bootstrap before any CIS-family / PASS-attestation
surface is added.

Q7 verification: compliance emits OCSF **class_uid 2003** (Compliance Finding) — the same
wire shape as F.3 + D.5 + k8s-posture (compliance is the **4th** 2003 emitter). Confirmed
against schemas + pinned (WI-C5).
"""

from __future__ import annotations

from pathlib import Path

import compliance
from compliance import schemas
from eval_framework.cases import load_cases

_CASES_DIR = Path(__file__).resolve().parents[1] / "eval" / "cases"


def test_version_bumped_to_v0_2() -> None:
    """Package version is 0.2.0 (the bootstrap's reason for existing)."""
    assert compliance.__version__ == "0.2.0"


def test_core_modules_still_import() -> None:
    """v0.2 import surface is intact — driver, CLI, schemas, aggregator, scorer, summarizer."""
    import compliance.agent
    import compliance.aggregator
    import compliance.cli
    import compliance.schemas
    import compliance.scorer
    import compliance.summarizer  # noqa: F401


def test_agent_run_is_callable() -> None:
    """The agent entry point is still callable after the bump."""
    from compliance.agent import run

    assert callable(run)


def test_ocsf_class_uid_is_2003() -> None:
    """Q7 / WI-C5: compliance emits OCSF Compliance Finding class_uid 2003 (4th emitter)."""
    assert schemas.OCSF_CLASS_UID == 2003
    assert schemas.OCSF_CLASS_NAME == "Compliance Finding"


def test_ocsf_envelope_constants_unchanged() -> None:
    """The rest of the OCSF envelope is byte-stable vs v0.1."""
    assert schemas.OCSF_VERSION == "1.3.0"
    assert schemas.OCSF_CATEGORY_UID == 2
    # The FAIL status the v0.1 path already emits; PASS attestation (Task 6) is additive.
    assert schemas.OCSF_COMPLIANCE_FAILED_STATUS_ID == 2


def test_ten_offline_eval_cases_still_load() -> None:
    """The 10 offline eval cases still load — no regression from the bump (these remain the
    deterministic gate; the CIS-family + live consumption lanes are added later)."""
    assert len(load_cases(_CASES_DIR)) == 10


def test_offline_eval_case_filenames_byte_stable() -> None:
    """The 10 case filenames are exactly the v0.1 set — guards against an accidental
    case add/drop during the version bump."""
    names = sorted(p.name for p in _CASES_DIR.glob("*.yaml"))
    assert names == [
        "001_clean_no_sources.yaml",
        "002_single_cis_iam_fail.yaml",
        "003_multi_source_rollup.yaml",
        "004_level_1_pinning.yaml",
        "005_partial_workspace_presence.yaml",
        "006_no_source_workspaces.yaml",
        "007_malformed_source_tolerated.yaml",
        "008_cis_attribution_in_output.yaml",
        "009_severity_canonicalization.yaml",
        "010_multi_control_from_one_finding.yaml",
    ]
