"""data-security v0.2 — bootstrap smoke tests (Milestone 1, Task 1).

The version-extension eligibility guards (ADR-010): the v0.2 bump must not perturb the v0.1
contracts. They assert the version moved to 0.2.0 and that the OCSF 2003 wire shape + the 10
offline eval cases are byte-stable — the "no breaking changes" invariant, checked at
bootstrap before any live multi-cloud / expanded-classifier surface is added.

Q7 verification: data-security emits OCSF **class_uid 2003** (Compliance Finding) — the same
wire shape as F.3 + D.5 + k8s-posture + compliance (data-security is the **5th** 2003
emitter). Confirmed against schemas + pinned (WI-S5).
"""

from __future__ import annotations

from pathlib import Path

import data_security
from data_security import schemas
from eval_framework.cases import load_cases

_CASES_DIR = Path(__file__).resolve().parents[1] / "eval" / "cases"


def test_version_bumped_to_v0_2() -> None:
    """Package version is 0.2.0 (the bootstrap's reason for existing)."""
    assert data_security.__version__ == "0.2.0"


def test_core_modules_still_import() -> None:
    """v0.2 import surface is intact — driver, CLI, schemas, correlate, scorer, summarizer."""
    import data_security.agent
    import data_security.cli
    import data_security.correlate
    import data_security.schemas
    import data_security.scorer
    import data_security.summarizer  # noqa: F401


def test_agent_run_is_callable() -> None:
    """The agent entry point is still callable after the bump."""
    from data_security.agent import run

    assert callable(run)


def test_ocsf_class_uid_is_2003() -> None:
    """Q7 / WI-S5: data-security emits OCSF Compliance Finding class_uid 2003 (5th emitter)."""
    assert schemas.OCSF_CLASS_UID == 2003
    assert schemas.OCSF_CLASS_NAME == "Compliance Finding"


def test_ocsf_envelope_constants_unchanged() -> None:
    """The rest of the OCSF envelope is byte-stable vs v0.1."""
    assert schemas.OCSF_VERSION == "1.3.0"
    assert schemas.OCSF_CATEGORY_UID == 2


def test_ten_offline_eval_cases_still_load() -> None:
    """The 10 offline eval cases still load — no regression from the bump (these remain the
    deterministic gate; the live multi-cloud lanes are added later)."""
    assert len(load_cases(_CASES_DIR)) == 10


def test_offline_eval_case_filenames_byte_stable() -> None:
    """The 10 case filenames are exactly the v0.1 set — guards against an accidental add/drop."""
    names = sorted(p.name for p in _CASES_DIR.glob("*.yaml"))
    assert names == [
        "001_clean_account.yaml",
        "002_public_bucket_no_pii.yaml",
        "003_public_bucket_with_pii_critical.yaml",
        "004_unencrypted_with_pii.yaml",
        "005_sensitive_location_violation.yaml",
        "006_oversharing_iam_no_pii.yaml",
        "007_oversharing_iam_with_pii.yaml",
        "008_correlation_uplift_from_f3.yaml",
        "009_no_correlation_workspace_absent.yaml",
        "010_no_pii_leak_in_report.yaml",
    ]
