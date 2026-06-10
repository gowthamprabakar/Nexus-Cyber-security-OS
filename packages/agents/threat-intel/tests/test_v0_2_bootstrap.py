"""D.8 Threat Intel v0.2 — bootstrap smoke tests (Milestone 1, Task 1).

The version-extension eligibility guards (ADR-010): the v0.2 bump must not perturb
the v0.1 contracts. They assert the version moved to 0.2.0 and that the OCSF 2004
wire shape + the 10 offline eval cases are byte-stable — the "no breaking changes to
the prior version's contracts" invariant, checked at bootstrap before any live
continuous-ingestion surface is added.
"""

from __future__ import annotations

from pathlib import Path

import threat_intel
from eval_framework.cases import load_cases
from threat_intel import schemas

_CASES_DIR = Path(__file__).resolve().parents[1] / "eval" / "cases"


def test_version_bumped_to_v0_2() -> None:
    """Package version is 0.2.0 (the bootstrap's reason for existing)."""
    assert threat_intel.__version__ == "0.2.0"


def test_core_modules_still_import() -> None:
    """v0.2 import surface is intact — driver, CLI, schemas, eval runner, scorer."""
    import threat_intel.agent
    import threat_intel.cli
    import threat_intel.eval_runner
    import threat_intel.schemas
    import threat_intel.scorer
    import threat_intel.summarizer  # noqa: F401


def test_agent_run_is_callable() -> None:
    """The agent entry point is still callable after the bump."""
    from threat_intel.agent import run

    assert callable(run)


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
    remain the deterministic gate; the live continuous lanes are added later)."""
    assert len(load_cases(_CASES_DIR)) == 10


def test_offline_eval_case_filenames_byte_stable() -> None:
    """The 10 case filenames are exactly the v0.1 set — guards against an accidental
    case add/drop during the version bump."""
    names = sorted(p.name for p in _CASES_DIR.glob("*.yaml"))
    assert names == [
        "001_empty_path.yaml",
        "002_cve_kev_match_emits_critical.yaml",
        "003_ioc_match_network_via_cve_id.yaml",
        "004_combined_cve_kev_plus_ioc_net.yaml",
        "005_d1_cve_not_in_kev_emits_nothing.yaml",
        "006_kev_without_d1_workspace.yaml",
        "007_nvd_without_d4_workspace.yaml",
        "008_partial_workspace_presence.yaml",
        "009_scorer_canonicalises_kev_to_critical.yaml",
        "010_multiple_cves_in_one_signature.yaml",
    ]
