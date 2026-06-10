"""D.3 Runtime Threat v0.2 — bootstrap smoke tests (Milestone 1, Task 1).

The version-extension eligibility guards (ADR-010): the v0.2 bump must not perturb the
v0.1 contracts. They assert the version moved to 0.2.0 and that the OCSF 2004 wire shape
+ the 10 offline eval cases are byte-stable — the "no breaking changes to the prior
version's contracts" invariant, checked at bootstrap before any live real-time
event-stream surface is added.

Q7 verification: D.3 emits OCSF **class_uid 2004** (Detection Finding) — the directive's
"likely 2005" guess was incorrect; confirmed against schemas here and pinned (WI-R5).
"""

from __future__ import annotations

from pathlib import Path

import runtime_threat
from eval_framework.cases import load_cases
from runtime_threat import schemas

_CASES_DIR = Path(__file__).resolve().parents[1] / "eval" / "cases"


def test_version_bumped_to_v0_2() -> None:
    """Package version is 0.2.0 (the bootstrap's reason for existing)."""
    assert runtime_threat.__version__ == "0.2.0"


def test_core_modules_still_import() -> None:
    """v0.2 import surface is intact — driver, CLI, schemas, normalizer, summarizer."""
    import runtime_threat.agent
    import runtime_threat.cli
    import runtime_threat.normalizer
    import runtime_threat.schemas
    import runtime_threat.summarizer  # noqa: F401


def test_agent_run_is_callable() -> None:
    """The agent entry point is still callable after the bump."""
    from runtime_threat.agent import run

    assert callable(run)


def test_ocsf_class_uid_is_2004_not_2005() -> None:
    """Q7 / WI-R5: D.3 emits OCSF Detection Finding class_uid 2004 (not 2005)."""
    assert schemas.OCSF_CLASS_UID == 2004
    assert schemas.OCSF_CLASS_NAME == "Detection Finding"


def test_ocsf_envelope_constants_unchanged() -> None:
    """The rest of the OCSF envelope is byte-stable vs v0.1."""
    assert schemas.OCSF_VERSION == "1.3.0"
    assert schemas.OCSF_CATEGORY_UID == 2


def test_ten_offline_eval_cases_still_load() -> None:
    """The 10 offline eval cases still load — no regression from the bump (these remain
    the deterministic gate; the live real-time lanes are added later)."""
    assert len(load_cases(_CASES_DIR)) == 10


def test_offline_eval_case_filenames_byte_stable() -> None:
    """The 10 case filenames are exactly the v0.1 set — guards against an accidental
    case add/drop during the version bump."""
    names = sorted(p.name for p in _CASES_DIR.glob("*.yaml"))
    assert names == [
        "001_clean_cluster.yaml",
        "002_suspicious_shell_spawn.yaml",
        "003_credential_file_read.yaml",
        "004_outbound_to_tor_exit.yaml",
        "005_kernel_module_loaded.yaml",
        "006_tracee_only_severe.yaml",
        "007_tracee_low_signal.yaml",
        "008_osquery_orphan_process.yaml",
        "009_multi_feed_overlap.yaml",
        "010_mixed_findings.yaml",
    ]
