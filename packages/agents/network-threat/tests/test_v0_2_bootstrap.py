"""D.4 Network Threat v0.2 — bootstrap smoke tests (Milestone 1, Task 1).

The version-extension eligibility guards (ADR-010): the v0.2 bump must not perturb the
v0.1 contracts. They assert the version moved to 0.2.0 and that the OCSF 2004 wire shape
+ the 10 offline eval cases are byte-stable — the "no breaking changes to the prior
version's contracts" invariant, checked at bootstrap before any live real-time
network-event surface is added.

Q7 verification: D.4 emits OCSF **class_uid 2004** (Detection Finding) — the same wire
shape as D.2 / D.3 / D.8 (4 emitters now). Confirmed against schemas + pinned (WI-N5).
"""

from __future__ import annotations

from pathlib import Path

import network_threat
from eval_framework.cases import load_cases
from network_threat import schemas

_CASES_DIR = Path(__file__).resolve().parents[1] / "eval" / "cases"


def test_version_bumped_to_v0_2() -> None:
    """Package version is 0.2.0 (the bootstrap's reason for existing)."""
    assert network_threat.__version__ == "0.2.0"


def test_core_modules_still_import() -> None:
    """v0.2 import surface is intact — driver, CLI, schemas, normalizer, summarizer."""
    import network_threat.agent
    import network_threat.cli
    import network_threat.enrichment
    import network_threat.schemas
    import network_threat.summarizer  # noqa: F401


def test_agent_run_is_callable() -> None:
    """The agent entry point is still callable after the bump."""
    from network_threat.agent import run

    assert callable(run)


def test_ocsf_class_uid_is_2004() -> None:
    """Q7 / WI-N5: D.4 emits OCSF Detection Finding class_uid 2004."""
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
        "001_clean_network.yaml",
        "002_port_scan_at_threshold.yaml",
        "003_beacon_low_variance.yaml",
        "004_beacon_high_variance.yaml",
        "005_dga_high_entropy.yaml",
        "006_dga_low_entropy_skipped.yaml",
        "007_suricata_alert_only.yaml",
        "008_intel_uplift_tor_exit.yaml",
        "009_three_feed_merge.yaml",
        "010_allowlisted_cloudfront_suppressed.yaml",
    ]
