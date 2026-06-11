"""D.6 K8s Posture v0.2 — bootstrap smoke tests (Milestone 1, Task 1).

The version-extension eligibility guards (ADR-010): the v0.2 bump must not perturb the
v0.1 contracts. They assert the version moved to 0.2.0 and that the OCSF 2003 wire shape
+ the 10 offline eval cases are byte-stable — the "no breaking changes to the prior
version's contracts" invariant, checked at bootstrap before any live cluster surface is
added.

Q7 verification: D.6 emits OCSF **class_uid 2003** (Compliance Finding) — the same wire
shape as F.3 + D.5 (3 emitters now). Confirmed against schemas + pinned (WI-K5).
"""

from __future__ import annotations

from pathlib import Path

import k8s_posture
from eval_framework.cases import load_cases
from k8s_posture import schemas

_CASES_DIR = Path(__file__).resolve().parents[1] / "eval" / "cases"


def test_version_bumped_to_v0_2() -> None:
    """Package version is 0.2.0 (the bootstrap's reason for existing)."""
    assert k8s_posture.__version__ == "0.2.0"


def test_core_modules_still_import() -> None:
    """v0.2 import surface is intact — driver, CLI, schemas, dedup, summarizer."""
    import k8s_posture.agent
    import k8s_posture.cli
    import k8s_posture.dedup
    import k8s_posture.schemas
    import k8s_posture.summarizer  # noqa: F401


def test_agent_run_is_callable() -> None:
    """The agent entry point is still callable after the bump."""
    from k8s_posture.agent import run

    assert callable(run)


def test_ocsf_class_uid_is_2003() -> None:
    """Q7 / WI-K5: D.6 emits OCSF Compliance Finding class_uid 2003."""
    assert schemas.OCSF_CLASS_UID == 2003
    assert schemas.OCSF_CLASS_NAME == "Compliance Finding"


def test_ocsf_envelope_constants_unchanged() -> None:
    """The rest of the OCSF envelope is byte-stable vs v0.1."""
    assert schemas.OCSF_VERSION == "1.3.0"
    assert schemas.OCSF_CATEGORY_UID == 2


def test_ten_offline_eval_cases_still_load() -> None:
    """The 10 offline eval cases still load — no regression from the bump (these remain
    the deterministic gate; the live cluster lanes are added later)."""
    assert len(load_cases(_CASES_DIR)) == 10


def test_offline_eval_case_filenames_byte_stable() -> None:
    """The 10 case filenames are exactly the v0.1 set — guards against an accidental
    case add/drop during the version bump."""
    names = sorted(p.name for p in _CASES_DIR.glob("*.yaml"))
    assert names == [
        "001_clean_cluster.yaml",
        "002_kube_bench_fail_high.yaml",
        "003_kube_bench_critical_marker.yaml",
        "004_polaris_danger.yaml",
        "005_manifest_root_container.yaml",
        "006_manifest_privileged.yaml",
        "007_manifest_missing_limits_medium.yaml",
        "008_dedup_overlap.yaml",
        "009_large_namespace_rollup.yaml",
        "010_three_feed_merge.yaml",
    ]
