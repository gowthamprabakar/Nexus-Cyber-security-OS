"""audit v0.2 — bootstrap smoke tests (Milestone 1, Task 1).

The version-extension eligibility guards (ADR-010): the v0.2 bump must not perturb the v0.1
contracts. They assert the version moved to 0.2.0, that the OCSF 6003 wire shape + the 10
offline eval cases are byte-stable, and that **F.6's single tool-proxy deviation is preserved**
(WI-F10) — checked at bootstrap before any aggregation / Merkle / tamper surface is added.

Q7 verification: audit emits OCSF **class_uid 6003** (API Activity) — the **first 6003 emitter**
in the fleet (alongside 5x2003 + 4x2004 = 10 OCSF emitters total). Chain hashes ride in the
unmapped slot, byte-identical (WI-F5).
"""

from __future__ import annotations

from pathlib import Path

import audit
from audit import schemas
from eval_framework.cases import load_cases

_CASES_DIR = Path(__file__).resolve().parents[1] / "eval" / "cases"


def test_version_bumped_to_v0_2() -> None:
    """Package version is 0.2.0 (the bootstrap's reason for existing)."""
    assert audit.__version__ == "0.2.0"


def test_core_modules_still_import() -> None:
    """v0.2 import surface is intact — driver, CLI, schemas, chain, store, summarizer."""
    import audit.agent
    import audit.chain
    import audit.cli
    import audit.schemas
    import audit.store
    import audit.summarizer  # noqa: F401


def test_agent_run_is_callable() -> None:
    """The agent entry point is still callable after the bump."""
    from audit.agent import run

    assert callable(run)


def test_ocsf_class_uid_is_6003() -> None:
    """Q7 / WI-F5: audit emits OCSF API Activity class_uid 6003 (first 6003 emitter)."""
    assert schemas.OCSF_CLASS_UID == 6003
    assert schemas.OCSF_CLASS_NAME == "API Activity"


def test_ocsf_envelope_constants_unchanged() -> None:
    """The rest of the OCSF envelope is byte-stable vs v0.1."""
    assert schemas.OCSF_VERSION == "1.3.0"
    assert schemas.OCSF_CATEGORY_UID == 6


def test_f6_tool_proxy_deviation_preserved() -> None:
    """WI-F10: F.6's BY_DESIGN_EXEMPT is the single standing tool-proxy exemption; v0.2 must
    NOT add new ones. Read the charter guard source + assert the set is exactly {'audit'}."""
    guard = (
        Path(__file__).resolve().parents[3]  # packages/
        / "charter"
        / "tests"
        / "test_tool_import_guard.py"
    )
    assert guard.is_file(), f"tool-import guard not found at {guard}"
    text = guard.read_text(encoding="utf-8")
    assert 'BY_DESIGN_EXEMPT = {"audit"}' in text  # single institutional exemption (WI-F10)


def test_ten_offline_eval_cases_still_load() -> None:
    """The 10 offline eval cases still load — no regression from the bump."""
    assert len(load_cases(_CASES_DIR)) == 10


def test_offline_eval_case_filenames_byte_stable() -> None:
    """The 10 case filenames are exactly the v0.1 set — guards against an accidental add/drop."""
    names = sorted(p.name for p in _CASES_DIR.glob("*.yaml"))
    assert names == [
        "001_empty_corpus.yaml",
        "002_clean_chain_ingest.yaml",
        "003_tampered_chain_detected.yaml",
        "004_per_action_query.yaml",
        "005_tenant_isolation.yaml",
        "006_cross_source_merge.yaml",
        "007_time_range_filter.yaml",
        "008_agent_id_filter.yaml",
        "009_correlation_id_walk.yaml",
        "010_nl_query_translation.yaml",
    ]
