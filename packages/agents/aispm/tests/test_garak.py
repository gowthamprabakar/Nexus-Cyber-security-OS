"""Tests for the Garak prompt-injection connector + detection rules (D.11 PR4)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from aispm.posture.prompt_injection import evaluate_prompt_injection
from aispm.schemas import Severity
from aispm.tools.garak import GarakProbeResult, results_from_entries, run_garak
from shared.fabric.envelope import NexusEnvelope

_NOW = datetime(2026, 6, 17, 12, 0, 0, tzinfo=UTC)


class _FakeGarakRunner:
    def __init__(self, entries: list[dict[str, Any]]) -> None:
        self._entries = entries

    async def probe(self, *, target: str) -> list[dict[str, Any]]:
        return self._entries


def _envelope() -> NexusEnvelope:
    return NexusEnvelope(
        correlation_id="c",
        tenant_id="cust_test",
        agent_id="aispm",
        nlah_version="0.1.0",
        model_pin="deterministic",
        charter_invocation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
    )


def test_results_from_entries_computes_failed() -> None:
    entries = [
        {
            "entry_type": "eval",
            "probe": "promptinject",
            "detector": "mitigation",
            "passed": 7,
            "total": 10,
        },
        {"entry_type": "config", "probe": "ignore"},  # non-eval skipped
        {"entry_type": "eval", "probe": "dan", "detector": "dan", "passed": 10, "total": 10},
    ]
    results = results_from_entries(entries)
    assert len(results) == 2
    pi = next(r for r in results if r.probe == "promptinject")
    assert pi.failed == 3 and pi.total == 10


@pytest.mark.asyncio
async def test_run_garak_with_injected_runner() -> None:
    runner = _FakeGarakRunner(
        [{"entry_type": "eval", "probe": "dan", "detector": "dan", "passed": 4, "total": 10}]
    )
    results = await run_garak(target="bedrock:model", runner=runner)
    assert results[0].probe == "dan" and results[0].failed == 6


def test_only_failed_probes_become_detections() -> None:
    results = [
        GarakProbeResult(probe="promptinject", detector="m", failed=6, total=10),  # 0.6 → critical
        GarakProbeResult(probe="dan", detector="d", failed=0, total=10),  # clean → no finding
        GarakProbeResult(probe="latentinjection", detector="l", failed=1, total=10),  # 0.1 → medium
    ]
    findings = evaluate_prompt_injection(
        results,
        provider="bedrock",
        account_id="111122223333",
        target="anthropic.claude",
        envelope=_envelope(),
        detected_at=_NOW,
    )
    assert len(findings) == 2  # the clean probe produced nothing
    assert all(f.to_dict()["class_uid"] == 2004 for f in findings)
    by_sev = {f.severity for f in findings}
    assert Severity.CRITICAL in by_sev and Severity.MEDIUM in by_sev
    assert all(f.finding_type.startswith("aispm_promptinjection_") for f in findings)


def test_clean_run_yields_no_detections() -> None:
    results = [GarakProbeResult(probe="dan", detector="d", failed=0, total=10)]
    assert (
        evaluate_prompt_injection(
            results,
            provider="bedrock",
            account_id="111122223333",
            target="m",
            envelope=_envelope(),
            detected_at=_NOW,
        )
        == []
    )
