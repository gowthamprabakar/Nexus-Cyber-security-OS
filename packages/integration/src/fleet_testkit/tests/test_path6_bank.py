"""Path-6 (privileged K8s pod + vulnerable image) capability bank. KIND + TRIVY-GATED.

Applies real privileged/non-privileged pods to a throwaway namespace on the live kind cluster.
Skips where kind or trivy is absent — REAL where present.
"""

from pathlib import Path

import pytest

from fleet_testkit.bank_runner import kind_context, run_privileged_vuln_case
from fleet_testkit.capability import evaluate, load_test_case
from fleet_testkit.vuln_scan import trivy_available

_CTX = kind_context()
pytestmark = pytest.mark.skipif(
    _CTX is None or not trivy_available, reason="needs a kind context + trivy"
)

_BANK = Path(__file__).parent / "banks" / "path6_privileged_vuln"
_CASES = sorted(_BANK.glob("*.yaml"))


@pytest.mark.parametrize("case", _CASES, ids=lambda p: p.stem)
@pytest.mark.asyncio
async def test_case_meets_pass_criteria(case: Path) -> None:
    result = await run_privileged_vuln_case(case, context=_CTX or "")
    evaluate(result, load_test_case(case).pass_criteria)


@pytest.mark.asyncio
async def test_bank_aggregate_precision_recall() -> None:
    assert _CASES, "no path-6 bank cases found"
    tp = fp = fn = 0
    rows = []
    for case in _CASES:
        r = await run_privileged_vuln_case(case, context=_CTX or "")
        tp += r.true_positives
        fp += r.false_positives
        fn += r.false_negatives
        rows.append((r.test_case_id, r.precision, r.recall, r.false_positives))

    precision = 1.0 if tp + fp == 0 else tp / (tp + fp)
    recall = 1.0 if tp + fn == 0 else tp / (tp + fn)
    print("\n=== Path 6 (privileged K8s + vulnerable) capability bank ===")
    for tcid, p, rc, f in rows:
        print(f"  {tcid:38s} P={p:.2f} R={rc:.2f} FP={f}")
    print(f"  AGGREGATE  TP={tp} FP={fp} FN={fn}  precision={precision:.3f} recall={recall:.3f}")

    assert recall == 1.0, f"missed ground truth — recall {recall:.3f}"
    assert precision == 1.0, f"false positives present — precision {precision:.3f}"
    assert fp == 0
