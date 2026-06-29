"""Path-3 (public-secret) capability bank — the first MEASURED vertical.

Per case: drive the real detector and assert it meets the case's precision/recall/FP thresholds.
Aggregate: print the measured precision/recall/FP across the whole bank (run with ``-s`` to see
the table). The bank is built so a correct detector aces it — a miss or false positive here is a
real defect, not a tuning knob.
"""

from pathlib import Path

import pytest

from fleet_testkit.bank_runner import run_public_secret_case
from fleet_testkit.capability import evaluate, load_test_case

_BANK = Path(__file__).parent / "banks" / "path3_public_secret"
_CASES = sorted(_BANK.glob("*.yaml"))


@pytest.mark.parametrize("case", _CASES, ids=lambda p: p.stem)
@pytest.mark.asyncio
async def test_case_meets_pass_criteria(case: Path) -> None:
    result = await run_public_secret_case(case)
    evaluate(result, load_test_case(case).pass_criteria)


@pytest.mark.asyncio
async def test_bank_aggregate_precision_recall() -> None:
    assert _CASES, "no path-3 bank cases found"
    tp = fp = fn = 0
    rows = []
    for case in _CASES:
        r = await run_public_secret_case(case)
        tp += r.true_positives
        fp += r.false_positives
        fn += r.false_negatives
        rows.append((r.test_case_id, r.precision, r.recall, r.false_positives))

    precision = 1.0 if tp + fp == 0 else tp / (tp + fp)
    recall = 1.0 if tp + fn == 0 else tp / (tp + fn)
    print("\n=== Path 3 (public-secret) capability bank ===")
    for tcid, p, rc, f in rows:
        print(f"  {tcid:34s} P={p:.2f} R={rc:.2f} FP={f}")
    print(f"  AGGREGATE  TP={tp} FP={fp} FN={fn}  precision={precision:.3f} recall={recall:.3f}")

    assert recall == 1.0, f"missed ground truth — recall {recall:.3f}"
    assert precision == 1.0, f"false positives present — precision {precision:.3f}"
    assert fp == 0
