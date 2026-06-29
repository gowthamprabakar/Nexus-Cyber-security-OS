"""Path-4 (fine-grained over-permission) capability bank — third measured vertical, first
cross-feeder (identity + data-security).

Per case: drive both feeders' real code and assert precision/recall/FP. Aggregate: print the
measured numbers (run with ``-s``). The traps (a "*" wildcard grant, a private-bucket grant)
genuinely produce no hit, so the score has teeth.
"""

from pathlib import Path

import pytest

from fleet_testkit.bank_runner import run_fine_grained_case
from fleet_testkit.capability import evaluate, load_test_case

_BANK = Path(__file__).parent / "banks" / "path4_fine_grained"
_CASES = sorted(_BANK.glob("*.yaml"))


@pytest.mark.parametrize("case", _CASES, ids=lambda p: p.stem)
@pytest.mark.asyncio
async def test_case_meets_pass_criteria(case: Path) -> None:
    result = await run_fine_grained_case(case)
    evaluate(result, load_test_case(case).pass_criteria)


@pytest.mark.asyncio
async def test_bank_aggregate_precision_recall() -> None:
    assert _CASES, "no path-4 bank cases found"
    tp = fp = fn = 0
    rows = []
    for case in _CASES:
        r = await run_fine_grained_case(case)
        tp += r.true_positives
        fp += r.false_positives
        fn += r.false_negatives
        rows.append((r.test_case_id, r.precision, r.recall, r.false_positives))

    precision = 1.0 if tp + fp == 0 else tp / (tp + fp)
    recall = 1.0 if tp + fn == 0 else tp / (tp + fn)
    print("\n=== Path 4 (fine-grained over-permission) capability bank ===")
    for tcid, p, rc, f in rows:
        print(f"  {tcid:38s} P={p:.2f} R={rc:.2f} FP={f}")
    print(f"  AGGREGATE  TP={tp} FP={fp} FN={fn}  precision={precision:.3f} recall={recall:.3f}")

    assert recall == 1.0, f"missed ground truth — recall {recall:.3f}"
    assert precision == 1.0, f"false positives present — precision {precision:.3f}"
    assert fp == 0
