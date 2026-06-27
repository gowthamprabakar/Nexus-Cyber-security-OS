"""Fleet attack-path coverage scorecard — the single measured North-Star number.

Runs every capability bank and prints ONE fleet-wide precision / recall / FP table plus a
per-path breakdown. This is the artifact the measurement effort produces: not eight separate
1.000s, but a reproducible coverage number across all detectors. Gated paths (trivy / kind)
are run where the tools exist and listed as skipped otherwise — never silently dropped.

Run with ``-s`` to see the table.
"""

from collections.abc import Awaitable, Callable
from pathlib import Path

import pytest

from fleet_testkit.bank_runner import (
    kind_context,
    run_crown_jewel_case,
    run_exposed_ai_case,
    run_exposed_vuln_case,
    run_external_trust_case,
    run_fine_grained_case,
    run_privileged_vuln_case,
    run_public_secret_case,
    run_public_unencrypted_case,
    run_resource_based_case,
)
from fleet_testkit.capability import CapabilityResult
from fleet_testkit.vuln_scan import trivy_available

_CTX = kind_context()
_Runner = Callable[[Path], Awaitable[CapabilityResult]]


async def _run_privileged(case: Path) -> CapabilityResult:
    return await run_privileged_vuln_case(case, context=_CTX or "")


# (label, bank-dir, runner, gate-reason-if-unavailable)
_PATHS: list[tuple[str, str, _Runner, str | None]] = [
    ("public-secret (3)", "path3_public_secret", run_public_secret_case, None),
    ("public-unencrypted (7)", "path7_public_unencrypted", run_public_unencrypted_case, None),
    ("fine-grained (4)", "path4_fine_grained", run_fine_grained_case, None),
    ("resource-based (#7)", "path_gap7_resource_based", run_resource_based_case, None),
    ("external-trust (8)", "path8_external_trust", run_external_trust_case, None),
    ("exposed-AI (10)", "path10_exposed_ai", run_exposed_ai_case, None),
    (
        "exposed-vuln (2)",
        "path2_exposed_vuln",
        run_exposed_vuln_case,
        None if trivy_available else "trivy",
    ),
    (
        "crown-jewel (5)",
        "path5_crown_jewel",
        run_crown_jewel_case,
        None if trivy_available else "trivy",
    ),
    (
        "privileged-vuln (6)",
        "path6_privileged_vuln",
        _run_privileged,
        None if (trivy_available and _CTX) else "kind+trivy",
    ),
]


# Coverage denominator — docs/strategy/wiz-coverage-denominator-2026-06-28.md. The public CNAPP
# attack-path category set (breadth proxy, NOT Wiz's internal rule count). "full" = a named
# archetype covers it; "partial" = half credit. This is COVERAGE (what we detect at all), distinct
# from the P/R QUALITY the banks measure (how well we detect what we cover).
_COVERAGE: list[tuple[str, str]] = [
    ("public storage + data", "full"),
    ("public resource + secret", "full"),
    ("internet-exposed + vuln", "full"),
    ("privileged k8s + vuln", "full"),
    ("over-permissioned identity -> data", "full"),
    ("external/cross-account trust -> data", "full"),
    ("resource-policy data exposure", "full"),
    ("exposed AI + training data", "full"),
    ("crown jewel (composite)", "full"),
    ("active C2 / malicious IP", "full"),
    ("runtime exploit on vuln workload", "full"),
    ("code-to-cloud IaC misconfig", "full"),
    ("identity privilege-escalation chain", "full"),
    ("network lateral movement", "none"),
    ("host/OS vuln (VM/AMI)", "none"),
    ("registry / supply-chain vuln", "partial"),
    ("secret-in-code -> cloud cred", "none"),
    ("SaaS over-scoped OAuth / SSO", "none"),
    ("exposed managed database", "none"),
    ("k8s RBAC privilege escalation", "none"),
    ("KMS key / encryption exposure", "none"),
    ("compliance/posture drift", "partial"),
]


def test_coverage_denominator_number() -> None:
    full = sum(1 for _, s in _COVERAGE if s == "full")
    partial = sum(1 for _, s in _COVERAGE if s == "partial")
    total = len(_COVERAGE)
    covered = full + 0.5 * partial
    pct = 100 * covered / total
    print("\n=== DETECTION COVERAGE vs WIZ (breadth) ===")
    print(f"  {full} full + {partial} partial of {total} = {covered:.0f}/{total} = {pct:.0f}%")
    print(f"  uncovered: {', '.join(c for c, s in _COVERAGE if s == 'none')}")
    # Pin the number so doc and code can't drift; bump deliberately when a gap closes.
    assert (full, partial, total) == (13, 2, 22)  # +privilege_escalation (#13)
    assert pct >= 50, f"coverage {pct:.0f}% below the ~50-60% North-Star floor"


@pytest.mark.asyncio
async def test_fleet_coverage_scorecard() -> None:
    base = Path(__file__).parent / "banks"
    fleet_tp = fleet_fp = fleet_fn = fleet_cases = 0
    rows: list[tuple[str, int, int, int, int, float, float]] = []
    skipped: list[str] = []

    for label, dirname, runner, gate in _PATHS:
        if gate:
            skipped.append(f"{label} [{gate} unavailable]")
            continue
        cases = sorted((base / dirname).glob("*.yaml"))
        tp = fp = fn = 0
        for case in cases:
            r = await runner(case)
            tp += r.true_positives
            fp += r.false_positives
            fn += r.false_negatives
        precision = 1.0 if tp + fp == 0 else tp / (tp + fp)
        recall = 1.0 if tp + fn == 0 else tp / (tp + fn)
        rows.append((label, len(cases), tp, fp, fn, precision, recall))
        fleet_tp += tp
        fleet_fp += fp
        fleet_fn += fn
        fleet_cases += len(cases)

    fleet_p = 1.0 if fleet_tp + fleet_fp == 0 else fleet_tp / (fleet_tp + fleet_fp)
    fleet_r = 1.0 if fleet_tp + fleet_fn == 0 else fleet_tp / (fleet_tp + fleet_fn)

    print("\n=== FLEET ATTACK-PATH COVERAGE SCORECARD ===")
    print(f"  {'path':26s} {'cases':>5} {'TP':>4} {'FP':>4} {'FN':>4} {'P':>7} {'R':>7}")
    for label, ncases, tp, fp, fn, p, rc in rows:
        print(f"  {label:26s} {ncases:>5} {tp:>4} {fp:>4} {fn:>4} {p:>7.3f} {rc:>7.3f}")
    print(
        f"  {'TOTAL (' + str(len(rows)) + ' paths)':26s} {fleet_cases:>5} {fleet_tp:>4} "
        f"{fleet_fp:>4} {fleet_fn:>4} {fleet_p:>7.3f} {fleet_r:>7.3f}"
    )
    if skipped:
        print(f"  gated (run where tools exist): {', '.join(skipped)}")
    else:
        print("  all 8 verticals ran (trivy + kind present)")

    # The measured fleet number is the regression floor: no missed ground truth, no FP.
    assert len(rows) >= 5, "at least the 5 hermetic verticals must run"
    assert fleet_r == 1.0, f"fleet recall {fleet_r:.3f} — a detector missed a planted violation"
    assert fleet_fp == 0, f"fleet false positives = {fleet_fp}"
