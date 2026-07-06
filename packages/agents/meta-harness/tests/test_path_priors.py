"""v0.5 Item 1 — priors: measured leaf probability + expert edge-traversal table."""

import pytest
from meta_harness.path_priors import (
    _LOGGING_DISABLED_LIFT,
    DEFAULT_EDGE_PRIOR,
    EDGE_TRAVERSAL_PRIOR,
    leaf_probability,
)


def test_severity_maps_linearly_into_0_to_0_8():
    assert leaf_probability(50) == pytest.approx(0.40)  # 50/100 * 0.8
    assert leaf_probability(95) == pytest.approx(0.76)  # 95/100 * 0.8


def test_epss_overrides_severity():
    assert leaf_probability(95, epss=0.3) == pytest.approx(0.3)


def test_kev_floors_probability_at_0_9():
    # noisy-OR bump: 1 - (1 - p)(1 - 0.9); sev 0 -> exactly 0.9
    assert leaf_probability(0, kev=True) == pytest.approx(0.9)
    assert leaf_probability(50, kev=True) == pytest.approx(0.94)  # 1 - 0.6*0.1


def test_severity_is_clamped():
    assert leaf_probability(200) == pytest.approx(0.8)
    assert leaf_probability(-5) == pytest.approx(0.0)


def test_edge_table_and_default():
    assert EDGE_TRAVERSAL_PRIOR["EXPOSES_DATA"] == 1.0
    assert EDGE_TRAVERSAL_PRIOR["CAN_REACH"] == 0.6
    assert DEFAULT_EDGE_PRIOR == 0.5


# ---------------------------------------------------------------------------
# Cycle 8 T1 — logging_disabled lift (defense-evasion enrichment)
# ---------------------------------------------------------------------------


def test_logging_disabled_lifts_probability() -> None:
    """logging_disabled=True must produce a strictly higher probability than False."""
    base = leaf_probability(50)
    lifted = leaf_probability(50, logging_disabled=True)
    assert lifted > base


def test_logging_disabled_lift_ratio_equals_constant() -> None:
    """Before clamping, the ratio must equal _LOGGING_DISABLED_LIFT exactly."""
    sev = 50  # p = 0.4, lifted = 0.4 * 1.15 = 0.46 — well under 1.0, so no clamping
    base = leaf_probability(sev)
    lifted = leaf_probability(sev, logging_disabled=True)
    assert lifted == pytest.approx(base * _LOGGING_DISABLED_LIFT)


def test_logging_disabled_clamps_at_1() -> None:
    """High-severity KEV path: the lift must not push probability above 1.0."""
    # severity=100, kev=True → base ≈ 0.98 (noisy-OR: 1-(1-0.8)(1-0.9) = 0.98)
    # 0.98 * 1.15 = 1.127 → must clamp to 1.0
    clamped = leaf_probability(100, kev=True, logging_disabled=True)
    assert clamped <= 1.0
    assert clamped == pytest.approx(1.0)


def test_logging_disabled_false_unchanged() -> None:
    """logging_disabled=False (default) must return exactly today's value — backward-compat."""
    assert leaf_probability(50, logging_disabled=False) == pytest.approx(leaf_probability(50))
    assert leaf_probability(95, kev=True, logging_disabled=False) == pytest.approx(
        leaf_probability(95, kev=True)
    )
