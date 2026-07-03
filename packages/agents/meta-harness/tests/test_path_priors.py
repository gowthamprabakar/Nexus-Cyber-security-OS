"""v0.5 Item 1 — priors: measured leaf probability + expert edge-traversal table."""

import pytest
from meta_harness.path_priors import DEFAULT_EDGE_PRIOR, EDGE_TRAVERSAL_PRIOR, leaf_probability


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
