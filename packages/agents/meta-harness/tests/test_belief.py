"""v0.5 Item 1 — belief: product route probability + noisy-OR sink combination."""

import pytest
from meta_harness.belief import route_probability, sink_probability


def test_route_is_product_of_entry_and_edge_priors():
    # entry 0.76, RUNS_IMAGE 0.95, VULNERABLE_TO 0.7 -> 0.76*0.95*0.7
    assert route_probability(0.76, ["RUNS_IMAGE", "VULNERABLE_TO"]) == pytest.approx(
        0.76 * 0.95 * 0.7
    )


def test_empty_route_is_entry_probability():
    assert route_probability(0.4, []) == pytest.approx(0.4)


def test_unknown_edge_uses_default_not_one():
    assert route_probability(0.4, ["NOT_A_REAL_EDGE"]) == pytest.approx(0.4 * 0.5)


def test_noisy_or_combines_routes_above_the_max():
    # THE belief-network property: two routes to one sink beat either alone
    combined = sink_probability([0.5, 0.5])
    assert combined == pytest.approx(0.75)  # 1 - 0.5*0.5
    assert combined > max(0.5, 0.5)


def test_single_route_sink_equals_that_route():
    assert sink_probability([0.8]) == pytest.approx(0.8)
