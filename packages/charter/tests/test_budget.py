"""Tests for the budget envelope."""

import pytest
from charter.budget import BudgetEnvelope
from charter.exceptions import BudgetExhausted


def test_envelope_construction() -> None:
    env = BudgetEnvelope(
        llm_calls=10, tokens=1000, wall_clock_sec=60.0, cloud_api_calls=50, mb_written=10
    )
    assert env.llm_calls == 10
    assert env.tokens == 1000


def test_envelope_consume_within_limit() -> None:
    env = BudgetEnvelope(
        llm_calls=10, tokens=1000, wall_clock_sec=60.0, cloud_api_calls=50, mb_written=10
    )
    env.consume(llm_calls=1, tokens=100)
    assert env.used("llm_calls") == 1
    assert env.used("tokens") == 100
    assert env.remaining("llm_calls") == 9


def test_envelope_consume_exceeds_limit_raises() -> None:
    env = BudgetEnvelope(
        llm_calls=2, tokens=1000, wall_clock_sec=60.0, cloud_api_calls=50, mb_written=10
    )
    env.consume(llm_calls=1, tokens=0)
    with pytest.raises(BudgetExhausted) as exc_info:
        env.consume(llm_calls=2, tokens=0)
    assert exc_info.value.dimension == "llm_calls"
    assert exc_info.value.limit == 2
    assert exc_info.value.used == 3


def test_envelope_wall_clock_check() -> None:
    env = BudgetEnvelope(
        llm_calls=10, tokens=1000, wall_clock_sec=0.001, cloud_api_calls=50, mb_written=10
    )
    env.start_clock()
    import time

    time.sleep(0.01)
    with pytest.raises(BudgetExhausted) as exc_info:
        env.check_wall_clock()
    assert exc_info.value.dimension == "wall_clock_sec"


def test_envelope_zero_or_negative_limit_rejected() -> None:
    with pytest.raises(ValueError):
        BudgetEnvelope(
            llm_calls=0, tokens=1000, wall_clock_sec=60.0, cloud_api_calls=50, mb_written=10
        )
    with pytest.raises(ValueError):
        BudgetEnvelope(
            llm_calls=10, tokens=-1, wall_clock_sec=60.0, cloud_api_calls=50, mb_written=10
        )
