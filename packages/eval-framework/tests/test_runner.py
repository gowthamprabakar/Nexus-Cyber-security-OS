"""Tests for the `EvalRunner` Protocol and `FakeRunner` test double."""

from __future__ import annotations

from pathlib import Path

import pytest
from eval_framework.cases import EvalCase
from eval_framework.runner import EvalRunner, FakeRunner


def _case(case_id: str = "001_x") -> EvalCase:
    return EvalCase(case_id=case_id, description="d", fixture={}, expected={})


# ---------------------------- Protocol shape ------------------------------


def test_protocol_is_runtime_checkable() -> None:
    fake = FakeRunner()
    assert isinstance(fake, EvalRunner)


def test_fake_runner_default_agent_name() -> None:
    assert FakeRunner().agent_name == "fake"


def test_fake_runner_custom_agent_name() -> None:
    assert FakeRunner(agent_name="cloud_posture").agent_name == "cloud_posture"


# ---------------------------- run() default behavior -----------------------


@pytest.mark.asyncio
async def test_run_returns_default_passed_when_no_queue(tmp_path: Path) -> None:
    runner = FakeRunner(default_passed=True)
    passed, reason, actuals, audit_path = await runner.run(_case(), workspace=tmp_path)
    assert passed is True
    assert reason is None
    assert actuals == {}
    assert audit_path is None


@pytest.mark.asyncio
async def test_run_returns_default_failed_when_no_queue(tmp_path: Path) -> None:
    runner = FakeRunner(default_passed=False)
    passed, reason, _actuals, _path = await runner.run(_case(), workspace=tmp_path)
    assert passed is False
    assert reason == "no queued response and default_passed is False"


# ---------------------------- queued responses -----------------------------


@pytest.mark.asyncio
async def test_run_returns_queued_response_for_case_id(tmp_path: Path) -> None:
    runner = FakeRunner()
    runner.queue(
        "002_y",
        passed=False,
        failure_reason="expected 0, got 1",
        actuals={"finding_count": 1, "by_severity": {"high": 1}},
    )

    # Different case_id → falls through to default
    passed, _, _, _ = await runner.run(_case("001_x"), workspace=tmp_path)
    assert passed is True

    # Matching case_id → queued response returned
    passed, reason, actuals, _ = await runner.run(_case("002_y"), workspace=tmp_path)
    assert passed is False
    assert reason == "expected 0, got 1"
    assert actuals["finding_count"] == 1


@pytest.mark.asyncio
async def test_run_records_each_call(tmp_path: Path) -> None:
    """The runner exposes its call history for assertions."""
    runner = FakeRunner()
    await runner.run(_case("001"), workspace=tmp_path)
    await runner.run(_case("002"), workspace=tmp_path)
    assert [c.case_id for c in runner.calls] == ["001", "002"]


@pytest.mark.asyncio
async def test_queued_response_with_audit_log_path(tmp_path: Path) -> None:
    audit = tmp_path / "audit.jsonl"
    audit.write_text("{}")

    runner = FakeRunner()
    runner.queue("001", passed=True, audit_log_path=audit)

    _passed, _, _, audit_path = await runner.run(_case("001"), workspace=tmp_path)
    assert audit_path == audit
