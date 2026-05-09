"""Tests for OCSF envelope wrap/unwrap (per ADR-004)."""

import pytest
from shared.fabric.envelope import NexusEnvelope, unwrap_ocsf, wrap_ocsf


def _envelope() -> NexusEnvelope:
    return NexusEnvelope(
        correlation_id="01HZX7B0K3M5N9P2Q4R6S8T0V0",
        tenant_id="tnt-abc",
        agent_id="cloud-posture",
        nlah_version="0.1.0",
        model_pin="claude-sonnet-4-5",
        charter_invocation_id="01HZX7B0K3M5N9P2Q4R6S8T0V1",
    )


def test_wrap_attaches_envelope_under_known_key() -> None:
    ocsf = {"category_uid": 4, "class_uid": 2003, "severity_id": 4}
    wrapped = wrap_ocsf(ocsf, _envelope())
    assert "nexus_envelope" in wrapped
    assert wrapped["category_uid"] == 4
    assert wrapped["nexus_envelope"]["tenant_id"] == "tnt-abc"


def test_wrap_does_not_mutate_input() -> None:
    ocsf = {"category_uid": 4}
    wrap_ocsf(ocsf, _envelope())
    assert "nexus_envelope" not in ocsf


def test_unwrap_returns_event_and_envelope() -> None:
    ocsf = {"category_uid": 4, "class_uid": 2003}
    payload = wrap_ocsf(ocsf, _envelope())
    event, env = unwrap_ocsf(payload)
    assert "nexus_envelope" not in event
    assert event["category_uid"] == 4
    assert env.tenant_id == "tnt-abc"
    assert env.model_pin == "claude-sonnet-4-5"


def test_unwrap_missing_envelope_raises() -> None:
    with pytest.raises(ValueError, match="nexus_envelope"):
        unwrap_ocsf({"category_uid": 4})


def test_unwrap_envelope_missing_required_field_raises() -> None:
    payload = {
        "category_uid": 4,
        "nexus_envelope": {"correlation_id": "x"},  # missing tenant_id et al.
    }
    with pytest.raises(ValueError):
        unwrap_ocsf(payload)


def test_round_trip_preserves_payload() -> None:
    ocsf = {
        "category_uid": 4,
        "class_uid": 2003,
        "severity_id": 5,
        "type_name": "Compliance Finding",
        "metadata": {"product": {"name": "prowler"}},
    }
    env = _envelope()
    event, recovered = unwrap_ocsf(wrap_ocsf(ocsf, env))
    assert event == ocsf
    assert recovered == env
