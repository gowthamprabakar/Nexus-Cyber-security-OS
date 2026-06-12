"""supervisor v0.2 Task 15 — hierarchy invariant tests (WI-O8/H2)."""

from __future__ import annotations

import pytest
from supervisor.hierarchy import (
    SUPERVISOR_AGENT_ID,
    PeerToPeerViolationError,
    assert_no_peer_to_peer,
)


@pytest.mark.parametrize(
    "target", ["compliance", "audit", "data_security", "remediation", "escalate"]
)
def test_supervisor_source_allowed(target: str) -> None:
    assert_no_peer_to_peer("supervisor", target)  # does not raise


@pytest.mark.parametrize(
    "source", ["compliance", "audit", "data_security", "remediation", "curiosity"]
)
def test_non_supervisor_source_rejected(source: str) -> None:
    with pytest.raises(PeerToPeerViolationError, match="Peer-to-peer"):
        assert_no_peer_to_peer(source, "compliance")


def test_supervisor_agent_id_constant() -> None:
    assert SUPERVISOR_AGENT_ID == "supervisor"


def test_error_names_source_and_target() -> None:
    with pytest.raises(PeerToPeerViolationError, match="audit"):
        assert_no_peer_to_peer("compliance", "audit")


def test_case_sensitive() -> None:
    # "Supervisor" is not "supervisor" — strict, no casing bypass.
    with pytest.raises(PeerToPeerViolationError):
        assert_no_peer_to_peer("Supervisor", "compliance")


def test_empty_source_rejected() -> None:
    with pytest.raises(PeerToPeerViolationError):
        assert_no_peer_to_peer("", "compliance")
