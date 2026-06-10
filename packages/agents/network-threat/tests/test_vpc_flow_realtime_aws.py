"""D.4 v0.2 Task 8 — live AWS VPC Flow Logs subscription tests (injected logs client)."""

from __future__ import annotations

from typing import Any

from charter.credentials import CredentialResolver as _Contract
from network_threat.credentials import CredentialResolver
from network_threat.tools.vpc_flow_realtime_aws import VpcFlowLiveReader

# A v2 VPC flow line: version acct eni src dst sport dport proto packets bytes start end action status
_FLOW = (
    "2 123456789012 eni-abc 10.0.0.5 1.2.3.4 44321 443 6 10 8400 1700000000 1700000060 ACCEPT OK"
)


class _FakeLogs:
    def __init__(self, events: list[dict[str, Any]]) -> None:
        self._events = events
        self.calls: list[dict[str, Any]] = []

    def filter_log_events(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(kwargs)
        return {"events": self._events}


def test_poll_parses_flow_records() -> None:
    reader = VpcFlowLiveReader(_FakeLogs([{"message": _FLOW}]))
    recs = reader.poll("vpc-flow-logs")
    assert len(recs) == 1
    assert recs[0].src_ip == "10.0.0.5" and recs[0].dst_ip == "1.2.3.4"
    assert recs[0].dst_port == 443 and recs[0].protocol == 6 and recs[0].bytes_transferred == 8400


def test_start_time_passed() -> None:
    logs = _FakeLogs([])
    VpcFlowLiveReader(logs).poll("vpc-flow-logs", start_time_ms=1_700_000_000_000)
    assert logs.calls[0]["logGroupName"] == "vpc-flow-logs"
    assert logs.calls[0]["startTime"] == 1_700_000_000_000


def test_no_start_time_omits_param() -> None:
    logs = _FakeLogs([])
    VpcFlowLiveReader(logs).poll("vpc-flow-logs")
    assert "startTime" not in logs.calls[0]


def test_malformed_message_skipped() -> None:
    reader = VpcFlowLiveReader(_FakeLogs([{"message": "garbage tokens"}, {"message": _FLOW}]))
    recs = reader.poll("g")
    assert len(recs) == 1  # only the valid flow parsed


def test_empty_events() -> None:
    assert VpcFlowLiveReader(_FakeLogs([])).poll("g") == ()


def test_multiple_records() -> None:
    reader = VpcFlowLiveReader(_FakeLogs([{"message": _FLOW}, {"message": _FLOW}]))
    assert len(reader.poll("g")) == 2


# --------------------------- CredentialResolver --------------------------


def test_resolver_state() -> None:
    r = CredentialResolver(profile="dev", region="eu-west-1")
    assert r.profile == "dev" and r.region == "eu-west-1"


def test_resolver_defaults() -> None:
    r = CredentialResolver()
    assert r.profile is None and r.region == "us-east-1"


def test_resolver_is_charter_contract() -> None:
    assert issubclass(CredentialResolver, _Contract)
    assert CredentialResolver.__slots__ == ("_profile", "_region")
