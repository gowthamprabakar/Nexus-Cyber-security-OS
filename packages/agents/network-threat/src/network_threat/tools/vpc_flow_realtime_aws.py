"""Live AWS VPC Flow Logs subscription (D.4 v0.2 Task 8).

The v0.2 live counterpart to the offline ``read_vpc_flow_logs`` (which stays for the
deterministic eval). Reads VPC Flow Log records from **CloudWatch Logs** via the hoisted
charter CredentialResolver, parsing each log event's space-separated ``message`` with the
**shared offline parser** (`_try_parse_record` + the v2 default field order) so records
are byte-identical. Per **Q3** AWS is live at v0.2; Azure NSG flow + GCP VPC flow are v0.3.
The CloudWatch Logs client is injectable so this is unit-testable without live AWS.
"""

from __future__ import annotations

from typing import Any

from network_threat.schemas import FlowRecord
from network_threat.tools.vpc_flow_reader import _V2_DEFAULT_FIELDS, _try_parse_record


class VpcFlowLiveReader:
    """Polls a CloudWatch Logs group for VPC Flow Log records. Client injected (a
    boto3 ``logs`` client in prod, a fake in tests)."""

    __slots__ = ("_logs",)

    def __init__(self, logs_client: Any) -> None:
        self._logs = logs_client

    def poll(self, log_group: str, *, start_time_ms: int | None = None) -> tuple[FlowRecord, ...]:
        """Fetch + parse VPC flow records from the log group. ``start_time_ms`` resumes
        from a saved cursor (epoch millis)."""
        kwargs: dict[str, Any] = {"logGroupName": log_group}
        if start_time_ms is not None:
            kwargs["startTime"] = start_time_ms
        resp = self._logs.filter_log_events(**kwargs)

        records: list[FlowRecord] = []
        for event in resp.get("events", []):
            message = str(event.get("message", ""))
            record = _try_parse_record(message.split(), _V2_DEFAULT_FIELDS)
            if record is not None:
                records.append(record)
        return tuple(records)


def read_vpc_flow_live(
    *,
    log_group: str,
    start_time_ms: int | None = None,
    profile: str | None = None,
    region: str = "us-east-1",
) -> tuple[FlowRecord, ...]:
    """Live VPC flow reader: builds the CloudWatch Logs client via the charter
    CredentialResolver and polls the group. (Driven from the live lane / e2e; not wired
    into the deterministic offline run loop.)"""
    from network_threat.credentials import CredentialResolver

    logs = CredentialResolver(profile=profile, region=region).client("logs")
    return VpcFlowLiveReader(logs).poll(log_group, start_time_ms=start_time_ms)
