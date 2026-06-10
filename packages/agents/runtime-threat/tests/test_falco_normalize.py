"""D.3 v0.2 Task 4 — Falco live event normalization + enrichment tests."""

from __future__ import annotations

from datetime import UTC, datetime

from runtime_threat.tools.falco import FalcoAlert
from runtime_threat.tools.falco_normalize import enrich, normalize_falco_event

_RX = datetime(2026, 6, 10, 12, 0, 0, tzinfo=UTC)

_RAW = {
    "rule": "Terminal shell in container",
    "priority": "Warning",
    "output": "shell spawned",
    "time": "2026-06-10T11:59:00.000Z",
    "output_fields": {
        "proc.name": "bash",
        "proc.pid": "1234",
        "proc.ppid": "1",
        "proc.pname": "runc",
        "proc.cmdline": "bash -i",
        "container.id": "abc123",
        "container.image.repository": "evil/image",
        "container.name": "web",
        "k8s.pod.name": "web-0",
        "k8s.ns.name": "prod",
    },
}


def test_normalize_full_event() -> None:
    norm = normalize_falco_event(_RAW, received_at=_RX)
    assert norm is not None
    assert norm.alert.rule == "Terminal shell in container"
    assert norm.alert.priority == "Warning"
    assert norm.alert.time.isoformat().startswith("2026-06-10T11:59:00")  # event's own time


def test_process_context() -> None:
    p = normalize_falco_event(_RAW, received_at=_RX).enrichment.process
    assert p.name == "bash" and p.pid == "1234" and p.ppid == "1"
    assert p.parent_name == "runc" and p.cmdline == "bash -i"


def test_container_context_repository() -> None:
    c = normalize_falco_event(_RAW, received_at=_RX).enrichment.container
    assert c.id == "abc123" and c.image == "evil/image" and c.name == "web"


def test_container_image_fallback_to_plain_field() -> None:
    raw = {"rule": "R", "output_fields": {"container.image": "plain/img"}}
    c = normalize_falco_event(raw, received_at=_RX).enrichment.container
    assert c.image == "plain/img"


def test_k8s_context() -> None:
    k = normalize_falco_event(_RAW, received_at=_RX).enrichment.k8s
    assert k.pod == "web-0" and k.namespace == "prod"


def test_missing_rule_returns_none() -> None:
    assert normalize_falco_event({"priority": "Warning"}, received_at=_RX) is None


def test_missing_time_uses_received_at() -> None:
    norm = normalize_falco_event({"rule": "R"}, received_at=_RX)
    assert norm is not None and norm.alert.time == _RX


def test_empty_output_fields_empty_contexts() -> None:
    norm = normalize_falco_event({"rule": "R"}, received_at=_RX)
    assert norm.enrichment.process.name == "" and norm.enrichment.container.id == ""


def test_enrich_standalone() -> None:
    alert = FalcoAlert(
        time=_RX, rule="R", priority="Notice", output="", output_fields={"proc.name": "sh"}
    )
    assert enrich(alert).process.name == "sh"
