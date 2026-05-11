"""Unit tests for the Runtime Threat Agent driver.

All three tool wrappers are mocked at the agent module's import level;
the test surface is the agent's wiring of charter + tools + normalizer
+ summarizer + schemas, not any specific sensor's behavior.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from charter.contract import BudgetSpec, ExecutionContract
from runtime_threat import agent as agent_mod
from runtime_threat.agent import build_registry, run
from runtime_threat.tools.falco import FalcoAlert
from runtime_threat.tools.osquery import OsqueryResult
from runtime_threat.tools.tracee import TraceeAlert

NOW = datetime(2026, 5, 11, tzinfo=UTC)


def _contract(tmp_path: Path) -> ExecutionContract:
    return ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="runtime_threat",
        customer_id="cust_test",
        task="Runtime threat scan",
        required_outputs=["findings.json", "summary.md"],
        budget=BudgetSpec(
            llm_calls=5,
            tokens=10_000,
            wall_clock_sec=60.0,
            cloud_api_calls=10,
            mb_written=10,
        ),
        permitted_tools=["falco_alerts_read", "tracee_alerts_read", "osquery_run"],
        completion_condition="findings.json AND summary.md exist",
        escalation_rules=[],
        workspace=str(tmp_path / "ws"),
        persistent_root=str(tmp_path / "p"),
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )


def _falco(
    *,
    rule: str = "Terminal shell in container",
    priority: str = "Critical",
    tags: tuple[str, ...] = ("container", "shell", "process"),
) -> FalcoAlert:
    return FalcoAlert(
        time=NOW,
        rule=rule,
        priority=priority,
        output="shell spawned",
        output_fields={"container.id": "abc123def456", "k8s.pod.name": "frontend"},
        tags=tags,
    )


def _tracee(
    *,
    event_name: str = "security_file_open",
    severity: int = 3,
) -> TraceeAlert:
    return TraceeAlert(
        timestamp=NOW,
        event_name=event_name,
        process_name="cat",
        process_id=4242,
        host_name="ip-10-0-1-42",
        container_image="alpine:3.18",
        container_id="tracee-cid",
        args={"pathname": "/etc/shadow"},
        severity=severity,
        description="Read /etc/shadow",
        pod_name="bastion",
        namespace="kube-system",
    )


def _patch_falco(monkeypatch: pytest.MonkeyPatch, alerts: Sequence[FalcoAlert]) -> None:
    async def fake(**_: Any) -> tuple[FalcoAlert, ...]:
        return tuple(alerts)

    monkeypatch.setattr(agent_mod, "falco_alerts_read", fake)


def _patch_tracee(monkeypatch: pytest.MonkeyPatch, alerts: Sequence[TraceeAlert]) -> None:
    async def fake(**_: Any) -> tuple[TraceeAlert, ...]:
        return tuple(alerts)

    monkeypatch.setattr(agent_mod, "tracee_alerts_read", fake)


def _patch_osquery(monkeypatch: pytest.MonkeyPatch, rows: list[dict[str, str]]) -> None:
    async def fake(*, sql: str, **_: Any) -> OsqueryResult:
        return OsqueryResult(sql=sql, rows=tuple(rows))

    monkeypatch.setattr(agent_mod, "osquery_run", fake)


# ---------------------------- registry ----------------------------------


def test_build_registry_includes_three_tools() -> None:
    reg = build_registry()
    known = reg.known_tools()
    assert "falco_alerts_read" in known
    assert "tracee_alerts_read" in known
    assert "osquery_run" in known


# ---------------------------- empty path --------------------------------


@pytest.mark.asyncio
async def test_run_with_no_feeds_yields_empty_report(tmp_path: Path) -> None:
    """All three feeds unset → agent emits empty findings and clean outputs."""
    report = await run(_contract(tmp_path))
    assert report.total == 0
    assert (tmp_path / "ws" / "findings.json").is_file()
    assert (tmp_path / "ws" / "summary.md").is_file()


@pytest.mark.asyncio
async def test_empty_findings_json_is_valid(tmp_path: Path) -> None:
    await run(_contract(tmp_path))
    payload = json.loads((tmp_path / "ws" / "findings.json").read_text())
    assert payload["agent"] == "runtime_threat"
    assert payload["customer_id"] == "cust_test"
    assert payload["findings"] == []


# ---------------------------- per-feed happy paths ----------------------


@pytest.mark.asyncio
async def test_falco_only_run_emits_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_falco(monkeypatch, [_falco()])
    feed = tmp_path / "falco.jsonl"
    feed.write_text("placeholder")  # path must exist; reader is mocked

    report = await run(_contract(tmp_path), falco_feed=feed)

    payload = json.loads((tmp_path / "ws" / "findings.json").read_text())
    assert report.total == 1
    assert payload["findings"][0]["finding_info"]["types"][0] == "runtime_process"


@pytest.mark.asyncio
async def test_tracee_only_run_emits_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_tracee(monkeypatch, [_tracee()])
    feed = tmp_path / "tracee.jsonl"
    feed.write_text("placeholder")

    report = await run(_contract(tmp_path), tracee_feed=feed)

    payload = json.loads((tmp_path / "ws" / "findings.json").read_text())
    assert report.total == 1
    assert payload["findings"][0]["finding_info"]["types"][0] == "runtime_file"


@pytest.mark.asyncio
async def test_osquery_only_run_emits_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_osquery(monkeypatch, [{"pid": "1234", "name": "init"}])
    pack = tmp_path / "pack.sql"
    pack.write_text("SELECT pid, name FROM processes LIMIT 1")

    report = await run(_contract(tmp_path), osquery_pack=pack)

    payload = json.loads((tmp_path / "ws" / "findings.json").read_text())
    assert report.total == 1
    assert payload["findings"][0]["finding_info"]["types"][0] == "runtime_osquery"


# ---------------------------- multi-feed --------------------------------


@pytest.mark.asyncio
async def test_all_three_feeds_run_concurrently(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_falco(monkeypatch, [_falco(rule="Outbound to suspicious IP", tags=("network",))])
    _patch_tracee(monkeypatch, [_tracee(event_name="security_file_open")])
    _patch_osquery(monkeypatch, [{"pid": "1234", "name": "orphan"}])

    falco = tmp_path / "f.jsonl"
    tracee = tmp_path / "t.jsonl"
    pack = tmp_path / "p.sql"
    for p in (falco, tracee):
        p.write_text("placeholder")
    pack.write_text("SELECT 1")

    report = await run(
        _contract(tmp_path),
        falco_feed=falco,
        tracee_feed=tracee,
        osquery_pack=pack,
    )

    payload = json.loads((tmp_path / "ws" / "findings.json").read_text())
    types = {f["finding_info"]["types"][0] for f in payload["findings"]}
    # One per feed; deterministic emission order is Falco → Tracee → OSQuery.
    assert report.total == 3
    assert types == {"runtime_network", "runtime_file", "runtime_osquery"}


# ---------------------------- output files ------------------------------


@pytest.mark.asyncio
async def test_findings_json_has_class_uid_2004(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_falco(monkeypatch, [_falco()])
    feed = tmp_path / "f.jsonl"
    feed.write_text("placeholder")

    await run(_contract(tmp_path), falco_feed=feed)

    payload = json.loads((tmp_path / "ws" / "findings.json").read_text())
    assert payload["findings"]
    assert all(f["class_uid"] == 2004 for f in payload["findings"])


@pytest.mark.asyncio
async def test_summary_md_includes_critical_pin_when_critical_present(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_falco(monkeypatch, [_falco(priority="Critical")])
    feed = tmp_path / "f.jsonl"
    feed.write_text("placeholder")

    await run(_contract(tmp_path), falco_feed=feed)

    summary = (tmp_path / "ws" / "summary.md").read_text()
    assert "# Runtime Threat Scan" in summary
    assert "Critical runtime alerts" in summary


# ---------------------------- audit chain -------------------------------


@pytest.mark.asyncio
async def test_audit_log_emits_invocation_completed(
    tmp_path: Path,
) -> None:
    await run(_contract(tmp_path))
    audit_lines = (tmp_path / "ws" / "audit.jsonl").read_text().splitlines()
    actions = [json.loads(line)["action"] for line in audit_lines if line.strip()]
    assert "invocation_started" in actions
    assert "invocation_completed" in actions


@pytest.mark.asyncio
async def test_envelope_attached_to_each_finding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_falco(monkeypatch, [_falco()])
    feed = tmp_path / "f.jsonl"
    feed.write_text("placeholder")
    contract = _contract(tmp_path)

    await run(contract, falco_feed=feed)

    payload = json.loads((tmp_path / "ws" / "findings.json").read_text())
    for f in payload["findings"]:
        envelope = f["nexus_envelope"]
        assert envelope["agent_id"] == "runtime_threat"
        assert envelope["tenant_id"] == "cust_test"
        assert envelope["charter_invocation_id"] == contract.delegation_id


# ---------------------------- OSQuery pack file handling ----------------


@pytest.mark.asyncio
async def test_empty_osquery_pack_skips_osquery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An empty .sql file means no query — OSQuery is skipped."""
    pack = tmp_path / "empty.sql"
    pack.write_text("   \n  \n")

    called = False

    async def boom(**_: Any) -> OsqueryResult:
        nonlocal called
        called = True
        return OsqueryResult(sql="", rows=())

    monkeypatch.setattr(agent_mod, "osquery_run", boom)

    report = await run(_contract(tmp_path), osquery_pack=pack)
    assert called is False
    assert report.total == 0


# ---------------------------- LLM provider plumbed but unused -----------


@pytest.mark.asyncio
async def test_run_accepts_llm_provider_without_calling_it(
    tmp_path: Path,
) -> None:
    """Signature accepts llm_provider for future iterations; v0.1 doesn't call it."""
    from charter.llm import FakeLLMProvider

    provider = FakeLLMProvider(responses=[])
    await run(_contract(tmp_path), llm_provider=provider)
    assert provider.calls == []
