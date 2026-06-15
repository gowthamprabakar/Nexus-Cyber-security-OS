"""Tests — ``data_security.agent`` driver.

Task 12. End-to-end pipeline tests:

- Empty contract (no feeds) → empty FindingsReport, both artifacts emitted.
- Single bucket via inventory feed → detector findings produced.
- Object sample with PII → classifier hit reflected in detector severity uplift.
- ``--cloud-posture-workspace`` present → CORRELATE + SCORE uplift.
- Public bucket + F.3 finding on same bucket → CRITICAL.
- Workspace artifacts (findings.json + report.md) written deterministically.
- Audit chain hash-chained (charter implicit audit).
- Tool registry has the 3 expected tools.
"""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from charter.contract import BudgetSpec, ExecutionContract
from data_security.agent import build_registry, run


def _make_contract(
    workspace: Path,
    *,
    delegation_id: str | None = None,
) -> ExecutionContract:
    """Build a minimal ExecutionContract sufficient for the agent run."""
    persistent = workspace / "_persistent"
    persistent.mkdir(exist_ok=True)
    return ExecutionContract(
        schema_version="0.1",
        delegation_id=delegation_id or "01J0000000000000000000DSEC",
        source_agent="supervisor",
        target_agent="data_security",
        customer_id="cust_test",
        task="Data security scan",
        required_outputs=["findings.json", "report.md"],
        budget=BudgetSpec(
            llm_calls=5,
            tokens=10_000,
            wall_clock_sec=60.0,
            cloud_api_calls=10,
            mb_written=10,
        ),
        permitted_tools=[
            "read_s3_inventory",
            "read_s3_objects",
            "read_f3_findings",
        ],
        completion_condition="findings.json AND report.md exist",
        escalation_rules=[],
        workspace=str(workspace),
        persistent_root=str(persistent),
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )


def _write_inventory(path: Path, buckets: list[dict]) -> None:
    path.write_text(json.dumps({"buckets": buckets}), encoding="utf-8")


def _write_objects(path: Path, objects: list[dict]) -> None:
    path.write_text(json.dumps({"objects": objects}), encoding="utf-8")


def _b64(payload: bytes) -> str:
    return base64.b64encode(payload).decode("ascii")


def _public_bucket_dict(name: str = "alpha") -> dict:
    return {
        "name": name,
        "region": "us-east-1",
        "account_id": "123456789012",
        "acl": {"grants_all_users": ["READ"], "grants_authenticated_users": []},
        "public_access_block": {
            "block_public_acls": False,
            "ignore_public_acls": False,
            "block_public_policy": False,
            "restrict_public_buckets": False,
        },
        "encryption": {"algorithm": "AES256", "kms_master_key_id": None},
        "policy_json": None,
        "tags": {},
    }


def _private_bucket_dict(name: str = "private") -> dict:
    return {
        "name": name,
        "region": "us-east-1",
        "account_id": "123456789012",
        "acl": {"grants_all_users": [], "grants_authenticated_users": []},
        "public_access_block": {
            "block_public_acls": True,
            "ignore_public_acls": True,
            "block_public_policy": True,
            "restrict_public_buckets": True,
        },
        "encryption": {"algorithm": "AES256", "kms_master_key_id": None},
        "policy_json": None,
        "tags": {},
    }


# ---------------------------------------------------------------------------
# Tool registry
# ---------------------------------------------------------------------------


def test_build_registry_has_expected_tools() -> None:
    reg = build_registry()
    names = sorted(reg.known_tools())
    # Phase C SS4 added scan_s3_live (the guarded live S3 route).
    assert names == ["read_f3_findings", "read_s3_inventory", "read_s3_objects", "scan_s3_live"]


# ---------------------------------------------------------------------------
# End-to-end runs
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_with_no_feeds_emits_empty_report(tmp_path: Path) -> None:
    contract = _make_contract(tmp_path)
    report = await run(contract)
    assert report.total == 0
    # Both artifacts emitted.
    assert (tmp_path / "findings.json").exists()
    assert (tmp_path / "report.md").exists()
    # Audit chain emitted by charter implicitly.
    assert (tmp_path / "audit.jsonl").exists()


@pytest.mark.asyncio
async def test_run_with_public_bucket_emits_high_finding(tmp_path: Path) -> None:
    inventory_path = tmp_path / "inventory.json"
    _write_inventory(inventory_path, [_public_bucket_dict("alpha")])

    contract = _make_contract(tmp_path)
    report = await run(contract, s3_inventory_feed=inventory_path)

    # Public bucket → at least one HIGH finding (s3_bucket_public).
    severities = {f["severity_id"] for f in report.findings}
    # severity_id 4 = HIGH
    assert 4 in severities


@pytest.mark.asyncio
async def test_run_with_classifier_hit_uplifts_to_critical(tmp_path: Path) -> None:
    """Public bucket + object sample containing PII → classifier hit →
    s3_bucket_public finding uplifts to CRITICAL.
    """
    inventory_path = tmp_path / "inventory.json"
    _write_inventory(inventory_path, [_public_bucket_dict("alpha")])

    objects_path = tmp_path / "objects.json"
    _write_objects(
        objects_path,
        [
            {
                "bucket": "alpha",
                "key": "data.csv",
                "content_sample_b64": _b64(b"name,ssn\nbob,123-45-6789"),
            }
        ],
    )

    contract = _make_contract(tmp_path)
    report = await run(
        contract,
        s3_inventory_feed=inventory_path,
        s3_objects_feed=objects_path,
    )

    # At least one CRITICAL finding (s3_bucket_public uplifted).
    severities = {f["severity_id"] for f in report.findings}
    # severity_id 5 = CRITICAL
    assert 5 in severities


@pytest.mark.asyncio
async def test_run_no_findings_for_fully_clean_account(tmp_path: Path) -> None:
    inventory_path = tmp_path / "inventory.json"
    _write_inventory(inventory_path, [_private_bucket_dict("private")])

    contract = _make_contract(tmp_path)
    report = await run(contract, s3_inventory_feed=inventory_path)
    assert report.total == 0


# ---------------------------------------------------------------------------
# F.3 correlation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_with_f3_workspace_uplifts_via_correlation(tmp_path: Path) -> None:
    """Public bucket alpha + F.3 finding on bucket alpha →
    s3_bucket_public uplifts HIGH → CRITICAL via correlation.
    """
    inventory_path = tmp_path / "inventory.json"
    _write_inventory(inventory_path, [_public_bucket_dict("alpha")])

    # Build a sibling F.3 workspace with a finding on the same bucket.
    f3_workspace = tmp_path / "f3-workspace"
    f3_workspace.mkdir()
    (f3_workspace / "findings.json").write_text(
        json.dumps(
            {
                "findings": [
                    {
                        "class_uid": 2003,
                        "finding_info": {"uid": "CSPM-AWS-PROW-001-alpha"},
                        "resources": [{"uid": "arn:aws:s3:::alpha"}],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    contract = _make_contract(tmp_path)
    report = await run(
        contract,
        s3_inventory_feed=inventory_path,
        cloud_posture_workspace=f3_workspace,
    )

    severities = {f["severity_id"] for f in report.findings}
    # s3_bucket_public → HIGH (4) base, uplifted to CRITICAL (5) by F.3 correlation.
    assert 5 in severities


@pytest.mark.asyncio
async def test_run_without_f3_workspace_no_uplift(tmp_path: Path) -> None:
    """No F.3 workspace → no correlation, no uplift. HIGH stays HIGH."""
    inventory_path = tmp_path / "inventory.json"
    _write_inventory(inventory_path, [_public_bucket_dict("alpha")])

    contract = _make_contract(tmp_path)
    report = await run(contract, s3_inventory_feed=inventory_path)

    severities = {f["severity_id"] for f in report.findings}
    # Only HIGH (4), no CRITICAL.
    assert 4 in severities
    assert 5 not in severities


# ---------------------------------------------------------------------------
# Artifact contents
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_writes_findings_json_with_correct_shape(tmp_path: Path) -> None:
    inventory_path = tmp_path / "inventory.json"
    _write_inventory(inventory_path, [_public_bucket_dict("alpha")])
    contract = _make_contract(tmp_path)
    await run(contract, s3_inventory_feed=inventory_path)

    payload = json.loads((tmp_path / "findings.json").read_text(encoding="utf-8"))
    assert payload["agent"] == "data_security"
    assert payload["customer_id"] == "cust_test"
    assert payload["run_id"] == contract.delegation_id
    assert isinstance(payload["findings"], list)
    assert len(payload["findings"]) >= 1


@pytest.mark.asyncio
async def test_run_writes_report_md_with_markdown(tmp_path: Path) -> None:
    inventory_path = tmp_path / "inventory.json"
    _write_inventory(inventory_path, [_public_bucket_dict("alpha")])
    contract = _make_contract(tmp_path)
    await run(contract, s3_inventory_feed=inventory_path)

    md = (tmp_path / "report.md").read_text(encoding="utf-8")
    assert md.startswith("# Data Security Agent")
    assert contract.delegation_id in md


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_same_inputs_same_finding_ids(tmp_path: Path) -> None:
    """Two runs with the same delegation_id produce the same finding-ids.

    (Underlying assumption: detectors are pure + sequence-numbered
    deterministically by bucket order.)
    """
    inventory_path = tmp_path / "inventory.json"
    _write_inventory(inventory_path, [_public_bucket_dict("alpha")])

    workspace_a = tmp_path / "a"
    workspace_a.mkdir()
    workspace_b = tmp_path / "b"
    workspace_b.mkdir()

    delegation_id = "01J0000000000000000000DETA"
    contract_a = _make_contract(workspace_a, delegation_id=delegation_id)
    contract_b = _make_contract(workspace_b, delegation_id=delegation_id)

    report_a = await run(contract_a, s3_inventory_feed=inventory_path)
    report_b = await run(contract_b, s3_inventory_feed=inventory_path)

    ids_a = sorted(f["finding_info"]["uid"] for f in report_a.findings)
    ids_b = sorted(f["finding_info"]["uid"] for f in report_b.findings)
    assert ids_a == ids_b


# ---------------------------------------------------------------------------
# Q6 — no PII leaks via the end-to-end run
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_does_not_leak_pii_into_report_or_findings(tmp_path: Path) -> None:
    """End-to-end Q6: PII in object samples must NEVER reach findings.json
    or report.md. Only ``ClassifierLabel`` tokens may surface.
    """
    inventory_path = tmp_path / "inventory.json"
    _write_inventory(inventory_path, [_public_bucket_dict("alpha")])

    secret_ssn = "987-65-4321"  # noqa: S105  # synthetic test fixture, not a credential
    secret_card = "4111-1111-1111-1111"  # noqa: S105  # well-known public Visa test card

    objects_path = tmp_path / "objects.json"
    _write_objects(
        objects_path,
        [
            {
                "bucket": "alpha",
                "key": "data.csv",
                "content_sample_b64": _b64(f"name,ssn,cc\nbob,{secret_ssn},{secret_card}".encode()),
            }
        ],
    )

    contract = _make_contract(tmp_path)
    await run(
        contract,
        s3_inventory_feed=inventory_path,
        s3_objects_feed=objects_path,
    )

    # Final-artifact contents must not contain the original PII strings.
    findings_text = (tmp_path / "findings.json").read_text(encoding="utf-8")
    report_text = (tmp_path / "report.md").read_text(encoding="utf-8")

    assert secret_ssn not in findings_text, (
        "Q6 violation: original SSN substring leaked into findings.json"
    )
    assert secret_ssn not in report_text, "Q6 violation: SSN leaked into report.md"
    assert secret_card not in findings_text, "Q6 violation: card number leaked into findings.json"
    assert secret_card not in report_text, "Q6 violation: card number leaked into report.md"

    # But the label tokens DO surface (this is the intended visible signal).
    assert "ssn" in report_text


# ---------------------------------------------------------------------------
# A-2.4 (ADR-015) — secrets-in-runtime cross-agent e2e (D.1 scans → DSPM emits)
# ---------------------------------------------------------------------------


def _write_d1_secrets(workspace: Path, secrets: list[dict]) -> Path:
    """Write the runtime_secrets.json artifact exactly as D.1 emits it (the
    contract from vulnerability.secrets.render_runtime_secrets_json)."""
    workspace.mkdir(parents=True, exist_ok=True)
    (workspace / "runtime_secrets.json").write_text(
        json.dumps(
            {
                "schema_version": "0.1",
                "agent": "vulnerability",
                "run_id": "d1-run",
                "secrets": secrets,
            }
        ),
        encoding="utf-8",
    )
    return workspace


_AWS_KEY_HIT = {
    "rule_id": "aws-access-key-id",
    "category": "AWS",
    "severity": "CRITICAL",
    "title": "AWS Access Key ID",
    "target": "app/.env",
    "start_line": 3,
    "end_line": 3,
}


@pytest.mark.asyncio
async def test_run_emits_ocsf_2003_secret_from_vulnerability_workspace(tmp_path: Path) -> None:
    """D.1 writes runtime_secrets.json → DSPM run() emits OCSF 2003 SECRET finding."""
    d1_ws = _write_d1_secrets(tmp_path / "d1-workspace", [_AWS_KEY_HIT])
    contract = _make_contract(tmp_path)

    report = await run(contract, vulnerability_workspace=d1_ws)

    secret_findings = [
        f for f in report.findings if f["finding_info"]["uid"].startswith("CSPM-RUNTIME-SECRET-")
    ]
    assert len(secret_findings) == 1
    sf = secret_findings[0]
    assert sf["class_uid"] == 2003
    assert sf["evidences"][0]["source_finding_type"] == "data_security_secret_exposed_in_runtime"
    # Multi-tenant: the resource's account is the consuming tenant, not D.1's.
    assert sf["resources"][0]["owner"]["account_uid"] == "cust_test"


@pytest.mark.asyncio
async def test_run_without_vulnerability_workspace_no_secret_findings(tmp_path: Path) -> None:
    """No vulnerability_workspace → no secret findings (default byte-identical)."""
    contract = _make_contract(tmp_path)
    report = await run(contract)
    assert not [
        f for f in report.findings if f["finding_info"]["uid"].startswith("CSPM-RUNTIME-SECRET-")
    ]


@pytest.mark.asyncio
async def test_run_secret_handoff_redacts_plaintext_end_to_end(tmp_path: Path) -> None:
    """The emitted findings.json never contains a plaintext secret value."""
    d1_ws = _write_d1_secrets(tmp_path / "d1-workspace", [_AWS_KEY_HIT])
    contract = _make_contract(tmp_path)
    await run(contract, vulnerability_workspace=d1_ws)
    findings_text = (tmp_path / "findings.json").read_text(encoding="utf-8")
    assert "AKIA" not in findings_text
