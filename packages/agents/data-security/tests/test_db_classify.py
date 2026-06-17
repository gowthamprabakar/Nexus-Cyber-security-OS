"""v0.4 Stage 1.2 — DynamoDB content classification + RDS posture (moto backends).

Real AWS backends via moto: DynamoDB items are scanned + classified (labels only,
raw values never persisted — the Q6 privacy contract); RDS instances/clusters are
posture-checked (encryption / public / deletion-protection). Both → OCSF 2003.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import boto3
import pytest
from data_security.db_classify import dynamodb_to_findings, rds_to_findings
from data_security.schemas import DataSecurityFindingType
from data_security.tools.dynamodb_scan import scan_dynamodb
from data_security.tools.rds_scan import scan_rds_posture
from moto import mock_aws
from shared.fabric.envelope import NexusEnvelope

_SSN = "123-45-6789"
_EMAIL = "alice@example.com"
_REGION = "us-east-1"


def _envelope() -> NexusEnvelope:
    return NexusEnvelope(
        correlation_id="01HV0T0000000000000000CORR",
        tenant_id="01HV0T0000000000000000TEN1",
        agent_id="data_security",
        nlah_version="0.1.0",
        model_pin="deterministic",
        charter_invocation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
    )


# ---------------------------- DynamoDB -----------------------------------


@pytest.mark.asyncio
async def test_dynamodb_classifies_sensitive_data_labels_only() -> None:
    with mock_aws():
        client = boto3.client("dynamodb", region_name=_REGION)
        client.create_table(
            TableName="customers",
            KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        client.put_item(
            TableName="customers",
            Item={"pk": {"S": "1"}, "ssn": {"S": _SSN}, "email": {"S": _EMAIL}},
        )
        hits = await scan_dynamodb(account_id="123456789012", region=_REGION)

    assert hits == {"customers": ["email", "ssn"]}
    # privacy contract: raw values never returned by the scanner
    assert _SSN not in json.dumps(hits)
    assert _EMAIL not in json.dumps(hits)


@pytest.mark.asyncio
async def test_dynamodb_to_findings_emits_ocsf_2003_no_raw_values() -> None:
    findings = dynamodb_to_findings(
        {"customers": ["email", "ssn"]}, envelope=_envelope(), detected_at=datetime.now(UTC)
    )
    assert len(findings) == 1
    payload = findings[0].to_dict()
    assert payload["class_uid"] == 2003
    assert payload["evidences"][0]["source_finding_type"] == (
        DataSecurityFindingType.SENSITIVE_DATA_IN_DYNAMODB.value
    )
    assert payload["evidences"][0]["data_types"] == ["email", "ssn"]
    assert payload["severity"] == "High"  # ssn is high-risk
    # no raw value ever crosses into the finding
    assert _SSN not in json.dumps(payload)


@pytest.mark.asyncio
async def test_dynamodb_clean_table_yields_no_hits() -> None:
    with mock_aws():
        client = boto3.client("dynamodb", region_name=_REGION)
        client.create_table(
            TableName="config",
            KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        client.put_item(TableName="config", Item={"pk": {"S": "1"}, "flag": {"S": "enabled"}})
        hits = await scan_dynamodb(account_id="123456789012", region=_REGION)
    assert hits == {}


# ---------------------------- RDS posture --------------------------------


def _create_db(client: object, *, identifier: str, encrypted: bool, public: bool) -> None:
    client.create_db_instance(  # type: ignore[attr-defined]
        DBInstanceIdentifier=identifier,
        DBInstanceClass="db.t3.micro",
        Engine="postgres",
        AllocatedStorage=20,
        MasterUsername="admin",
        MasterUserPassword="correct-horse-battery",
        StorageEncrypted=encrypted,
        PubliclyAccessible=public,
        DeletionProtection=False,
    )


@pytest.mark.asyncio
async def test_rds_posture_flags_unencrypted_public_instance() -> None:
    with mock_aws():
        client = boto3.client("rds", region_name=_REGION)
        _create_db(client, identifier="prod-db", encrypted=False, public=True)
        records = await scan_rds_posture(account_id="123456789012", region=_REGION)

    assert len(records) == 1
    rec = records[0]
    assert rec["identifier"] == "prod-db"
    assert "storage_not_encrypted" in rec["violations"]
    assert "publicly_accessible" in rec["violations"]

    findings = rds_to_findings(records, envelope=_envelope(), detected_at=datetime.now(UTC))
    payload = findings[0].to_dict()
    assert payload["class_uid"] == 2003
    assert payload["evidences"][0]["source_finding_type"] == (
        DataSecurityFindingType.RDS_POSTURE_VIOLATION.value
    )
    assert payload["severity"] == "High"  # public + unencrypted


@pytest.mark.asyncio
async def test_rds_encrypted_private_instance_still_flags_deletion_protection() -> None:
    with mock_aws():
        client = boto3.client("rds", region_name=_REGION)
        _create_db(client, identifier="safe-db", encrypted=True, public=False)
        records = await scan_rds_posture(account_id="123456789012", region=_REGION)

    # encrypted + private but DeletionProtection=False → one MEDIUM violation
    assert len(records) == 1
    assert records[0]["violations"] == ["deletion_protection_disabled"]
    findings = rds_to_findings(records, envelope=_envelope(), detected_at=datetime.now(UTC))
    assert findings[0].to_dict()["severity"] == "Medium"
