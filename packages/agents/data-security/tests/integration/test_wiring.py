"""Fleet Test Level 1 — data-security (D.5 / DSPM) wiring smoke.

Tier A: writes the graph + emits OCSF findings → the full §2.3 wiring assertions, copying the
two reference harnesses (cloud-posture + runtime-threat).

L1 is SMOKE, not capability — it proves the plumbing (run completes, kg_writer writes, OCSF
valid, tenant isolated, audit chain clean, inert offline). It does NOT measure precision/recall
or assert "the agent found the right violation" — that is L2 (v2 directive §3).

PRIVACY (Q6): the agent's classifier returns a ``ClassifierLabel`` enum only — never the matched
substring — so the seeded SSN sample below cannot reach findings/evidence/graph. We seed via the
agent's own unit-test feed fixtures (public bucket inventory + a PII object sample) so the data
conforms to the categorical-only privacy contract.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

import pytest
from charter.memory.graph_types import NodeCategory
from data_security.agent import run
from fleet_testkit import (
    assert_audit_chain,
    assert_entity_written,
    assert_no_entities,
    assert_ocsf_valid,
    assert_two_tenant_disjoint,
    in_memory_semantic_store,
    wiring_contract,
)

_PERMITTED = [
    "read_s3_inventory",
    "read_s3_objects",
    "read_f3_findings",
    "scan_s3_live",
    "scan_dynamodb",
    "scan_rds_posture",
]
_CATEGORIES = (NodeCategory.CLOUD_RESOURCE, NodeCategory.DATA_CLASSIFICATION)
_OCSF_CLASS = 2003  # Compliance Finding (data_security.schemas, F.3 wire shape)


def _public_bucket_dict(name: str = "alpha") -> dict[str, Any]:
    """A public, classifier-tagged S3 bucket (reused from test_agent.py unit fixtures)."""
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


def _seed_feeds(workspace: Path) -> tuple[Path, Path]:
    """Write the agent's two JSON ingest feeds: a public bucket + a PII object sample.

    The SSN below is a synthetic fixture; the classifier returns only the ``ssn``
    ``ClassifierLabel`` (Q6 categorical-only), so the plaintext never reaches the graph or
    findings — exercising both the storage node and the data-classification node.
    """
    workspace.mkdir(parents=True, exist_ok=True)
    inventory_path = workspace / "inventory.json"
    inventory_path.write_text(
        json.dumps({"buckets": [_public_bucket_dict("alpha")]}), encoding="utf-8"
    )
    objects_path = workspace / "objects.json"
    pii_sample = base64.b64encode(b"name,ssn\nbob,123-45-6789").decode("ascii")
    objects_path.write_text(
        json.dumps(
            {"objects": [{"bucket": "alpha", "key": "data.csv", "content_sample_b64": pii_sample}]}
        ),
        encoding="utf-8",
    )
    return inventory_path, objects_path


def _contract(tmp_path: Path, **kwargs: Any) -> Any:
    """Build the L1 wiring contract, fixing ``required_outputs`` to D.5's actual outputs.

    The shared ``wiring_contract`` hardcodes ``["findings.json", "summary.md"]`` (the
    cloud-posture / runtime-threat convention), but D.5 writes ``findings.json`` +
    ``report.md``. ``Charter.assert_complete`` validates against ``contract.required_outputs``,
    so the contract must name the files the agent actually produces (matches the agent's own
    unit-test contract).
    """
    contract = wiring_contract(tmp_path, target_agent="data_security", **kwargs)
    return contract.model_copy(update={"required_outputs": ["findings.json", "report.md"]})


def _findings(workspace: Path) -> list[dict[str, Any]]:
    payload = json.loads((workspace / "findings.json").read_text())
    return list(payload["findings"])


@pytest.mark.asyncio
async def test_wiring_data_security(tmp_path: Path) -> None:
    """Tier A full §2.3: run completes · OCSF 2003 valid · CLOUD_RESOURCE +
    DATA_CLASSIFICATION written · audit chain hash-verifies · tenant isolation."""
    async with in_memory_semantic_store() as store:
        # tenant A
        ws_a = tmp_path / "a"
        inventory_a, objects_a = _seed_feeds(ws_a / "feeds")
        contract_a = _contract(ws_a, permitted_tools=_PERMITTED, customer_id="tenant_a")
        report_a = await run(
            contract=contract_a,
            s3_inventory_feed=inventory_a,
            s3_objects_feed=objects_a,
            semantic_store=store,
        )

        # run-completes + produced findings
        assert report_a.total >= 1
        findings = _findings(ws_a / "ws")
        assert findings, "no findings emitted"

        # OCSF valid (every emitted finding)
        for finding in findings:
            assert_ocsf_valid(finding, class_uid=_OCSF_CLASS)

        # kg_writer wrote the expected ADR-018 node types
        await assert_entity_written(
            store, tenant_id="tenant_a", category=NodeCategory.CLOUD_RESOURCE
        )
        await assert_entity_written(
            store, tenant_id="tenant_a", category=NodeCategory.DATA_CLASSIFICATION
        )

        # audit chain hash-verifies
        assert_audit_chain(ws_a / "ws" / "audit.jsonl")

        # tenant isolation: same input under tenant_b → disjoint subgraph
        ws_b = tmp_path / "b"
        inventory_b, objects_b = _seed_feeds(ws_b / "feeds")
        contract_b = _contract(
            ws_b,
            permitted_tools=_PERMITTED,
            customer_id="tenant_b",
            delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHG0",
        )
        await run(
            contract=contract_b,
            s3_inventory_feed=inventory_b,
            s3_objects_feed=objects_b,
            semantic_store=store,
        )
        await assert_two_tenant_disjoint(
            store, tenant_a="tenant_a", tenant_b="tenant_b", categories=_CATEGORIES
        )


@pytest.mark.asyncio
async def test_wiring_data_security_inert_offline(tmp_path: Path) -> None:
    """No semantic_store → no graph writes; findings still emit (byte-identical offline)."""
    async with in_memory_semantic_store() as store:
        inventory, objects = _seed_feeds(tmp_path / "feeds")
        contract = _contract(tmp_path, permitted_tools=_PERMITTED, customer_id="t_off")
        report = await run(
            contract=contract,
            s3_inventory_feed=inventory,
            s3_objects_feed=objects,
            semantic_store=None,
        )
        assert report.total >= 1  # detection still runs offline
        # The injected store (unused by the run) stays empty — inert/byte-identical offline.
        await assert_no_entities(store, tenant_id="t_off", categories=_CATEGORIES)
