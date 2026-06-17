"""D.15 v0.2 Task 12 — Defender + SCC + native provenance tagging (Q7 / WI-D2)."""

from __future__ import annotations

from datetime import UTC, datetime

from multi_cloud_posture.rules_azure import AZURE_CIS_RULES, AzureResource, AzureRuleEngine
from multi_cloud_posture.schemas import CSPMFindingType, provenance_label
from multi_cloud_posture.summarizer import _cloud_and_source, render_summary
from shared.fabric.envelope import NexusEnvelope

NOW = datetime(2026, 6, 9, 12, 0, 0, tzinfo=UTC)


def _envelope() -> NexusEnvelope:
    return NexusEnvelope(
        correlation_id="corr",
        tenant_id="cust_test",
        agent_id="multi_cloud_posture@0.2.0",
        nlah_version="0.1.0",
        model_pin="deterministic",
        charter_invocation_id="inv",
    )


def test_provenance_label_mapping() -> None:
    assert provenance_label(CSPMFindingType.AZURE_DEFENDER) == "Microsoft Defender"
    assert provenance_label(CSPMFindingType.GCP_SCC) == "Google Security Command Center"
    assert provenance_label(CSPMFindingType.AZURE_NATIVE) == "Nexus-native"
    assert provenance_label(CSPMFindingType.GCP_NATIVE) == "Nexus-native"
    assert provenance_label(CSPMFindingType.GCP_IAM) == "Nexus-native"
    assert provenance_label(CSPMFindingType.AZURE_ACTIVITY) == "Azure Activity Log"


def test_label_defined_for_every_finding_type() -> None:
    # no source may be missing a customer-visible label.
    for ft in CSPMFindingType:
        assert isinstance(provenance_label(ft), str) and provenance_label(ft)


def _native_finding() -> object:
    engine = AzureRuleEngine(AZURE_CIS_RULES)
    findings = engine.evaluate(
        [
            AzureResource(
                resource_type="storage_account",
                resource_id="/subscriptions/s/r/x",
                subscription_id="sub",
                region="eastus",
                properties={"public_network_access": "Enabled"},
            )
        ],
        envelope=_envelope(),
        scan_time=NOW,
    )
    return findings[0]


def test_native_finding_carries_nexus_native_in_findings_json() -> None:
    doc = _native_finding().to_dict()
    assert doc["evidences"][0]["provenance"] == "Nexus-native"


def test_cloud_and_source_returns_friendly_provenance() -> None:
    cloud, source = _cloud_and_source(_native_finding())
    assert cloud == "azure"
    assert source == "Nexus-native"  # not the raw "cspm_azure_native"


def test_summary_surfaces_provenance_plainly() -> None:
    from multi_cloud_posture.schemas import FindingsReport

    report = FindingsReport(
        agent="multi_cloud_posture",
        agent_version="0.2.0",
        customer_id="cust_test",
        run_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        scan_started_at=NOW,
        scan_completed_at=NOW,
        findings=[_native_finding().to_dict()],
    )
    text = render_summary(report)
    assert "Source: Nexus-native" in text
