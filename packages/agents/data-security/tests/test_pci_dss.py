"""data-security v0.2 Task 12 — PCI-DSS framework alignment tests (Q6)."""

from __future__ import annotations

from data_security.frameworks.pci_dss import PciRequirement, map_pci_dss
from data_security.tools.data_source import DataCloud, DataSource


def _src(identifier: str, *, public: bool = False, encrypted: bool = True) -> DataSource:
    return DataSource(
        cloud=DataCloud.AWS,
        identifier=identifier,
        region="us-east-1",
        is_public=public,
        is_encrypted=encrypted,
    )


def test_pan_bearing_gets_req_10_2_always() -> None:
    findings = map_pci_dss([_src("cards")], pan_bearing_identifiers={"cards"})
    assert any(f.requirement == PciRequirement.REQ_10_2 for f in findings)


def test_unencrypted_pan_req_3_4_critical() -> None:
    findings = map_pci_dss([_src("cards", encrypted=False)], pan_bearing_identifiers={"cards"})
    [r34] = [f for f in findings if f.requirement == PciRequirement.REQ_3_4]
    assert r34.severity == "critical"


def test_public_pan_req_1_3_critical() -> None:
    findings = map_pci_dss([_src("cards", public=True)], pan_bearing_identifiers={"cards"})
    [r13] = [f for f in findings if f.requirement == PciRequirement.REQ_1_3]
    assert r13.severity == "critical"


def test_encrypted_private_only_req_10_2() -> None:
    findings = map_pci_dss([_src("cards")], pan_bearing_identifiers={"cards"})
    reqs = {f.requirement for f in findings}
    assert reqs == {PciRequirement.REQ_10_2}


def test_public_unencrypted_all_three() -> None:
    findings = map_pci_dss(
        [_src("cards", public=True, encrypted=False)], pan_bearing_identifiers={"cards"}
    )
    assert {f.requirement for f in findings} == {
        PciRequirement.REQ_1_3,
        PciRequirement.REQ_3_4,
        PciRequirement.REQ_10_2,
    }


def test_non_pan_source_skipped() -> None:
    assert map_pci_dss([_src("logs")], pan_bearing_identifiers=set()) == ()


def test_findings_metadata_only() -> None:
    [f, *_] = map_pci_dss([_src("cards")], pan_bearing_identifiers={"cards"})
    assert f.source == "cards"
    assert set(type(f).__slots__) == {"requirement", "source", "severity", "message"}
