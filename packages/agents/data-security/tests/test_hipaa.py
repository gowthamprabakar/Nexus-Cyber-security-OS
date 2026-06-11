"""data-security v0.2 Task 13 — HIPAA Security Rule alignment tests (Q6)."""

from __future__ import annotations

from data_security.frameworks.hipaa import HipaaSection, map_hipaa
from data_security.tools.data_source import DataCloud, DataSource


def _src(identifier: str, *, public: bool = False, encrypted: bool = True) -> DataSource:
    return DataSource(
        cloud=DataCloud.AWS,
        identifier=identifier,
        region="us-east-1",
        is_public=public,
        is_encrypted=encrypted,
    )


def test_phi_always_audit_and_logging() -> None:
    findings = map_hipaa([_src("phi")], phi_bearing_identifiers={"phi"})
    sections = {f.section for f in findings}
    assert HipaaSection.AUDIT_CONTROLS in sections and HipaaSection.ACCESS_LOGGING in sections


def test_unencrypted_phi_encryption_critical() -> None:
    findings = map_hipaa([_src("phi", encrypted=False)], phi_bearing_identifiers={"phi"})
    [enc] = [f for f in findings if f.section == HipaaSection.ENCRYPTION]
    assert enc.severity == "critical"


def test_public_phi_access_control_critical() -> None:
    findings = map_hipaa([_src("phi", public=True)], phi_bearing_identifiers={"phi"})
    [ac] = [f for f in findings if f.section == HipaaSection.ACCESS_CONTROL]
    assert ac.severity == "critical"


def test_encrypted_private_only_verify_sections() -> None:
    findings = map_hipaa([_src("phi")], phi_bearing_identifiers={"phi"})
    assert {f.section for f in findings} == {
        HipaaSection.AUDIT_CONTROLS,
        HipaaSection.ACCESS_LOGGING,
    }


def test_public_unencrypted_all_four() -> None:
    findings = map_hipaa(
        [_src("phi", public=True, encrypted=False)], phi_bearing_identifiers={"phi"}
    )
    assert {f.section for f in findings} == set(HipaaSection)


def test_non_phi_skipped() -> None:
    assert map_hipaa([_src("logs")], phi_bearing_identifiers=set()) == ()


def test_section_values_are_hipaa_citations() -> None:
    assert HipaaSection.ENCRYPTION.value == "164.312(a)(2)(iv)"


def test_findings_metadata_only() -> None:
    [f, *_] = map_hipaa([_src("phi")], phi_bearing_identifiers={"phi"})
    assert set(type(f).__slots__) == {"section", "source", "severity", "message"}
