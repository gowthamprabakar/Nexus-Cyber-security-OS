"""Tests — ``threat_intel.entities``.

Task 6 (entities half). Verifies the three pydantic entity models
that the kg_writer persists to SemanticStore.
"""

from __future__ import annotations

from datetime import UTC, date, datetime

import pytest
from threat_intel.entities import CveEntity, IocEntity, TechniqueEntity
from threat_intel.schemas import IocType

# ---------------------------------------------------------------------------
# IocEntity
# ---------------------------------------------------------------------------


def test_ioc_entity_external_id_encodes_type_and_value() -> None:
    ioc = IocEntity(
        ioc_type=IocType.IP,
        value="1.2.3.4",
        first_seen=datetime(2024, 1, 1, tzinfo=UTC),
        last_seen=datetime(2024, 1, 2, tzinfo=UTC),
        source_feed="abuse.ch",
    )
    assert ioc.external_id == "ip:1.2.3.4"


def test_ioc_entity_distinct_ids_across_types() -> None:
    """An IP and a hypothetical URL sharing the same string get distinct external_ids."""
    ip = IocEntity(
        ioc_type=IocType.IP,
        value="example",
        first_seen=datetime(2024, 1, 1, tzinfo=UTC),
        last_seen=datetime(2024, 1, 1, tzinfo=UTC),
        source_feed="x",
    )
    domain = IocEntity(
        ioc_type=IocType.DOMAIN,
        value="example",
        first_seen=datetime(2024, 1, 1, tzinfo=UTC),
        last_seen=datetime(2024, 1, 1, tzinfo=UTC),
        source_feed="x",
    )
    assert ip.external_id != domain.external_id


def test_ioc_entity_properties_roundtrip() -> None:
    ioc = IocEntity(
        ioc_type=IocType.DOMAIN,
        value="evil.example",
        first_seen=datetime(2024, 1, 1, tzinfo=UTC),
        last_seen=datetime(2024, 1, 2, tzinfo=UTC),
        confidence=0.9,
        source_feed="abuse.ch",
    )
    props = ioc.properties()
    assert props["ioc_type"] == "domain"
    assert props["value"] == "evil.example"
    assert props["confidence"] == 0.9
    assert props["source_feed"] == "abuse.ch"
    assert "first_seen" in props
    assert "last_seen" in props


def test_ioc_entity_confidence_default_is_0_5() -> None:
    ioc = IocEntity(
        ioc_type=IocType.IP,
        value="1.2.3.4",
        first_seen=datetime(2024, 1, 1, tzinfo=UTC),
        last_seen=datetime(2024, 1, 1, tzinfo=UTC),
        source_feed="x",
    )
    assert ioc.confidence == 0.5


def test_ioc_entity_confidence_clamped_to_unit_range() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        IocEntity(
            ioc_type=IocType.IP,
            value="1.2.3.4",
            first_seen=datetime(2024, 1, 1, tzinfo=UTC),
            last_seen=datetime(2024, 1, 1, tzinfo=UTC),
            confidence=1.5,
            source_feed="x",
        )


# ---------------------------------------------------------------------------
# CveEntity
# ---------------------------------------------------------------------------


def test_cve_entity_external_id_is_cve_id() -> None:
    cve = CveEntity(cve_id="CVE-2024-12345")
    assert cve.external_id == "CVE-2024-12345"


def test_cve_entity_default_kev_listed_false() -> None:
    cve = CveEntity(cve_id="CVE-2024-12345")
    assert cve.kev_listed is False
    assert cve.kev_added_date is None


def test_cve_entity_properties_roundtrip_with_kev() -> None:
    cve = CveEntity(
        cve_id="CVE-2024-12345",
        cvss_v3_score=9.8,
        cvss_v3_severity="CRITICAL",
        kev_listed=True,
        kev_added_date=date(2024, 1, 15),
        description="Critical RCE",
        affected_products=["acme-server"],
    )
    props = cve.properties()
    assert props["cve_id"] == "CVE-2024-12345"
    assert props["cvss_v3_score"] == 9.8
    assert props["cvss_v3_severity"] == "CRITICAL"
    assert props["kev_listed"] is True
    assert props["kev_added_date"] == "2024-01-15"
    assert props["affected_products"] == ["acme-server"]


def test_cve_entity_properties_kev_date_none_when_unlisted() -> None:
    cve = CveEntity(cve_id="CVE-2024-12345", kev_listed=False)
    props = cve.properties()
    assert props["kev_added_date"] is None


def test_cve_entity_cvss_score_clamped() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        CveEntity(cve_id="CVE-2024-12345", cvss_v3_score=11.0)


def test_cve_entity_epss_score_clamped() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        CveEntity(cve_id="CVE-2024-12345", epss_score=1.5)


# ---------------------------------------------------------------------------
# TechniqueEntity
# ---------------------------------------------------------------------------


def test_technique_entity_external_id_is_technique_id() -> None:
    t = TechniqueEntity(technique_id="T1059", name="Command Interpreter")
    assert t.external_id == "T1059"


def test_technique_entity_supports_subtechnique_id() -> None:
    t = TechniqueEntity(
        technique_id="T1059.003",
        name="Windows Command Shell",
        is_subtechnique=True,
    )
    assert t.external_id == "T1059.003"
    assert t.is_subtechnique is True


def test_technique_entity_properties_roundtrip() -> None:
    t = TechniqueEntity(
        technique_id="T1059",
        name="Command Interpreter",
        description="Adversaries may abuse command interpreters.",
        tactics=["execution"],
        platforms=["Linux", "Windows", "macOS"],
        url="https://attack.mitre.org/techniques/T1059",
    )
    props = t.properties()
    assert props["technique_id"] == "T1059"
    assert props["tactics"] == ["execution"]
    assert props["platforms"] == ["Linux", "Windows", "macOS"]
    assert props["url"] == "https://attack.mitre.org/techniques/T1059"
