"""Tests for `investigation.schemas` (D.7 Task 2) — OCSF v1.3 Incident Finding (class_uid 2005).

**Q1 resolution.** The D.7 plan said "ship under 2004 with `types[0]="incident"`,
but verify against the OCSF v1.3 spec at Task 4." On verification: OCSF v1.3
*does* have `2005 Incident Finding` (added in OCSF v1.2.0), purpose-built for
exactly D.7's output shape. **Corrected to class_uid 2005.**

Production contract — six pydantic models, all `frozen=True`,
`extra="forbid"`, JSON-round-tripping:

- `Hypothesis` — a single hypothesis with `evidence_refs` pointing at
  audit_event_id / finding_id values. `evidence_refs` validation
  happens at the synthesizer layer (Task 11); the schema only pins
  shape.
- `IocItem` — an indicator of compromise. Type ∈ {ipv4, ipv6, domain,
  url, sha256, sha1, md5, email, cve}. Value validated against the
  type's canonical regex.
- `MitreTechnique` — a MITRE ATT&CK technique reference with optional
  sub-technique. Tactic + technique IDs validated as ATT&CK v14.x.
- `TimelineEvent` — one row in the reconstructed timeline.
- `Timeline` — ordered tuple of `TimelineEvent`; deterministic sort by
  `emitted_at`.
- `IncidentReport` — the top-level wire shape. Class_uid 2005 in the
  OCSF envelope; carries the timeline + hypotheses + iocs + mitre
  refs + containment plan + a final `confidence` score.

Cross-agent OCSF inventory after D.7:

  F.3 Cloud Posture     → 2003 Compliance Finding
  D.1 Vulnerability     → 2002 Vulnerability Finding
  D.2 Identity          → 2004 Detection Finding
  D.3 Runtime Threat    → 2004 Detection Finding
  F.6 Audit Agent       → 6003 API Activity
  D.7 Investigation     → 2005 Incident Finding   ← NEW
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from investigation.schemas import (
    OCSF_ACTIVITY_INCIDENT_CREATE,
    OCSF_CATEGORY_NAME,
    OCSF_CATEGORY_UID,
    OCSF_CLASS_NAME,
    OCSF_CLASS_UID,
    OCSF_VERSION,
    Hypothesis,
    IncidentReport,
    IocItem,
    IocType,
    MitreTechnique,
    Timeline,
    TimelineEvent,
)
from pydantic import ValidationError

# ---------------------------- OCSF constants ----------------------------


def test_ocsf_constants_pin_incident_finding_class() -> None:
    """Plan-corrected from 2004 to 2005 at Task 2 verification."""
    assert OCSF_VERSION == "1.3.0"
    assert OCSF_CATEGORY_UID == 2
    assert OCSF_CATEGORY_NAME == "Findings"
    assert OCSF_CLASS_UID == 2005
    assert OCSF_CLASS_NAME == "Incident Finding"
    # OCSF activity_id 1 = "Create" (the canonical activity for a new
    # incident record); D.7 always emits "Create" in v0.1.
    assert OCSF_ACTIVITY_INCIDENT_CREATE == 1


# ---------------------------- Hypothesis --------------------------------


def test_hypothesis_round_trips_through_json() -> None:
    h = Hypothesis(
        hypothesis_id="H-001",
        statement="The attacker pivoted from the public S3 bucket to the EC2 instance via stolen IAM keys.",
        confidence=0.75,
        evidence_refs=("audit_event:42", "finding:F-1", "finding:F-2"),
    )
    restored = Hypothesis.model_validate_json(h.model_dump_json())
    assert restored == h


def test_hypothesis_is_frozen() -> None:
    h = Hypothesis(
        hypothesis_id="H-1",
        statement="x",
        confidence=0.5,
        evidence_refs=("audit_event:1",),
    )
    with pytest.raises(ValidationError):
        h.confidence = 0.9  # type: ignore[misc]


@pytest.mark.parametrize("bad_confidence", [-0.1, 1.01, 2.0])
def test_hypothesis_rejects_out_of_range_confidence(bad_confidence: float) -> None:
    with pytest.raises(ValidationError):
        Hypothesis(
            hypothesis_id="H-1",
            statement="x",
            confidence=bad_confidence,
            evidence_refs=("audit_event:1",),
        )


def test_hypothesis_rejects_empty_evidence_refs() -> None:
    """A hypothesis with zero evidence is a guess, not a hypothesis."""
    with pytest.raises(ValidationError):
        Hypothesis(
            hypothesis_id="H-1",
            statement="something happened",
            confidence=0.5,
            evidence_refs=(),
        )


# ---------------------------- IocItem -----------------------------------


@pytest.mark.parametrize(
    ("ioc_type", "value"),
    [
        (IocType.IPV4, "192.0.2.1"),
        (IocType.IPV6, "2001:db8::1"),
        (IocType.DOMAIN, "evil.example.com"),
        (IocType.URL, "https://evil.example.com/path"),
        (IocType.SHA256, "a" * 64),
        (IocType.SHA1, "b" * 40),
        (IocType.MD5, "c" * 32),
        (IocType.EMAIL, "attacker@evil.example.com"),
        (IocType.CVE, "CVE-2024-12345"),
    ],
)
def test_ioc_item_accepts_canonical_shapes(ioc_type: IocType, value: str) -> None:
    item = IocItem(type=ioc_type, value=value)
    assert item.type is ioc_type
    assert item.value == value


@pytest.mark.parametrize(
    ("ioc_type", "bad_value"),
    [
        (IocType.IPV4, "999.999.999.999"),
        (IocType.SHA256, "a" * 63),  # too short
        (IocType.SHA1, "z" * 40),  # non-hex
        (IocType.MD5, "c" * 31),  # too short
        (IocType.CVE, "cve-2024-1234"),  # lowercase rejected (canonical is uppercase CVE-)
    ],
)
def test_ioc_item_rejects_malformed_values(ioc_type: IocType, bad_value: str) -> None:
    with pytest.raises(ValidationError):
        IocItem(type=ioc_type, value=bad_value)


# ---------------------------- MitreTechnique ----------------------------


def test_mitre_technique_round_trips() -> None:
    t = MitreTechnique(
        technique_id="T1078",
        technique_name="Valid Accounts",
        tactic_id="TA0001",
        tactic_name="Initial Access",
        sub_technique_id="T1078.004",
        sub_technique_name="Cloud Accounts",
    )
    restored = MitreTechnique.model_validate_json(t.model_dump_json())
    assert restored == t


def test_mitre_technique_sub_technique_optional() -> None:
    t = MitreTechnique(
        technique_id="T1078",
        technique_name="Valid Accounts",
        tactic_id="TA0001",
        tactic_name="Initial Access",
    )
    assert t.sub_technique_id is None


@pytest.mark.parametrize("bad", ["1078", "T078", "TX1078", "T1078.x"])
def test_mitre_technique_rejects_malformed_technique_id(bad: str) -> None:
    with pytest.raises(ValidationError):
        MitreTechnique(
            technique_id=bad,
            technique_name="x",
            tactic_id="TA0001",
            tactic_name="y",
        )


@pytest.mark.parametrize("bad", ["1078.004", "TA1078", "T1078.0040"])
def test_mitre_technique_rejects_malformed_sub_technique_id(bad: str) -> None:
    with pytest.raises(ValidationError):
        MitreTechnique(
            technique_id="T1078",
            technique_name="x",
            tactic_id="TA0001",
            tactic_name="y",
            sub_technique_id=bad,
            sub_technique_name="z",
        )


# ---------------------------- Timeline ----------------------------------


def test_timeline_event_round_trips() -> None:
    e = TimelineEvent(
        emitted_at=datetime(2026, 5, 12, 12, 0, 0, tzinfo=UTC),
        source="audit",
        actor="cloud_posture",
        action="finding.created",
        evidence_ref="audit_event:42",
        description="S3 bucket made public",
    )
    restored = TimelineEvent.model_validate_json(e.model_dump_json())
    assert restored == e


def test_timeline_orders_events_by_emitted_at_ascending() -> None:
    base = datetime(2026, 5, 12, tzinfo=UTC)
    from datetime import timedelta

    e1 = _event(emitted_at=base, evidence_ref="audit_event:1")
    e2 = _event(emitted_at=base + timedelta(seconds=5), evidence_ref="audit_event:2")
    e3 = _event(emitted_at=base + timedelta(seconds=10), evidence_ref="audit_event:3")

    # Timeline construction sorts the provided events regardless of input order.
    out_of_order = Timeline(events=(e3, e1, e2))
    assert [e.emitted_at for e in out_of_order.events] == [
        e1.emitted_at,
        e2.emitted_at,
        e3.emitted_at,
    ]


def _event(*, emitted_at: datetime, evidence_ref: str) -> TimelineEvent:
    return TimelineEvent(
        emitted_at=emitted_at,
        source="audit",
        actor="cloud_posture",
        action="x",
        evidence_ref=evidence_ref,
        description="y",
    )


def test_timeline_empty_is_valid() -> None:
    assert Timeline(events=()).events == ()


# ---------------------------- IncidentReport ----------------------------


def _report(*, hypotheses: tuple[Hypothesis, ...] = ()) -> IncidentReport:
    return IncidentReport(
        incident_id="INC-001",
        tenant_id="01HV0T0000000000000000TENA",
        correlation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        timeline=Timeline(events=()),
        hypotheses=hypotheses,
        iocs=(),
        mitre_techniques=(),
        containment_summary="No action taken in test fixture.",
        confidence=0.5,
        emitted_at=datetime.now(UTC),
    )


def test_incident_report_round_trips() -> None:
    report = _report()
    restored = IncidentReport.model_validate_json(report.model_dump_json())
    assert restored == report


def test_incident_report_to_ocsf_carries_class_uid_2005() -> None:
    report = _report()
    ocsf = report.to_ocsf()
    assert ocsf["class_uid"] == 2005
    assert ocsf["class_name"] == "Incident Finding"
    assert ocsf["category_uid"] == 2
    assert ocsf["activity_id"] == OCSF_ACTIVITY_INCIDENT_CREATE
    assert ocsf["metadata"]["version"] == OCSF_VERSION
    # Investigation-specific fields ride in `unmapped` per the F.6 pattern.
    assert "timeline" in ocsf["unmapped"]
    assert "hypotheses" in ocsf["unmapped"]


def test_incident_report_aggregates_count_by_hypothesis_confidence() -> None:
    h_high = Hypothesis(hypothesis_id="H-1", statement="x", confidence=0.9, evidence_refs=("a:1",))
    h_med = Hypothesis(hypothesis_id="H-2", statement="y", confidence=0.6, evidence_refs=("a:2",))
    h_low = Hypothesis(hypothesis_id="H-3", statement="z", confidence=0.2, evidence_refs=("a:3",))
    report = _report(hypotheses=(h_high, h_med, h_low))
    assert report.count_hypotheses_by_confidence_bucket() == {
        "high": 1,  # >= 0.7
        "medium": 1,  # 0.4..0.7
        "low": 1,  # < 0.4
    }


def test_incident_report_rejects_invalid_tenant_id() -> None:
    with pytest.raises(ValidationError):
        IncidentReport(
            incident_id="INC-1",
            tenant_id="too-short",
            correlation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
            timeline=Timeline(events=()),
            hypotheses=(),
            iocs=(),
            mitre_techniques=(),
            containment_summary="",
            confidence=0.5,
            emitted_at=datetime.now(UTC),
        )


# ---------------------------- exports -----------------------------------


def test_module_all_exports_models_plus_constants() -> None:
    import investigation.schemas as schemas

    expected = {
        "Hypothesis",
        "IocItem",
        "IocType",
        "MitreTechnique",
        "Timeline",
        "TimelineEvent",
        "IncidentReport",
        "OCSF_CLASS_UID",
        "OCSF_CLASS_NAME",
        "OCSF_VERSION",
    }
    assert expected <= set(schemas.__all__)
