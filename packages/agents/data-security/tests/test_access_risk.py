"""data-security v0.2 Task 15 — sensitive + over-permissive-access uplift tests (Q5/WI-S11)."""

from __future__ import annotations

import data_security.access_risk as mod
from data_security.access_risk import elevate_sensitive_with_access, escalate


def test_escalate_ladder() -> None:
    assert escalate("low") == "medium"
    assert escalate("medium") == "high"
    assert escalate("high") == "critical"


def test_escalate_critical_is_ceiling() -> None:
    assert escalate("critical") == "critical"


def test_escalate_unknown_starts_low() -> None:
    assert escalate("bogus") == "medium"  # treated as low -> medium


def test_elevated_when_in_both_sets() -> None:
    [f] = elevate_sensitive_with_access(
        sensitive_identifiers={"pii-bucket"},
        access_flagged_identifiers={"pii-bucket"},
        base_severities={"pii-bucket": "high"},
    )
    assert f.source == "pii-bucket"
    assert f.base_severity == "high" and f.elevated_severity == "critical"
    assert "over-permissive access" in f.reason


def test_not_elevated_when_only_sensitive() -> None:
    assert (
        elevate_sensitive_with_access(
            sensitive_identifiers={"pii"}, access_flagged_identifiers=set()
        )
        == ()
    )


def test_not_elevated_when_only_access() -> None:
    assert (
        elevate_sensitive_with_access(
            sensitive_identifiers=set(), access_flagged_identifiers={"role-x"}
        )
        == ()
    )


def test_default_base_severity_high() -> None:
    [f] = elevate_sensitive_with_access(
        sensitive_identifiers={"b"}, access_flagged_identifiers={"b"}
    )
    assert f.base_severity == "high" and f.elevated_severity == "critical"


def test_emit_only_no_enforcement_surface() -> None:
    # WI-S11 / Q5: advisory only — no IAM-modification / remediation function.
    for name in ("remediate", "modify_iam", "revoke", "enforce", "apply"):
        assert not hasattr(mod, name)
