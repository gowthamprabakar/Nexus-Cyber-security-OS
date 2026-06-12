"""investigation v0.2 Task 12 — containment plan tests (Q5/H4/WI-I14)."""

from __future__ import annotations

import investigation.containment.plan as mod
from investigation.containment.plan import (
    ContainmentRecommendation,
    build_a1_handoff,
    order_containment,
)


def _r(action: str, target: str, severity: str) -> ContainmentRecommendation:
    return ContainmentRecommendation(
        action_type=action, target=target, severity=severity, rationale="x"
    )


def test_severity_ordering() -> None:
    recs = [_r("monitor", "a", "low"), _r("isolate_host", "b", "critical")]
    ordered = order_containment(recs)
    assert ordered[0].severity == "critical"


def test_h4_rotate_creds_before_isolate_within_severity() -> None:
    recs = [_r("isolate_host", "h1", "high"), _r("rotate_credentials", "k1", "high")]
    ordered = order_containment(recs)
    assert ordered[0].action_type == "rotate_credentials"


def test_handoff_is_advisory() -> None:
    bundle = build_a1_handoff([_r("rotate_credentials", "k1", "critical")])
    assert bundle["advisory"] is True and bundle["enforced"] is False
    assert bundle["recommendations"][0]["action_type"] == "rotate_credentials"


def test_handoff_ordered() -> None:
    bundle = build_a1_handoff(
        [_r("monitor", "a", "low"), _r("rotate_credentials", "k", "critical")]
    )
    assert bundle["recommendations"][0]["severity"] == "critical"


def test_empty() -> None:
    assert order_containment([]) == () and build_a1_handoff([])["recommendations"] == []


def test_no_enforcement_surface() -> None:
    # WI-I14: D.7 is advisory — no enforce / apply / execute / dispatch / remediate surface.
    for name in ("enforce", "apply", "execute", "dispatch", "remediate", "rotate", "isolate"):
        assert not hasattr(mod, name)
