"""D.6 v0.2 Task 7 — Polaris custom-policy support tests."""

from __future__ import annotations

from k8s_posture.polaris.custom_policy import (
    PolarisPolicy,
    PolicyOverlay,
    load_custom_policies,
    parse_custom_policies,
)

_CONTEXT = """---
industry: technology
polaris_policies:
  - check_id: runAsRootAllowed
    severity: danger
    enabled: true
  - check_id: hostNetworkSet
    enabled: false
---

# Customer
"""


def test_parse_custom_policies() -> None:
    policies = parse_custom_policies(
        [{"check_id": "a", "severity": "danger"}, {"check_id": "b"}, {"severity": "x"}]
    )
    assert [p.check_id for p in policies] == ["a", "b"]
    assert policies[0].severity == "danger" and policies[1].severity == "warning"


def test_load_from_context() -> None:
    policies = load_custom_policies(_CONTEXT)
    assert {p.check_id for p in policies} == {"runAsRootAllowed", "hostNetworkSet"}


def test_no_policies_returns_empty() -> None:
    assert load_custom_policies("# Customer\nno frontmatter\n") == ()
    assert load_custom_policies("---\nindustry: tech\n---\n") == ()


def test_overlay_is_enabled() -> None:
    overlay = PolicyOverlay(load_custom_policies(_CONTEXT))
    assert overlay.is_enabled("runAsRootAllowed") is True
    assert overlay.is_enabled("hostNetworkSet") is False  # explicitly disabled


def test_overlay_default_when_unknown() -> None:
    overlay = PolicyOverlay()
    assert overlay.is_enabled("anything", default=True) is True
    assert overlay.is_enabled("anything", default=False) is False


def test_overlay_severity() -> None:
    overlay = PolicyOverlay((PolarisPolicy("c", "danger"),))
    assert overlay.severity_for("c", default="warning") == "danger"
    assert overlay.severity_for("other", default="warning") == "warning"


def test_empty_overlay_preserves_defaults() -> None:
    # Additive: no custom policies → defaults preserved.
    overlay = PolicyOverlay()
    assert overlay.severity_for("x", default="danger") == "danger"
