"""compliance v0.2 Task 2 — CIS-AWS real-rule wiring + no-fabrication guard (WI-C2).

Operator-confirmed honest-wiring decision (2026-06-11): a control wires ONLY to a source
rule a sibling agent actually emits. This test is the **drift guard** — every
`cloud_posture` mapping must reference one of F.3's real stable AWS rule ids, so future
edits can't silently fabricate coverage against rules that don't exist.
"""

from __future__ import annotations

from pathlib import Path

import yaml

# F.3 cloud-posture's stable, CIS-mappable AWS rule ids (ground-truthed from
# cloud_posture/agent.py _PROWLER_RULE_MAP + the hand-written IAM rules, 2026-06-11).
_REAL_CLOUD_POSTURE_AWS_RULES = {
    "CSPM-AWS-IAM-001",
    "CSPM-AWS-IAM-002",
    "CSPM-AWS-S3-001",
    "CSPM-AWS-S3-002",
    "CSPM-AWS-KMS-001",
    "CSPM-AWS-RDS-001",
    "CSPM-AWS-EC2-001",
}

_LIB = (
    Path(__file__).resolve().parents[1]
    / "src"
    / "compliance"
    / "control_libraries"
    / "cis_aws_v3.yaml"
)


def _controls() -> list[dict]:
    data = yaml.safe_load(_LIB.read_text(encoding="utf-8"))
    return [c for c in data["controls"] if isinstance(c, dict)]


def _mappings(control: dict) -> list[dict]:
    sm = control.get("source_mappings") or []
    return [m for m in sm if isinstance(m, dict)]


def test_every_cloud_posture_mapping_is_a_real_rule() -> None:
    """No fabricated coverage: every cloud_posture rule id is one F.3 actually emits."""
    for control in _controls():
        for m in _mappings(control):
            if m.get("source_agent") == "cloud_posture":
                assert m["source_rule_id"] in _REAL_CLOUD_POSTURE_AWS_RULES, (
                    f"control {control['control_id']} maps to non-emitted rule "
                    f"{m['source_rule_id']!r}"
                )


def test_newly_wired_controls_present() -> None:
    by_id = {c["control_id"]: c for c in _controls()}
    # Task 2 honest additions: default-SG (5.3) + open-ICMP (5.5) → open-SG detection.
    for cid in ("5.3", "5.5"):
        rules = {m["source_rule_id"] for m in _mappings(by_id[cid])}
        assert "CSPM-AWS-EC2-001" in rules, f"{cid} not wired to EC2-001"


def test_wired_count_increased() -> None:
    wired = [c for c in _controls() if _mappings(c)]
    # 12 wired at v0.1 entry + 2 honest additions (5.3, 5.5) = 14.
    assert len(wired) == 14


def test_unwired_controls_are_explicit_empty_not_fabricated() -> None:
    # Controls without a real emitter rule carry an explicit empty list (honest gap),
    # never a placeholder/fake mapping.
    for control in _controls():
        sm = control.get("source_mappings")
        assert sm == [] or all(isinstance(m, dict) and m.get("source_rule_id") for m in sm)
