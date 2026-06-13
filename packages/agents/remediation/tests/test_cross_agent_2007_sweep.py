"""remediation v0.2 Task 21 — cross-agent OCSF 2007 sweep (WI-A6).

A.1 is the **sole** OCSF 2007 (Remediation Activity) producer in the fleet — it *consumes* the
posture emitters' findings and *produces* the only remediation-activity records. This sweep pins
the sole-producer fact + the fleet OCSF emitter inventory after all 17 agents reach v0.2.
"""

from __future__ import annotations

from remediation.schemas import OCSF_CLASS_UID

#: The fleet OCSF emitter inventory at v0.2 completion (one class per producer role).
OCSF_EMITTER_INVENTORY = {
    2003: ("cloud_posture", "multi_cloud_posture", "k8s_posture", "compliance", "data_security"),
    2004: (
        "identity",
        "runtime_threat",
        "network_threat",
        "threat_intel",
        "synthesis",
        "curiosity",
    ),
    2005: ("investigation",),
    6003: ("audit",),
    2007: ("remediation",),
}


def test_remediation_is_sole_2007_producer() -> None:
    assert OCSF_CLASS_UID == 2007
    assert OCSF_EMITTER_INVENTORY[2007] == ("remediation",)


def test_remediation_consumes_not_emits_other_classes() -> None:
    # A.1 produces ONLY 2007; it does not appear under any other class.
    for class_uid, emitters in OCSF_EMITTER_INVENTORY.items():
        if class_uid != 2007:
            assert "remediation" not in emitters


def test_fleet_emitter_count() -> None:
    total = sum(len(v) for v in OCSF_EMITTER_INVENTORY.values())
    assert total == 14  # 5x2003 + 6x2004 + 1x2005 + 1x6003 + 1x2007
