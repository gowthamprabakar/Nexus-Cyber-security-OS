"""curiosity v0.2 Task 19 — cross-agent OCSF 2004 sweep (WI-X7).

D.12 joins as the **6th OCSF 2004 (Detection Finding) emitter** in the fleet
(D.2/D.3/D.4/D.8/D.13 + D.12). It is *additive*: the claims.> CuriosityClaim envelope continues
alongside the new OCSF 2004 emission (WI-X6).
"""

from __future__ import annotations

from curiosity.ocsf.schema import OCSF_CLASS_UID

#: The six OCSF 2004 emitters fleet-wide after D.12 v0.2.
OCSF_2004_EMITTERS = (
    "identity",  # D.2
    "runtime_threat",  # D.3
    "network_threat",  # D.4
    "threat_intel",  # D.8
    "synthesis",  # D.13
    "curiosity",  # D.12 (this cycle)
)


def test_curiosity_emits_2004() -> None:
    assert OCSF_CLASS_UID == 2004


def test_six_2004_emitters() -> None:
    assert len(OCSF_2004_EMITTERS) == 6
    assert "curiosity" in OCSF_2004_EMITTERS


def test_curiosity_is_the_newest_emitter() -> None:
    # D.12 is the 6th; D.7 (investigation) emits 2005, not 2004, so it is NOT in this set.
    assert "investigation" not in OCSF_2004_EMITTERS
