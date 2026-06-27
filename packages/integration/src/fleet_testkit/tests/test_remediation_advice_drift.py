"""Cross-package drift guard: every 'auto-fixable' attack-path claim names a REAL A.1 action.

The ranker's remediation advice (meta-harness) claims certain archetypes are auto-fixable by the
remediation agent (A.1). If A.1 renames or drops that action, the claim becomes a lie the customer
sees. This test ties the two packages together so that drift fails CI instead of shipping silently.
"""

from meta_harness.attack_path_remediation import REMEDIATION
from remediation.schemas import RemediationActionType


def test_auto_via_values_are_real_remediation_actions() -> None:
    real = {t.value for t in RemediationActionType}
    for path_type, advice in REMEDIATION.items():
        if advice.auto_fixable:
            assert advice.auto_via in real, (
                f"{path_type} claims auto-fix via {advice.auto_via!r}, which is not a real "
                f"RemediationActionType — A.1 changed and the advice is now wrong"
            )
        else:
            assert advice.auto_via == "", f"{path_type} is not auto-fixable but names an action"
