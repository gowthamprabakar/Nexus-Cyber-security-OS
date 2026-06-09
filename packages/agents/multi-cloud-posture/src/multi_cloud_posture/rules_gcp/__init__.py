"""Native GCP rule engine (D.5 v0.2 Task 11).

New non-IAM CIS-GCP rules emitting OCSF 2003 tagged `Source: Nexus-native`
(`CSPMFindingType.GCP_NATIVE`), alongside the existing IAM-binding rules in
`tools/gcp_iam.py` (`GCP_IAM`). Q4: a starting CIS subset; full CIS = v0.3.
"""

from __future__ import annotations

from multi_cloud_posture.rules_gcp.cis_rules import GCP_CIS_RULES
from multi_cloud_posture.rules_gcp.engine import (
    PROVENANCE_NATIVE,
    GcpNativeRule,
    GcpResource,
    GcpRuleEngine,
)

__all__ = [
    "GCP_CIS_RULES",
    "PROVENANCE_NATIVE",
    "GcpNativeRule",
    "GcpResource",
    "GcpRuleEngine",
]
