"""Native Azure rule engine (D.5 v0.2 Task 10).

Nexus DETECTS Azure misconfigurations natively (vs the Defender passthrough),
emitting OCSF 2003 findings tagged `Source: Nexus-native`
(`CSPMFindingType.AZURE_NATIVE`). Q4: a starting CIS-Azure subset; full CIS = v0.3.
"""

from __future__ import annotations

from multi_cloud_posture.rules_azure.cis_rules import AZURE_CIS_RULES
from multi_cloud_posture.rules_azure.engine import (
    PROVENANCE_NATIVE,
    AzureNativeRule,
    AzureResource,
    AzureRuleEngine,
)

__all__ = [
    "AZURE_CIS_RULES",
    "PROVENANCE_NATIVE",
    "AzureNativeRule",
    "AzureResource",
    "AzureRuleEngine",
]
