"""Native Azure rule engine — evaluation + OCSF 2003 emission (D.5 v0.2 Task 10).

Resources are produced by the live Azure readers (`azure-mgmt`) when they land;
the engine + rules are **pure** and tested offline with mock resources. Each
violation emits a finding tagged `Source: Nexus-native`
(`CSPMFindingType.AZURE_NATIVE`) — Nexus detecting, not Defender re-formatting.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from shared.fabric.envelope import NexusEnvelope

from multi_cloud_posture.schemas import (
    AffectedResource,
    CloudPostureFinding,
    CSPMFindingType,
    Severity,
    build_finding,
    short_resource_token,
)

#: Provenance tag carried in evidence for natively-detected findings (Q7/WI-D2).
PROVENANCE_NATIVE = "Nexus-native"


@dataclass(frozen=True)
class AzureResource:
    """A normalized Azure resource config the native rules inspect."""

    resource_type: str
    resource_id: str
    subscription_id: str
    region: str
    properties: dict[str, Any]


@dataclass(frozen=True)
class AzureNativeRule:
    """A single native CIS-Azure rule: a pure predicate over an `AzureResource`."""

    rule_id: str
    title: str
    description: str
    severity: Severity
    resource_type: str
    is_violation: Callable[[AzureResource], bool]


def _native_finding_id(seq: int, resource_id: str) -> str:
    slug = short_resource_token(resource_id).lower() or "unknown"
    return f"CSPM-AZURE-NATIVE-{seq:03d}-{slug}"


class AzureRuleEngine:
    """Holds the native rules and evaluates resources into OCSF 2003 findings."""

    def __init__(self, rules: Sequence[AzureNativeRule]) -> None:
        self._rules = tuple(rules)

    @property
    def rule_count(self) -> int:
        return len(self._rules)

    def evaluate(
        self,
        resources: Iterable[AzureResource],
        *,
        envelope: NexusEnvelope,
        scan_time: datetime,
    ) -> list[CloudPostureFinding]:
        findings: list[CloudPostureFinding] = []
        seq = 0
        for resource in resources:
            for rule in self._rules:
                if rule.resource_type != resource.resource_type:
                    continue
                if not rule.is_violation(resource):
                    continue
                seq += 1
                findings.append(self._build(rule, resource, seq, envelope, scan_time))
        return findings

    def _build(
        self,
        rule: AzureNativeRule,
        resource: AzureResource,
        seq: int,
        envelope: NexusEnvelope,
        scan_time: datetime,
    ) -> CloudPostureFinding:
        affected = [
            AffectedResource(
                cloud="azure",
                account_id=resource.subscription_id or "unknown",
                region=resource.region or "global",
                resource_type=resource.resource_type,
                resource_id=resource.resource_id,
                arn=resource.resource_id,
            )
        ]
        return build_finding(
            finding_id=_native_finding_id(seq, resource.resource_id),
            rule_id=rule.rule_id,
            severity=rule.severity,
            title=rule.title,
            description=rule.description,
            affected=affected,
            detected_at=scan_time,
            envelope=envelope,
            evidence={
                "source_finding_type": CSPMFindingType.AZURE_NATIVE.value,
                "provenance": PROVENANCE_NATIVE,
                "resource_type": resource.resource_type,
            },
        )
