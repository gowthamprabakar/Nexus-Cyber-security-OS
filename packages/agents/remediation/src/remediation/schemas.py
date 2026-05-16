"""Remediation Agent schemas — OCSF v1.3 `class_uid 2007 Remediation Activity`.

A.1 is the **first producer** of OCSF class 2007 in the platform. Downstream
consumers (D.7 / fabric / Meta-Harness / S.1 console when shipped) subscribe to
this class to learn what the platform *did*, complementing class 2003
(Compliance Finding) which tells them what was *wrong*.

**Re-exports F.3's substrate** verbatim — `AffectedResource`, `Severity`,
`severity_to_id`, `OCSF_*` constants, `NexusEnvelope`, the `wrap_ocsf` /
`unwrap_ocsf` helpers. A.1 adds its own:

- `REM_FINDING_ID_RE` — `REM-K8S-NNN-<context>` (the analogue of F.3's
  `CSPM-<CLOUD>-<SVC>-NNN-<context>`).
- `RemediationActionType` enum — the 5 v0.1 action classes (one per D.6
  rule_id; one-to-one mapping documented at the class level).
- `RemediationMode` enum — `recommend` / `dry_run` / `execute`.
- `RemediationOutcome` enum — `recommended_only` / `dry_run_only` /
  `executed_validated` / `executed_rolled_back` / `refused_unauthorized` /
  `refused_blast_radius`.
- `RemediationArtifact` — the patch payload (target ref + JSON-merge-patch
  body + inverse-patch body for rollback).
- `RemediationFinding` typed wrapper over the OCSF 2007 payload.
- `build_remediation_finding` constructor (mirrors F.3's `build_finding`).
- `RemediationReport` aggregate (one per agent run).

The shape is **strictly disjoint** from F.3's `CloudPostureFinding`: a
remediation activity is not a finding, even though OCSF puts them in the
same category. Downstream filters on `class_uid` to route.
"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Any

from cloud_posture.schemas import (
    AffectedResource,
    Severity,
    severity_to_id,
)
from pydantic import BaseModel, Field
from shared.fabric.envelope import NexusEnvelope, unwrap_ocsf, wrap_ocsf

# ---------------------------- constants ------------------------------------

OCSF_VERSION = "1.3.0"
OCSF_CATEGORY_UID = 2  # Findings
OCSF_CATEGORY_NAME = "Findings"
OCSF_CLASS_UID = 2007  # Remediation Activity (per OCSF v1.3)
OCSF_CLASS_NAME = "Remediation Activity"
OCSF_ACTIVITY_REMEDIATE = 1  # Apply
OCSF_STATUS_NEW = 1

REM_FINDING_ID_RE = re.compile(r"^REM-[A-Z0-9]+-\d{3}-[a-z0-9_-]+$")


# ---------------------------- enums ----------------------------------------


class RemediationActionType(StrEnum):
    """The 5 v0.1 K8s-patch action classes (one per D.6 rule_id).

    Discriminator on `finding_info.types[0]`. Each value maps 1:1 to a D.6
    `rule_id` in the input findings.json (the mapping lives in
    `action_classes.ACTION_CLASS_REGISTRY` — Task 3).
    """

    K8S_PATCH_RUN_AS_NON_ROOT = "remediation_k8s_patch_runAsNonRoot"
    K8S_PATCH_RESOURCE_LIMITS = "remediation_k8s_patch_resource_limits"
    K8S_PATCH_READ_ONLY_ROOT_FS = "remediation_k8s_patch_readOnlyRootFilesystem"
    K8S_PATCH_IMAGE_PULL_POLICY_ALWAYS = "remediation_k8s_patch_imagePullPolicy_Always"
    K8S_PATCH_DISABLE_PRIVILEGE_ESCALATION = "remediation_k8s_patch_disable_privilege_escalation"


class RemediationMode(StrEnum):
    """The three operational modes. Default is `recommend` (lowest blast radius)."""

    RECOMMEND = "recommend"
    DRY_RUN = "dry_run"
    EXECUTE = "execute"


class RemediationOutcome(StrEnum):
    """The outcome of one action attempt (one OCSF 2007 record per attempt)."""

    RECOMMENDED_ONLY = "recommended_only"  # `recommend` mode — artifact built; no execution
    DRY_RUN_ONLY = "dry_run_only"  # `dry_run` mode — kubectl --dry-run=server succeeded
    EXECUTED_VALIDATED = "executed_validated"  # `execute` + post-validate confirmed fix
    EXECUTED_ROLLED_BACK = (
        "executed_rolled_back"  # `execute` + post-validate failed; inverse applied
    )
    REFUSED_UNAUTHORIZED = "refused_unauthorized"  # action class not in contract allowlist
    REFUSED_BLAST_RADIUS = "refused_blast_radius"  # would exceed max_actions_per_run
    DRY_RUN_FAILED = "dry_run_failed"  # kubectl --dry-run=server returned non-zero
    EXECUTE_FAILED = "execute_failed"  # kubectl apply returned non-zero (before validation)


_OUTCOME_TO_SEVERITY: dict[RemediationOutcome, Severity] = {
    # An action that succeeded is INFO (informational, not a problem).
    RemediationOutcome.RECOMMENDED_ONLY: Severity.INFO,
    RemediationOutcome.DRY_RUN_ONLY: Severity.INFO,
    RemediationOutcome.EXECUTED_VALIDATED: Severity.INFO,
    # Rollbacks + refusals are MEDIUM — operator should know.
    RemediationOutcome.EXECUTED_ROLLED_BACK: Severity.MEDIUM,
    RemediationOutcome.REFUSED_UNAUTHORIZED: Severity.MEDIUM,
    RemediationOutcome.REFUSED_BLAST_RADIUS: Severity.MEDIUM,
    # Failures are HIGH — something's wrong with our apply path.
    RemediationOutcome.DRY_RUN_FAILED: Severity.HIGH,
    RemediationOutcome.EXECUTE_FAILED: Severity.HIGH,
}


def outcome_severity(outcome: RemediationOutcome) -> Severity:
    """Map a `RemediationOutcome` to the OCSF severity reported on the record."""
    return _OUTCOME_TO_SEVERITY[outcome]


# ---------------------------- artifact -------------------------------------


class RemediationArtifact(BaseModel):
    """A patch payload generated by an action class.

    The artifact is **everything needed** to apply the fix and to roll it
    back: the K8s resource reference, the JSON-merge-patch body, and the
    inverse patch (applied during rollback when post-validation fails).
    """

    action_type: RemediationActionType
    # K8s target reference (RFC 6901-style for kubectl patch).
    api_version: str = Field(min_length=1)
    kind: str = Field(min_length=1)
    namespace: str = Field(min_length=1)
    name: str = Field(min_length=1)
    # The fix and its inverse — both JSON-merge-patch (RFC 7396) by default.
    patch_strategy: str = Field(default="strategic")  # `strategic` | `merge` | `json`
    patch_body: dict[str, Any]
    inverse_patch_body: dict[str, Any]
    # Lineage — links back to the source finding that triggered this artifact.
    source_finding_uid: str = Field(min_length=1)
    # Idempotency key — same source finding → same correlation_id → same artifact.
    correlation_id: str = Field(min_length=1)


# ---------------------------- typed OCSF wrapper ---------------------------


class RemediationFinding:
    """Typed wrapper over a wrapped OCSF v1.3 Remediation Activity dict.

    Construction validates that the payload is `class_uid 2007`, has a
    valid `finding_info.uid` matching `REM_FINDING_ID_RE`, and carries a
    well-formed `nexus_envelope`. The full wrapped payload is preserved
    for emission.
    """

    def __init__(self, payload: dict[str, Any]) -> None:
        if payload.get("class_uid") != OCSF_CLASS_UID:
            raise ValueError(
                f"expected OCSF class_uid={OCSF_CLASS_UID}, got {payload.get('class_uid')!r}"
            )
        finding_id = payload.get("finding_info", {}).get("uid", "")
        if not REM_FINDING_ID_RE.match(finding_id):
            raise ValueError(
                f"finding_id must match {REM_FINDING_ID_RE.pattern} (got {finding_id!r})"
            )
        # unwrap_ocsf raises if nexus_envelope is missing or malformed.
        unwrap_ocsf(payload)
        self._payload = payload

    @property
    def finding_id(self) -> str:
        return str(self._payload["finding_info"]["uid"])

    @property
    def action_type(self) -> RemediationActionType:
        types = self._payload["finding_info"].get("types") or []
        if not types:
            raise ValueError("RemediationFinding payload is missing finding_info.types[0]")
        return RemediationActionType(types[0])

    @property
    def outcome(self) -> RemediationOutcome:
        return RemediationOutcome(self._payload["finding_info"]["analytic"]["name"])

    @property
    def severity(self) -> Severity:
        from cloud_posture.schemas import severity_from_id

        return severity_from_id(int(self._payload["severity_id"]))

    @property
    def envelope(self) -> NexusEnvelope:
        _, env = unwrap_ocsf(self._payload)
        return env

    @property
    def resources(self) -> list[dict[str, Any]]:
        return list(self._payload.get("resources", []))

    def to_dict(self) -> dict[str, Any]:
        return dict(self._payload)


# ---------------------------- constructor ----------------------------------


def build_remediation_finding(
    *,
    finding_id: str,
    action_type: RemediationActionType,
    outcome: RemediationOutcome,
    title: str,
    description: str,
    affected: list[AffectedResource],
    detected_at: Any,  # datetime — typing kept loose to match cloud_posture.build_finding
    envelope: NexusEnvelope,
    artifact: RemediationArtifact | None = None,
    evidence: dict[str, Any] | None = None,
) -> RemediationFinding:
    """Build a Nexus OCSF v1.3 Remediation Activity wrapped with a NexusEnvelope.

    `finding_id` must match `REM_FINDING_ID_RE` (`REM-<TARGET>-NNN-<context>`).
    `affected` must contain at least one resource.
    `artifact` is included in the evidence list when supplied (so operators
    can see the patch payload + inverse + lineage in `findings.json`).
    """
    if not REM_FINDING_ID_RE.match(finding_id):
        raise ValueError(f"finding_id must match {REM_FINDING_ID_RE.pattern} (got {finding_id!r})")
    if not affected:
        raise ValueError("affected resources list must not be empty")

    severity = outcome_severity(outcome)
    timestamp_ms = int(detected_at.timestamp() * 1000)
    evidences: list[dict[str, Any]] = []
    if evidence is not None:
        evidences.append(evidence)
    if artifact is not None:
        evidences.append(
            {
                "kind": "remediation-artifact",
                "action_type": artifact.action_type.value,
                "patch_strategy": artifact.patch_strategy,
                "patch_body": artifact.patch_body,
                "inverse_patch_body": artifact.inverse_patch_body,
                "source_finding_uid": artifact.source_finding_uid,
                "correlation_id": artifact.correlation_id,
                "target": {
                    "api_version": artifact.api_version,
                    "kind": artifact.kind,
                    "namespace": artifact.namespace,
                    "name": artifact.name,
                },
            }
        )

    payload: dict[str, Any] = {
        "category_uid": OCSF_CATEGORY_UID,
        "category_name": OCSF_CATEGORY_NAME,
        "class_uid": OCSF_CLASS_UID,
        "class_name": OCSF_CLASS_NAME,
        "activity_id": OCSF_ACTIVITY_REMEDIATE,
        "activity_name": "Apply",
        "type_uid": OCSF_CLASS_UID * 100 + OCSF_ACTIVITY_REMEDIATE,
        "type_name": f"{OCSF_CLASS_NAME}: Apply",
        "severity_id": severity_to_id(severity),
        "severity": severity.value.capitalize(),
        "time": timestamp_ms,
        "time_dt": detected_at.isoformat(),
        "status_id": OCSF_STATUS_NEW,
        "status": "New",
        "metadata": {
            "version": OCSF_VERSION,
            "product": {
                "name": "Nexus Remediation",
                "vendor_name": "Nexus Cyber OS",
            },
        },
        "finding_info": {
            "uid": finding_id,
            "title": title,
            "desc": description,
            "first_seen_time": timestamp_ms,
            "last_seen_time": timestamp_ms,
            "types": [action_type.value],
            # `analytic.name` carries the outcome; downstream consumers
            # filter on it without parsing evidence.
            "analytic": {"name": outcome.value},
        },
        "resources": [r.to_ocsf() for r in affected],
        "evidences": evidences,
    }
    wrapped = wrap_ocsf(payload, envelope)
    return RemediationFinding(wrapped)


# ---------------------------- aggregate report -----------------------------


class RemediationReport(BaseModel):
    """Aggregate report metadata produced by one agent run.

    `findings` stores raw wrapped OCSF dicts (one per RemediationFinding) so
    the report serializes cleanly to JSON without losing OCSF shape.
    """

    agent: str
    agent_version: str
    customer_id: str
    run_id: str
    mode: RemediationMode
    scan_started_at: Any  # datetime
    scan_completed_at: Any  # datetime
    findings: list[dict[str, Any]] = Field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.findings)

    def add_finding(self, f: RemediationFinding) -> None:
        self.findings.append(f.to_dict())

    def count_by_outcome(self) -> dict[str, int]:
        counts: dict[str, int] = dict.fromkeys((o.value for o in RemediationOutcome), 0)
        for raw in self.findings:
            try:
                outcome = raw["finding_info"]["analytic"]["name"]
            except (KeyError, TypeError):
                continue
            if outcome in counts:
                counts[outcome] += 1
        return counts


# ---------------------------- exports --------------------------------------

__all__ = [
    "OCSF_ACTIVITY_REMEDIATE",
    "OCSF_CATEGORY_NAME",
    "OCSF_CATEGORY_UID",
    "OCSF_CLASS_NAME",
    "OCSF_CLASS_UID",
    "OCSF_STATUS_NEW",
    "OCSF_VERSION",
    "REM_FINDING_ID_RE",
    "AffectedResource",
    "RemediationActionType",
    "RemediationArtifact",
    "RemediationFinding",
    "RemediationMode",
    "RemediationOutcome",
    "RemediationReport",
    "Severity",
    "build_remediation_finding",
    "outcome_severity",
]
