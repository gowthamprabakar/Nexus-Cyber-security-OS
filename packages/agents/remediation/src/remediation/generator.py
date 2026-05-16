"""`generate_artifacts` — Stage 3 of the 7-stage pipeline.

Pure function. Takes the (already-authz-filtered) findings from Stage 2
and produces the `RemediationArtifact` tuple Stage 4/5 will execute.

**Defense in depth.** The Stage-2 AUTHZ gate has already dropped findings
whose rule_id has no action class. The generator double-checks via
`lookup_action_class` and silently skips any unmapped finding — making
the function safe to call on any iterable, not just authz-filtered input.

The artifacts are produced via each action class's `build()` method
(which is itself pure). Determinism: feeding the same findings in the
same order always produces the same artifact tuple in the same order.
This is what powers the `correlation_id`-based idempotency: re-running
A.1 on the same input twice produces identical artifacts → kubectl
applies are no-ops on the second run (strategic-merge-patch is
idempotent under repeated identical patches).

**Lineage.** Each artifact's `source_finding_uid` is the source D.6
ManifestFinding's `rule_id` (the most stable identifier we have for a
finding before A.1 issues its own OCSF 2007 finding_id). The agent
driver (Task 12) overwrites this with the OCSF 2003 `finding_info.uid`
when it has access to the wrapped finding payload — the generator
only sees the un-wrapped `ManifestFinding` shape.
"""

from __future__ import annotations

from collections.abc import Iterable

from k8s_posture.tools.manifests import ManifestFinding

from remediation.action_classes import lookup_action_class
from remediation.schemas import RemediationArtifact


def generate_artifacts(
    findings: Iterable[ManifestFinding],
) -> tuple[RemediationArtifact, ...]:
    """Per finding, build the remediation artifact via the registered action class.

    Args:
        findings: Already-authz-filtered ManifestFinding records. Findings
            whose `rule_id` has no v0.1 action class are silently skipped
            (defense in depth — Stage 2 should have already dropped them).

    Returns:
        Tuple of `RemediationArtifact` records in the input order.
    """
    out: list[RemediationArtifact] = []
    for finding in findings:
        action_class = lookup_action_class(finding.rule_id)
        if action_class is None:
            continue
        out.append(action_class.build(finding))
    return tuple(out)


__all__ = ["generate_artifacts"]
