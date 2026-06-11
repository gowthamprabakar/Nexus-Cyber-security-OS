"""Runtime posture rules (D.6 v0.2 Task 10).

Evaluates the enumerated runtime state (Task 9) against a set of **runtime posture rules**
— privileged containers, hostNetwork/hostPID, run-as-root, dangerous capabilities,
privilege escalation, missing security contexts — producing typed `RuntimeViolation`s for
downstream OCSF 2003 emission. Pure + deterministic.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from k8s_posture.runtime.enumerate import PodState

#: Linux capabilities whose addition is a notable posture risk.
DANGEROUS_CAPABILITIES = frozenset({"ALL", "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE"})


@dataclass(frozen=True, slots=True)
class RuntimeViolation:
    rule_id: str
    severity: str
    namespace: str
    pod: str
    container: str
    message: str


def evaluate_runtime_posture(pods: Sequence[PodState]) -> tuple[RuntimeViolation, ...]:
    """Evaluate runtime posture rules over the enumerated pods → violations."""
    out: list[RuntimeViolation] = []
    for pod in pods:
        if pod.host_network:
            out.append(
                RuntimeViolation(
                    "host-network", "high", pod.namespace, pod.name, "", "pod uses hostNetwork"
                )
            )
        if pod.host_pid:
            out.append(
                RuntimeViolation(
                    "host-pid", "high", pod.namespace, pod.name, "", "pod uses hostPID"
                )
            )
        for c in pod.containers:
            if c.privileged:
                out.append(
                    RuntimeViolation(
                        "privileged-container",
                        "critical",
                        pod.namespace,
                        pod.name,
                        c.name,
                        "privileged container",
                    )
                )
            if c.run_as_user == 0:
                out.append(
                    RuntimeViolation(
                        "run-as-root",
                        "high",
                        pod.namespace,
                        pod.name,
                        c.name,
                        "container runs as UID 0",
                    )
                )
            elif c.run_as_user is None:
                out.append(
                    RuntimeViolation(
                        "missing-run-as-user",
                        "low",
                        pod.namespace,
                        pod.name,
                        c.name,
                        "no runAsUser set (may run as root)",
                    )
                )
            dangerous = sorted(set(c.added_capabilities) & DANGEROUS_CAPABILITIES)
            if dangerous:
                out.append(
                    RuntimeViolation(
                        "dangerous-capabilities",
                        "high",
                        pod.namespace,
                        pod.name,
                        c.name,
                        f"added capabilities: {', '.join(dangerous)}",
                    )
                )
            if c.allow_privilege_escalation:
                out.append(
                    RuntimeViolation(
                        "privilege-escalation",
                        "medium",
                        pod.namespace,
                        pod.name,
                        c.name,
                        "allowPrivilegeEscalation is true",
                    )
                )
            if not c.read_only_root_fs:
                out.append(
                    RuntimeViolation(
                        "writable-root-fs",
                        "low",
                        pod.namespace,
                        pod.name,
                        c.name,
                        "root filesystem is writable",
                    )
                )
    return tuple(out)
