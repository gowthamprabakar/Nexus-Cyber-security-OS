"""Severity normalizer — three native scales → one internal `Severity` enum.

Each runtime sensor uses a different severity scale:

- **Falco**: 8-level priority string (Emergency / Alert / Critical / Error /
  Warning / Notice / Informational / Debug) — see
  [FALCO_PRIORITIES](tools/falco.py).
- **Tracee**: integer 0-3 inside `metadata.Severity` — see
  [TraceeAlert.severity](tools/tracee.py).
- **OSQuery**: no native severity; query-pack metadata supplies it as a
  caller-defined int that we map the same way as Tracee.

The three `<sensor>_to_severity()` functions return a value from the
canonical `runtime_threat.schemas.Severity` enum. The normalizer (Task
7) then calls `severity_to_id()` from `schemas` to land the OCSF
`severity_id` on each finding.

Unknown / out-of-range inputs fall back to `Severity.INFO` rather than
raising — runtime sensors evolve their schemas, and the agent must not
fail on a single anomalous alert.
"""

from __future__ import annotations

from runtime_threat.schemas import Severity

# Falco's 8 priority levels → internal Severity buckets.
_FALCO_PRIORITY_MAP: dict[str, Severity] = {
    "Emergency": Severity.CRITICAL,
    "Alert": Severity.CRITICAL,
    "Critical": Severity.CRITICAL,
    "Error": Severity.HIGH,
    "Warning": Severity.MEDIUM,
    "Notice": Severity.LOW,
    "Informational": Severity.INFO,
    "Debug": Severity.INFO,
}

# Tracee's 0-3 integer scale → internal Severity buckets.
# Tracee documents 3 as "the most severe" — we map it to CRITICAL.
_TRACEE_SEVERITY_MAP: dict[int, Severity] = {
    0: Severity.INFO,
    1: Severity.LOW,
    2: Severity.MEDIUM,
    3: Severity.CRITICAL,
}


def falco_to_severity(priority: str) -> Severity:
    """Map a Falco priority string to the internal `Severity` enum.

    Unknown / blank input → `Severity.INFO`.
    """
    return _FALCO_PRIORITY_MAP.get(priority, Severity.INFO)


def tracee_to_severity(value: int) -> Severity:
    """Map a Tracee `metadata.Severity` int (0-3) to the internal `Severity`.

    Out-of-range input → `Severity.INFO`.
    """
    return _TRACEE_SEVERITY_MAP.get(int(value), Severity.INFO)


def osquery_to_severity(value: int) -> Severity:
    """Map an OSQuery-pack-supplied int (0-3) to the internal `Severity`.

    Same scale as Tracee — query-pack authors specify severity per
    query, defaulting to 0 (info) when omitted.
    """
    return tracee_to_severity(value)


__all__ = [
    "falco_to_severity",
    "osquery_to_severity",
    "tracee_to_severity",
]
