"""PCI-DSS framework alignment (data-security v0.2 Task 12, Q6).

Maps PAN-bearing data sources to PCI-DSS requirements — restrict public access to cardholder
data (Req 1.3), render PAN unreadable / encrypt at rest (Req 3.4), and verify access logging
(Req 10.2). Findings are metadata-only (source identifier + requirement + severity).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum

from data_security.tools.data_source import DataSource


class PciRequirement(StrEnum):
    REQ_1_3 = "req_1_3"  # restrict public access to cardholder data
    REQ_3_4 = "req_3_4"  # render PAN unreadable (encryption at rest)
    REQ_10_2 = "req_10_2"  # access logging


@dataclass(frozen=True, slots=True)
class PciFinding:
    requirement: PciRequirement
    source: str
    severity: str
    message: str


def map_pci_dss(
    sources: Sequence[DataSource], *, pan_bearing_identifiers: set[str]
) -> tuple[PciFinding, ...]:
    """Emit PCI-DSS findings for sources holding cardholder data (PAN)."""
    out: list[PciFinding] = []
    for s in sources:
        if s.identifier not in pan_bearing_identifiers:
            continue
        if s.is_public:
            out.append(
                PciFinding(
                    PciRequirement.REQ_1_3,
                    s.identifier,
                    "critical",
                    "cardholder data publicly accessible — PCI-DSS Req 1.3",
                )
            )
        if not s.is_encrypted:
            out.append(
                PciFinding(
                    PciRequirement.REQ_3_4,
                    s.identifier,
                    "critical",
                    "PAN not encrypted at rest — PCI-DSS Req 3.4",
                )
            )
        out.append(
            PciFinding(
                PciRequirement.REQ_10_2,
                s.identifier,
                "medium",
                "verify access logging on cardholder-data store — PCI-DSS Req 10.2",
            )
        )
    return tuple(out)
