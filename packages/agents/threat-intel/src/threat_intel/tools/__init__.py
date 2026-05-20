"""Filesystem-mode feed clients for the D.8 Threat Intel agent.

v0.1 clients consume operator-staged JSON snapshots of public threat-
intel feeds (NVD CVE 2.0, CISA KEV, MITRE ATT&CK STIX 2.1). Live HTTP
polling lands in D.8 v0.2 behind the same async wrapper signatures
per the shim-behind-reader pattern (mirrors F.3 / multi-cloud-posture).
"""

from __future__ import annotations

from threat_intel.tools.cisa_kev import (
    CisaKevReaderError,
    KevEntry,
    read_cisa_kev,
)
from threat_intel.tools.nvd_feed import (
    NvdCveRecord,
    NvdFeedReaderError,
    read_nvd_feed,
)

__all__ = [
    "CisaKevReaderError",
    "KevEntry",
    "NvdCveRecord",
    "NvdFeedReaderError",
    "read_cisa_kev",
    "read_nvd_feed",
]
