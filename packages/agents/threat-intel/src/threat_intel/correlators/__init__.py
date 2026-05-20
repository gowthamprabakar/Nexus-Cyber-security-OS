"""Threat-intel correlators (D.8 v0.1, Stage 3 CORRELATE).

Three correlators ship in v0.1, one per sibling-agent integration:

- :mod:`threat_intel.correlators.cve_correlator` — D.1 Vulnerability
  CVEs that also appear in CISA KEV (i.e., actively exploited). Emits
  ``threat_intel_cve_in_kev_catalog``.
- :mod:`threat_intel.correlators.ioc_correlator_network` — D.4 Network
  Threat findings whose evidence references an IOC in the v0.1 IOC
  index (post-Task 8). Emits ``threat_intel_ioc_match_network``.
- :mod:`threat_intel.correlators.ioc_correlator_runtime` — D.3 Runtime
  Threat findings whose evidence references an IOC in the v0.1 IOC
  index (post-Task 9). Emits ``threat_intel_ioc_match_runtime``.

Per ADR-005 the per-correlator sibling-workspace reads happen on
``asyncio.to_thread`` so the agent driver (Task 12) can fan them out
via ``asyncio.TaskGroup``.
"""

from __future__ import annotations
