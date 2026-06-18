"""Compliance correlators (D.9 v0.1, Stage 3 CORRELATE).

Two correlators ship in v0.1, one per sibling-agent integration:

- :mod:`compliance.correlators.cloud_posture_correlator` — maps
  F.3 Cloud Posture findings (``CSPM-AWS-*`` rule ids) to the bundled
  CIS controls. Emits per-mapping ComplianceFinding with status
  carried; Task 8 aggregator collapses to per-control roll-up.
- :mod:`compliance.correlators.data_security_correlator` — maps
  D.5 Data Security findings (``data_security_*`` discriminator) to
  the bundled CIS controls. Same per-mapping emit shape.

Per ADR-005 the per-correlator sibling-workspace reads happen on
``asyncio.to_thread`` so the agent driver (Task 11) can fan them
out via ``asyncio.TaskGroup``.
"""

from __future__ import annotations
