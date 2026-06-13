"""Continuous-monitoring infrastructure for the remediation agent (v0.2, WI-A2).

INFRASTRUCTURE ONLY (Path 1): the scheduler decides WHEN each tenant is due for a re-run; it is
NOT wired into ``agent.run()``. Driving the production loop is the Phase C consolidated retrofit.
Crucially, continuous mode NEVER changes the default tier — a continuous run is still ``recommend``
unless the operator has opted into a higher tier via both auth layers (H1 preserved).
"""
