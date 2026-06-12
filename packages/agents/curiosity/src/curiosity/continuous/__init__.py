"""Continuous-monitoring infrastructure for the curiosity agent (v0.2, WI-X2).

INFRASTRUCTURE ONLY (Path 1): the scheduler decides WHEN each tenant is due for a re-scan; it is
NOT wired into ``agent.run()``. Driving the production loop is the Phase C consolidated retrofit.
"""
