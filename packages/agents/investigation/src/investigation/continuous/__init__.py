"""Continuous-monitoring infrastructure for the investigation agent (v0.2, WI-I9).

INFRASTRUCTURE ONLY (Path 1): the scheduler decides WHEN each tenant is due for a re-run; it is
NOT wired into ``agent.run()``. Driving the production loop is the Phase C consolidated retrofit.
"""
