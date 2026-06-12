"""Code-level safety invariants for the remediation agent (v0.2, WI-A8..A18).

A.1 is the **only state-mutating agent**, so its 6 decision heuristics (H1-H6) are formalized here
as hard, reusable guard functions — plus 2 NEW action-specific invariants, the tool-proxy guard,
and the tenant guard. Each raises on violation; none is ever worked around. The institutional
safety-critical-agent pattern for future v0.3 host-* actions + cloud-native remediation.
"""
