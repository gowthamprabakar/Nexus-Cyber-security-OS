"""Nexus control plane — auth (Auth0 SSO/SCIM/RBAC/MFA) + tenant manager.

Per [F.4 plan](../../../../docs/superpowers/plans/2026-05-11-f-4-auth-tenant-manager.md).
The control plane hosts the auth layer; agents and edge plane consume
tenant identity but don't host the IdP.
"""

from __future__ import annotations

__version__ = "0.1.0"
