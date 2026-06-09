"""Nexus Identity Agent — CIEM (Cloud Infrastructure Entitlement Management) for AWS.

Agent #3 of 18. Second consumer of ADR-007 v1.1 (the LLM-adapter hoist).
Imports `from charter.llm_adapter import ...` directly; ships no per-agent
`llm.py`.

v0.2 (Level 2 — live multi-cloud CIEM). Per the v0.2 plan
(docs/superpowers/plans/2026-06-10-d-2-identity-v0-2.md), an ADR-010
version-extension: live AWS IAM (via the hoisted charter `CredentialResolver`) +
net-new Azure AD/Entra + basic SAML/OIDC federation forensics — additive, with the
OCSF 2004 wire shape + offline eval cases byte-stable. **D.2 is the genuine 3rd
consumer of F.3's cloud patterns (#266): the ADR-007 charter hoist (Patterns
E → D → A) fires this cycle — the substrate-seal-empty streak ends, intentionally
and minimally.** GCP IAM, effective-permissions, Conditional Access defer to v0.3.
"""

from __future__ import annotations

__version__ = "0.2.0"
