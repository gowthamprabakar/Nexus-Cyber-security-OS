"""Nexus AppSec Agent (D.14) — application-security scanning of source repos.

Scope (per ADR-007 reference model + ADR-014 SBOM boundary):

- **Owns build-time** application security: SCM repository discovery, build-time
  SCA/SBOM, IaC misconfiguration, SAST, and secrets-in-code — everything rooted in
  *source*. Deploy-time SBOM/SCA (images/registries/hosts) stays with D.1 (ADR-014);
  secrets-in-code route to DSPM for OCSF 2003 emission (ADR-015).

v0.1 (B-1 PR1) ships the substrate only: the charter agent skeleton, the SCM
Pattern-A credential resolver, and repository discovery. The scanners
(Checkov / gitleaks / Semgrep) land in subsequent B-1 PRs.
"""

__version__ = "0.1.0"
