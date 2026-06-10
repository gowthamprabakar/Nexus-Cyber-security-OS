"""Network-threat credential-resolution seam (D.4 v0.2 Task 8).

Consumes the hoisted `charter.credentials.CredentialResolver` contract (Pattern A) for
the live AWS VPC Flow Logs reader. The boto3-specific session construction stays
in-package (per the F.3/D.2 precedent); only the cloud-agnostic contract lives in
`charter`. The resolver's only state is a profile name + region; no secret material is
stored or logged.
"""

from __future__ import annotations

from typing import Any

import boto3
from charter.credentials import CredentialResolver as _CredentialResolverContract


class CredentialResolver(_CredentialResolverContract):
    """Resolves a boto3 Session for a Network-Threat (AWS VPC flow) run.

    No profile → ``boto3.Session(region_name=…)`` (the default credential chain). A named
    profile → ``boto3.Session(profile_name=…, region_name=…)``.
    """

    __slots__ = ("_profile", "_region")

    def __init__(self, *, profile: str | None = None, region: str = "us-east-1") -> None:
        self._profile = profile
        self._region = region

    @property
    def profile(self) -> str | None:
        return self._profile

    @property
    def region(self) -> str:
        return self._region

    def resolve_session(self) -> Any:
        if self._profile is not None:
            return boto3.Session(profile_name=self._profile, region_name=self._region)
        return boto3.Session(region_name=self._region)

    def client(self, service: str) -> Any:
        """A service client from the resolved session (region is set on the session)."""
        return self.resolve_session().client(service)
