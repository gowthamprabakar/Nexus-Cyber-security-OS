"""Charter Pattern A credential resolver for live AWS data discovery (data-security v0.2).

A thin concrete subclass of the hoisted `charter.credentials.CredentialResolver` (the
shared boto3 seam, consumed since the Cycle-4 D.2 trilogy). The boto3-specific session
construction stays here; the rest of the agent depends only on the abstract contract.
"""

from __future__ import annotations

from typing import Any

import boto3
from charter.credentials import CredentialResolver as _CredentialResolverContract


class CredentialResolver(_CredentialResolverContract):
    """Resolves a boto3 Session for a data-security (AWS S3) run.

    No profile → the default credential chain; a named profile → that profile."""

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
        """A service client from the resolved session."""
        return self.resolve_session().client(service)
