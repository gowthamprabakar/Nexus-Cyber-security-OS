"""Identity credential-resolution seam (D.2 v0.2 Task 5).

Adopts the hoisted `charter.credentials.CredentialResolver` contract (Pattern A,
Task 4) — **D.2 Identity is the canonical 3rd consumer** of the cloud
CredentialResolver pattern, so the ADR-007 hoist's value is realized here. The
boto3-specific session construction stays in-package (per WI-I2); only the
cloud-agnostic contract lives in `charter`.

Mirrors F.3's resolver shape, with the region threaded into the `Session` (IAM is
global but boto3 requires a region for client construction). It only ever handles a
profile name + region; the actual secret material is resolved inside boto3 and never
passes through — or is logged by — this class.
"""

from __future__ import annotations

from typing import Any

import boto3
from charter.credentials import CredentialResolver as _CredentialResolverContract


class CredentialResolver(_CredentialResolverContract):
    """Resolves a boto3 Session for an Identity (AWS IAM) run.

    No profile → ``boto3.Session(region_name=…)`` (the default credential chain),
    which preserves the v0.1 behavior. A named profile →
    ``boto3.Session(profile_name=…, region_name=…)``. The resolver's only state is
    the profile name + region; no secret material is stored or logged.
    """

    __slots__ = ("_profile", "_region")

    def __init__(self, *, profile: str | None = None, region: str = "us-east-1") -> None:
        self._profile = profile
        self._region = region

    @property
    def profile(self) -> str | None:
        """The named profile, or ``None`` for the boto3 default chain."""
        return self._profile

    @property
    def region(self) -> str:
        """The region threaded into the session (IAM is global; boto3 needs one)."""
        return self._region

    def resolve_session(self) -> Any:
        """Build a boto3 Session per the configured profile + region."""
        if self._profile is not None:
            return boto3.Session(profile_name=self._profile, region_name=self._region)
        return boto3.Session(region_name=self._region)

    def client(self, service: str) -> Any:
        """A service client from the resolved session (region is set on the session)."""
        return self.resolve_session().client(service)
