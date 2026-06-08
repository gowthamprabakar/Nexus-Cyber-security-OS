"""Cloud Posture credential-resolution seam (F.3 v0.2 Task 2).

A single, small seam for *how* the agent obtains AWS credentials for a run:
the boto3 default chain (env vars / shared config / IAM role — preserves the
v0.1 behavior) or a named profile. It only ever handles a *profile name*; the
actual secret material is resolved inside boto3 and never passes through — or is
logged by — this class.

In-package by design (ADR-007 Q7 / brainstorm §7: establish the shape here and
hoist to `charter` at the third consumer — D.5 / D.2 v0.2). The per-tenant
credential **store** (F.4 control-plane) is a separate, deferred SAFETY-CRITICAL
cycle (brainstorm §0 option B; gated on the tenant-RLS substrate fix).

Per-region scoping (Q3) is threaded through the tool layer in Task 4; `client()`
accepts an optional region for that wiring.
"""

from __future__ import annotations

from typing import Any

import boto3


class CredentialResolver:
    """Resolves a boto3 Session for a Cloud Posture run.

    No profile → ``boto3.Session()`` (the default credential chain), which
    preserves v0.1 behavior. A named profile → ``boto3.Session(profile_name=…)``.
    The resolver's only state is the profile name; no secret material is stored
    or logged.
    """

    __slots__ = ("_profile",)

    def __init__(self, *, profile: str | None = None) -> None:
        self._profile = profile

    @property
    def profile(self) -> str | None:
        """The named profile, or ``None`` for the boto3 default chain."""
        return self._profile

    def resolve_session(self) -> Any:
        """Build a boto3 Session per the configured profile."""
        if self._profile is not None:
            return boto3.Session(profile_name=self._profile)
        return boto3.Session()

    def client(self, service: str, *, region: str | None = None) -> Any:
        """A service client from the resolved session.

        ``region`` is optional — global services (e.g. IAM) ignore it. Task 4
        threads per-region scoping through the tool layer.
        """
        session = self.resolve_session()
        if region is not None:
            return session.client(service, region_name=region)
        return session.client(service)
