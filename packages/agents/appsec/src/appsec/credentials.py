"""SCM credential resolution — Pattern-A (D.14, Q-AppSec-2).

Mirrors cloud-posture's ``CredentialResolver`` Pattern-A: the resolver stores
ONLY a non-secret identifier (the SCM type + an optional profile name) and resolves
the actual token at call time from the environment. No PAT/token material is ever
stored on the instance or logged.

v0.1 resolves tokens from environment variables (``GITHUB_TOKEN`` / ``GITLAB_TOKEN``
/ ``BITBUCKET_TOKEN``). A per-tenant credential store (a profile that maps to a
secret backend) is a future SAFETY-CRITICAL substrate concern and is explicitly
NOT implemented here (raising rather than guessing).
"""

from __future__ import annotations

import os

from charter.credentials import CredentialResolver as _CredentialResolverContract

#: Supported SCM hosts (Q-AppSec-2 = GitHub + GitLab + Bitbucket).
SUPPORTED_SCM_TYPES: frozenset[str] = frozenset({"github", "gitlab", "bitbucket"})

_ENV_VAR_BY_SCM: dict[str, str] = {
    "github": "GITHUB_TOKEN",
    "gitlab": "GITLAB_TOKEN",
    "bitbucket": "BITBUCKET_TOKEN",
}


class ScmCredentialError(RuntimeError):
    """No credential could be resolved for the requested SCM."""


class ScmCredentialResolver(_CredentialResolverContract):
    """Resolve SCM API auth (Pattern-A): identifier-only state, token at call time."""

    __slots__ = ("_profile", "_scm_type")

    def __init__(self, *, scm_type: str = "github", profile: str | None = None) -> None:
        scm = scm_type.lower()
        if scm not in SUPPORTED_SCM_TYPES:
            raise ScmCredentialError(
                f"unsupported scm_type {scm_type!r}; supported: {sorted(SUPPORTED_SCM_TYPES)}"
            )
        self._scm_type = scm
        self._profile = profile

    @property
    def scm_type(self) -> str:
        return self._scm_type

    @property
    def profile(self) -> str | None:
        """The named profile, or ``None`` for the environment-variable default."""
        return self._profile

    def resolve_token(self) -> str:
        """Resolve the SCM token at call time. Never stored; raises if absent."""
        if self._profile is not None:
            # A profile maps to a per-tenant secret backend — SAFETY-CRITICAL
            # substrate not yet built. Raise rather than silently degrade.
            raise ScmCredentialError(
                f"profile-based SCM credential store not implemented (profile={self._profile!r}); "
                "set the environment-variable token instead for v0.1"
            )
        env_var = _ENV_VAR_BY_SCM[self._scm_type]
        token = os.environ.get(env_var)
        if not token:
            raise ScmCredentialError(f"{env_var} is not set")
        return token

    def auth_headers(self) -> dict[str, str]:
        """Authorization header for the SCM API (token resolved fresh; not stored)."""
        return {"Authorization": f"Bearer {self.resolve_token()}"}

    def client(self) -> dict[str, str]:
        """Pattern-A ``client`` hook — v0.1 returns auth headers (no HTTP client yet).

        The live httpx-based SCM connectors land in B-1 PR2; they consume these
        headers. Kept on the resolver so the Pattern-A contract is satisfied.
        """
        return self.auth_headers()
