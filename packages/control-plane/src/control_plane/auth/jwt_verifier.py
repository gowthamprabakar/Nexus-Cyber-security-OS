"""Auth0 JWT verifier (RS256 + JWKS cache).

Pulls the Auth0 JWKS once per ~24h, validates RS256 signatures, and
checks `iss`/`aud`/`exp`/`nbf`. Extracts Nexus custom claims:

- `https://nexus.app/tenant_id` → routed to `VerifiedToken.tenant_id`.
- `https://nexus.app/roles`     → routed to `VerifiedToken.roles`.

Resolves F.4 plan **Q2** (JWT claim format): we adopt Auth0's
namespaced-custom-claim convention rather than embedding tenant/role
data in the standard claim set, so that the platform stays compatible
with Auth0 Rules / Actions and any other claim a customer's IdP injects.

Async by ADR-005; the JWKS fetch is the only network call. PyJWT's
`decode` is sync (CPU-bound), called from the same coroutine.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import httpx
import jwt
from jwt.algorithms import RSAAlgorithm

JWKS_TTL_SEC = 24 * 60 * 60
TENANT_ID_CLAIM = "https://nexus.app/tenant_id"
ROLES_CLAIM = "https://nexus.app/roles"


class JwtVerificationError(RuntimeError):
    """Token failed verification (signature, claims, or JWKS lookup)."""


@dataclass(frozen=True, slots=True)
class VerifiedToken:
    """Successfully verified Auth0 access token, projected onto our domain."""

    sub: str
    tenant_id: str
    roles: tuple[str, ...]
    expires_at: datetime
    amr: tuple[str, ...] = field(default_factory=tuple)


class JwtVerifier:
    """Auth0 JWT verifier with per-instance JWKS cache."""

    def __init__(
        self,
        *,
        domain: str,
        audience: str,
        algorithms: tuple[str, ...] = ("RS256",),
        jwks_ttl_sec: int = JWKS_TTL_SEC,
        timeout_sec: float = 10.0,
    ) -> None:
        self._domain = domain.rstrip("/")
        self._audience = audience
        self._algorithms = list(algorithms)
        self._jwks_ttl = jwks_ttl_sec
        self._timeout = timeout_sec
        self._jwks: dict[str, Any] | None = None
        self._jwks_expires_at: float = 0.0

    @property
    def issuer(self) -> str:
        return f"https://{self._domain}/"

    @property
    def jwks_url(self) -> str:
        return f"https://{self._domain}/.well-known/jwks.json"

    async def _fetch_jwks(self) -> dict[str, Any]:
        now = time.monotonic()
        if self._jwks is not None and self._jwks_expires_at > now:
            return self._jwks

        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.get(self.jwks_url)
        except httpx.HTTPError as e:
            raise JwtVerificationError(f"jwks fetch failed: {e}") from e

        if response.status_code != 200:
            raise JwtVerificationError(f"jwks endpoint returned {response.status_code}")
        try:
            jwks = response.json()
        except ValueError as e:
            raise JwtVerificationError(f"jwks response was not JSON: {e}") from e

        if not isinstance(jwks, dict) or not isinstance(jwks.get("keys"), list):
            raise JwtVerificationError("jwks response missing 'keys' list")

        self._jwks = jwks
        self._jwks_expires_at = now + self._jwks_ttl
        return jwks

    def _signing_key(self, jwks: dict[str, Any], kid: str) -> Any:
        for key in jwks.get("keys", []):
            if key.get("kid") == kid:
                return RSAAlgorithm.from_jwk(key)
        raise JwtVerificationError(f"unknown kid: {kid}")

    async def verify(self, token: str) -> VerifiedToken:
        """Verify `token` and return the projected `VerifiedToken`.

        Raises:
            JwtVerificationError: on any verification failure (malformed
                token, bad signature, claim mismatch, JWKS lookup error).
        """
        try:
            unverified_header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as e:
            raise JwtVerificationError(f"malformed token header: {e}") from e
        kid = unverified_header.get("kid")
        if not isinstance(kid, str) or not kid:
            raise JwtVerificationError("token header missing 'kid'")

        jwks = await self._fetch_jwks()
        key = self._signing_key(jwks, kid)

        try:
            claims = jwt.decode(
                token,
                key=key,
                algorithms=self._algorithms,
                audience=self._audience,
                issuer=self.issuer,
            )
        except jwt.PyJWTError as e:
            raise JwtVerificationError(f"jwt verification failed: {e}") from e

        return _project_claims(claims)


def _project_claims(claims: dict[str, Any]) -> VerifiedToken:
    sub = claims.get("sub")
    if not isinstance(sub, str) or not sub:
        raise JwtVerificationError("missing 'sub' claim")

    tenant_id = claims.get(TENANT_ID_CLAIM)
    if not isinstance(tenant_id, str) or not tenant_id:
        raise JwtVerificationError(f"missing custom claim: {TENANT_ID_CLAIM}")

    roles_raw = claims.get(ROLES_CLAIM, [])
    if not isinstance(roles_raw, list):
        raise JwtVerificationError(f"{ROLES_CLAIM} must be a list")
    roles = tuple(str(r) for r in roles_raw)

    amr_raw = claims.get("amr", [])
    amr = tuple(str(a) for a in amr_raw) if isinstance(amr_raw, list) else ()

    exp = claims.get("exp")
    if not isinstance(exp, (int, float)):
        raise JwtVerificationError("missing or non-numeric 'exp' claim")
    expires_at = datetime.fromtimestamp(int(exp), tz=UTC)

    return VerifiedToken(
        sub=sub,
        tenant_id=tenant_id,
        roles=roles,
        expires_at=expires_at,
        amr=amr,
    )


__all__ = [
    "JWKS_TTL_SEC",
    "ROLES_CLAIM",
    "TENANT_ID_CLAIM",
    "JwtVerificationError",
    "JwtVerifier",
    "VerifiedToken",
]
