"""Auth0 management API client.

Async httpx wrapper following ADR-007 v1.1's HTTP-wrapper convention
(also seen in [`vulnerability.tools.nvd`](../../../../agents/vulnerability/src/vulnerability/tools/nvd.py)):
custom Error subclass, tenacity retry on 429/5xx, in-process token cache.

Wraps:

- `POST /oauth/token` — fetch a management API access token, cached for ~24h.
- `POST /api/v2/users` — invite a user (Auth0 sends a password-reset email).
- `GET /api/v2/users` — list users (paginated; Lucene query via `q`).
- `POST /api/v2/organizations` — create a SAML organization.

Per-instance token cache: build one `Auth0Client` per process and reuse
it. The token is fetched lazily on first call and refreshed on expiry.
"""

from __future__ import annotations

import time
from typing import Any

import httpx
from pydantic import BaseModel, EmailStr, Field
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

DEFAULT_TIMEOUT_SEC = 30.0
TOKEN_TTL_SEC = 23 * 60 * 60  # Auth0 mgmt tokens last 24h; refresh ~1h early.
TOKEN_REFRESH_LEAD_SEC = 60.0


class Auth0Error(RuntimeError):
    """Auth0 management API returned a non-retryable error or exhausted retries.

    `status_code` is populated for HTTP-level errors; `None` for transport
    failures or malformed responses.
    """

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class Auth0User(BaseModel):
    """Subset of the Auth0 user shape we care about downstream."""

    user_id: str
    email: EmailStr
    name: str | None = None
    blocked: bool = False
    app_metadata: dict[str, Any] = Field(default_factory=dict)


class Auth0Organization(BaseModel):
    """Subset of the Auth0 organization shape we care about downstream."""

    id: str
    name: str
    display_name: str | None = None


class _RetryableHTTPError(Exception):
    """Internal retry signal for 429 / 5xx; not user-facing."""


@retry(
    retry=retry_if_exception_type(_RetryableHTTPError),
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=0.1, min=0.05, max=1.0),
    reraise=True,
)
async def _send_with_retry(client: httpx.AsyncClient, request: httpx.Request) -> httpx.Response:
    response = await client.send(request)
    if response.status_code == 429 or 500 <= response.status_code < 600:
        raise _RetryableHTTPError(f"{request.url} returned {response.status_code}")
    return response


class Auth0Client:
    """Auth0 management-API client with token caching + retry."""

    def __init__(
        self,
        *,
        domain: str,
        client_id: str,
        client_secret: str,
        audience: str | None = None,
        timeout_sec: float = DEFAULT_TIMEOUT_SEC,
    ) -> None:
        self._domain = domain.rstrip("/")
        self._client_id = client_id
        self._client_secret = client_secret
        self._audience = audience or f"https://{self._domain}/api/v2/"
        self._timeout = timeout_sec
        self._token: str | None = None
        self._token_expires_at: float = 0.0

    @property
    def base_url(self) -> str:
        return f"https://{self._domain}"

    async def _get_management_token(self, client: httpx.AsyncClient) -> str:
        now = time.monotonic()
        if self._token is not None and self._token_expires_at > now:
            return self._token

        request = client.build_request(
            "POST",
            f"{self.base_url}/oauth/token",
            json={
                "client_id": self._client_id,
                "client_secret": self._client_secret,
                "audience": self._audience,
                "grant_type": "client_credentials",
            },
        )
        try:
            response = await _send_with_retry(client, request)
        except _RetryableHTTPError as e:
            raise Auth0Error(f"oauth/token retries exhausted: {e}") from e

        if response.status_code != 200:
            raise Auth0Error(
                f"oauth/token returned {response.status_code}: {response.text[:200]}",
                status_code=response.status_code,
            )

        data = response.json()
        token = data.get("access_token")
        if not isinstance(token, str):
            raise Auth0Error("oauth/token response missing access_token")
        expires_in_raw = data.get("expires_in")
        ttl = (
            float(expires_in_raw)
            if isinstance(expires_in_raw, (int, float))
            else float(TOKEN_TTL_SEC)
        )
        capped_ttl = min(ttl - TOKEN_REFRESH_LEAD_SEC, float(TOKEN_TTL_SEC))
        self._token = token
        self._token_expires_at = now + max(capped_ttl, 60.0)
        return token

    async def _authenticated_request(
        self,
        client: httpx.AsyncClient,
        method: str,
        path: str,
        **kwargs: Any,
    ) -> httpx.Response:
        token = await self._get_management_token(client)
        headers = dict(kwargs.pop("headers", None) or {})
        headers["Authorization"] = f"Bearer {token}"
        request = client.build_request(method, f"{self.base_url}{path}", headers=headers, **kwargs)
        try:
            return await _send_with_retry(client, request)
        except _RetryableHTTPError as e:
            raise Auth0Error(f"{method} {path} retries exhausted: {e}") from e

    async def invite_user(
        self,
        *,
        email: str,
        connection: str = "Username-Password-Authentication",
        app_metadata: dict[str, Any] | None = None,
    ) -> Auth0User:
        """Create a user; Auth0 sends a verification/password-reset email."""
        body: dict[str, Any] = {
            "email": email,
            "connection": connection,
            "email_verified": False,
            "verify_email": True,
        }
        if app_metadata:
            body["app_metadata"] = app_metadata

        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await self._authenticated_request(
                    client, "POST", "/api/v2/users", json=body
                )
        except httpx.HTTPError as e:
            raise Auth0Error(f"HTTP error inviting user: {e}") from e

        if response.status_code != 201:
            raise Auth0Error(
                f"POST /api/v2/users returned {response.status_code}: {response.text[:200]}",
                status_code=response.status_code,
            )
        return Auth0User.model_validate(response.json())

    async def list_users(
        self,
        *,
        page: int = 0,
        per_page: int = 50,
        q: str | None = None,
    ) -> list[Auth0User]:
        """Page through Auth0 users. `q` is a Lucene query (search_engine v3)."""
        params: dict[str, str] = {"page": str(page), "per_page": str(per_page)}
        if q:
            params["q"] = q
            params["search_engine"] = "v3"

        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await self._authenticated_request(
                    client, "GET", "/api/v2/users", params=params
                )
        except httpx.HTTPError as e:
            raise Auth0Error(f"HTTP error listing users: {e}") from e

        if response.status_code != 200:
            raise Auth0Error(
                f"GET /api/v2/users returned {response.status_code}: {response.text[:200]}",
                status_code=response.status_code,
            )
        rows = response.json()
        if not isinstance(rows, list):
            raise Auth0Error(f"GET /api/v2/users returned non-list: {type(rows).__name__}")
        return [Auth0User.model_validate(r) for r in rows]

    async def create_organization(
        self,
        *,
        name: str,
        display_name: str | None = None,
    ) -> Auth0Organization:
        """Create an Auth0 organization (used to model enterprise tenants)."""
        body: dict[str, Any] = {"name": name}
        if display_name:
            body["display_name"] = display_name

        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await self._authenticated_request(
                    client, "POST", "/api/v2/organizations", json=body
                )
        except httpx.HTTPError as e:
            raise Auth0Error(f"HTTP error creating organization: {e}") from e

        if response.status_code != 201:
            raise Auth0Error(
                f"POST /api/v2/organizations returned {response.status_code}: {response.text[:200]}",
                status_code=response.status_code,
            )
        return Auth0Organization.model_validate(response.json())


__all__ = [
    "Auth0Client",
    "Auth0Error",
    "Auth0Organization",
    "Auth0User",
]
