"""Tests for `control_plane.api.scim`.

In-memory aiosqlite database (same pattern as the tenant-resolver
tests). FastAPI `TestClient` drives the HTTP surface; HMAC signatures
are minted via `scim.sign_body` so the assertions exercise the same
crypto path the real Auth0 webhook does.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Iterator
from datetime import UTC, datetime

import pytest
import pytest_asyncio
from control_plane.api.scim import (
    NEXUS_EXTENSION_SCHEMA,
    PATCH_OP_SCHEMA,
    SCIM_USER_SCHEMA,
    SIGNATURE_HEADER,
    build_scim_app,
    sign_body,
)
from control_plane.tenants.models import Base, TenantRow
from fastapi.testclient import TestClient
from httpx import Response
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from ulid import ULID

HMAC_SECRET = b"super-secret-rotated-quarterly"
TENANT_ID = str(ULID())


@pytest_asyncio.fixture
async def session_factory() -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)

    async with factory() as session:
        session.add(TenantRow(tenant_id=TENANT_ID, name="Acme", created_at=datetime.now(UTC)))
        await session.commit()

    yield factory
    await engine.dispose()


@pytest.fixture
def client(
    session_factory: async_sessionmaker[AsyncSession],
) -> Iterator[TestClient]:
    app = build_scim_app(session_factory=session_factory, hmac_secret=HMAC_SECRET)
    with TestClient(app) as test_client:
        yield test_client


def _scim_user(
    user_name: str = "alice@example.com",
    tenant_id: str = TENANT_ID,
    role: str = "operator",
    external_id: str = "auth0|abc123",
) -> dict[str, object]:
    return {
        "schemas": [SCIM_USER_SCHEMA, NEXUS_EXTENSION_SCHEMA],
        "userName": user_name,
        "externalId": external_id,
        "active": True,
        "emails": [{"value": user_name, "primary": True}],
        NEXUS_EXTENSION_SCHEMA: {"tenantId": tenant_id, "role": role},
    }


def _post(
    client: TestClient,
    body: dict[str, object],
    *,
    secret: bytes = HMAC_SECRET,
) -> Response:
    raw = json.dumps(body).encode()
    headers = {
        "content-type": "application/scim+json",
        SIGNATURE_HEADER: sign_body(raw, secret),
    }
    return client.post("/scim/v2/Users", content=raw, headers=headers)


# ---------------------------- POST happy paths ---------------------------


def test_post_user_with_valid_hmac_creates_row(client: TestClient) -> None:
    response = _post(client, _scim_user())
    assert response.status_code == 201
    data = response.json()
    assert data["userName"] == "alice@example.com"
    assert data["externalId"] == "auth0|abc123"
    assert data[NEXUS_EXTENSION_SCHEMA]["tenantId"] == TENANT_ID
    assert len(data["id"]) == 26  # ULID


def test_post_user_persists_to_db(client: TestClient) -> None:
    response = _post(client, _scim_user())
    user_id = response.json()["id"]

    fetched = client.get(f"/scim/v2/Users/{user_id}")
    assert fetched.status_code == 200
    assert fetched.json()["userName"] == "alice@example.com"


# ---------------------------- POST rejection paths -----------------------


def test_post_user_with_bad_hmac_returns_401(client: TestClient) -> None:
    response = _post(client, _scim_user(), secret=b"wrong-secret")
    assert response.status_code == 401


def test_post_user_with_missing_signature_returns_401(client: TestClient) -> None:
    raw = json.dumps(_scim_user()).encode()
    response = client.post("/scim/v2/Users", content=raw)
    assert response.status_code == 401


def test_post_user_malformed_json_returns_400(client: TestClient) -> None:
    raw = b"{not json"
    headers = {SIGNATURE_HEADER: sign_body(raw, HMAC_SECRET)}
    response = client.post("/scim/v2/Users", content=raw, headers=headers)
    assert response.status_code == 400


def test_post_user_missing_extension_returns_400(client: TestClient) -> None:
    payload = _scim_user()
    payload.pop(NEXUS_EXTENSION_SCHEMA)
    response = _post(client, payload)
    assert response.status_code == 400


def test_post_user_unknown_tenant_returns_404(client: TestClient) -> None:
    payload = _scim_user(tenant_id=str(ULID()))
    response = _post(client, payload)
    assert response.status_code == 404


def test_post_user_unknown_role_returns_400(client: TestClient) -> None:
    payload = _scim_user(role="god-mode")
    response = _post(client, payload)
    assert response.status_code == 400


# ---------------------------- GET ---------------------------------------


def test_get_user_returns_scim_shape(client: TestClient) -> None:
    user_id = _post(client, _scim_user()).json()["id"]
    response = client.get(f"/scim/v2/Users/{user_id}")
    assert response.status_code == 200
    body = response.json()
    assert SCIM_USER_SCHEMA in body["schemas"]
    assert body["meta"]["resourceType"] == "User"
    assert body["meta"]["location"].endswith(user_id)


def test_get_nonexistent_user_returns_404(client: TestClient) -> None:
    response = client.get(f"/scim/v2/Users/{ULID()}")
    assert response.status_code == 404


# ---------------------------- PATCH -------------------------------------


def test_patch_active_false_deactivates_user(client: TestClient) -> None:
    user_id = _post(client, _scim_user()).json()["id"]
    body = {
        "schemas": [PATCH_OP_SCHEMA],
        "Operations": [{"op": "replace", "path": "active", "value": False}],
    }
    raw = json.dumps(body).encode()
    headers = {SIGNATURE_HEADER: sign_body(raw, HMAC_SECRET)}
    response = client.patch(f"/scim/v2/Users/{user_id}", content=raw, headers=headers)
    assert response.status_code == 204

    assert client.get(f"/scim/v2/Users/{user_id}").status_code == 404


def test_patch_with_bad_hmac_returns_401(client: TestClient) -> None:
    user_id = _post(client, _scim_user()).json()["id"]
    body = {
        "schemas": [PATCH_OP_SCHEMA],
        "Operations": [{"op": "replace", "path": "active", "value": False}],
    }
    raw = json.dumps(body).encode()
    headers = {SIGNATURE_HEADER: sign_body(raw, b"wrong")}
    response = client.patch(f"/scim/v2/Users/{user_id}", content=raw, headers=headers)
    assert response.status_code == 401


# ---------------------------- DELETE ------------------------------------


def test_delete_user_removes_row(client: TestClient) -> None:
    user_id = _post(client, _scim_user()).json()["id"]
    raw = b""
    headers = {SIGNATURE_HEADER: sign_body(raw, HMAC_SECRET)}
    response = client.delete(f"/scim/v2/Users/{user_id}", headers=headers)
    assert response.status_code == 204
    assert client.get(f"/scim/v2/Users/{user_id}").status_code == 404


def test_delete_nonexistent_user_returns_404(client: TestClient) -> None:
    raw = b""
    headers = {SIGNATURE_HEADER: sign_body(raw, HMAC_SECRET)}
    response = client.delete(f"/scim/v2/Users/{ULID()}", headers=headers)
    assert response.status_code == 404
