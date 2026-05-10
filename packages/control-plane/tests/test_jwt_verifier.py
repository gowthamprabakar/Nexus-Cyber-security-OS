"""Tests for `control_plane.auth.jwt_verifier.JwtVerifier`.

Generates a one-shot RSA keypair, builds an Auth0-shaped JWKS from its
public key, and signs tokens with the matching private key. Negative
cases (bad signature) sign with a second keypair the verifier never sees.

JWKS endpoint is mocked via respx; no network.
"""

from __future__ import annotations

import json
import time
from typing import Any

import httpx
import jwt
import pytest
import respx
from control_plane.auth.jwt_verifier import (
    ROLES_CLAIM,
    TENANT_ID_CLAIM,
    JwtVerificationError,
    JwtVerifier,
    VerifiedToken,
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

DOMAIN = "test-tenant.auth0.com"
AUDIENCE = "https://api.nexus.app"
ISSUER = f"https://{DOMAIN}/"
KID = "test-kid-1"
JWKS_URL = f"https://{DOMAIN}/.well-known/jwks.json"


# ---------------------------- key fixtures -------------------------------


@pytest.fixture(scope="module")
def keypair() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def other_keypair() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def jwks(keypair: rsa.RSAPrivateKey) -> dict[str, Any]:
    jwk = json.loads(RSAAlgorithm.to_jwk(keypair.public_key()))
    jwk["kid"] = KID
    jwk["alg"] = "RS256"
    jwk["use"] = "sig"
    return {"keys": [jwk]}


def _private_pem(keypair: rsa.RSAPrivateKey) -> bytes:
    return keypair.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _make_token(
    keypair: rsa.RSAPrivateKey,
    *,
    sub: str = "auth0|abc",
    tenant_id: str | None = "01HXYZTENANT",
    roles: tuple[str, ...] = ("admin",),
    aud: str | list[str] = AUDIENCE,
    iss: str = ISSUER,
    exp_offset: int = 3600,
    amr: tuple[str, ...] = ("pwd",),
    kid: str = KID,
) -> str:
    now = int(time.time())
    claims: dict[str, Any] = {
        "sub": sub,
        "iss": iss,
        "aud": aud,
        "exp": now + exp_offset,
        "iat": now,
        ROLES_CLAIM: list(roles),
        "amr": list(amr),
    }
    if tenant_id is not None:
        claims[TENANT_ID_CLAIM] = tenant_id
    return jwt.encode(
        claims,
        _private_pem(keypair),
        algorithm="RS256",
        headers={"kid": kid},
    )


def _verifier() -> JwtVerifier:
    return JwtVerifier(domain=DOMAIN, audience=AUDIENCE)


def _mock_jwks(respx_mock: respx.Router, jwks: dict[str, Any]) -> respx.Route:
    return respx_mock.get(JWKS_URL).mock(return_value=httpx.Response(200, json=jwks))


# ---------------------------- happy paths --------------------------------


@pytest.mark.asyncio
async def test_valid_token_yields_verified_token(
    keypair: rsa.RSAPrivateKey, jwks: dict[str, Any]
) -> None:
    async with respx.mock() as respx_mock:
        _mock_jwks(respx_mock, jwks)
        token = _make_token(keypair)
        verified = await _verifier().verify(token)

    assert isinstance(verified, VerifiedToken)
    assert verified.sub == "auth0|abc"
    assert verified.tenant_id == "01HXYZTENANT"
    assert verified.roles == ("admin",)
    assert verified.amr == ("pwd",)


@pytest.mark.asyncio
async def test_roles_extracted_as_tuple(keypair: rsa.RSAPrivateKey, jwks: dict[str, Any]) -> None:
    async with respx.mock() as respx_mock:
        _mock_jwks(respx_mock, jwks)
        token = _make_token(keypair, roles=("admin", "operator", "auditor"))
        verified = await _verifier().verify(token)

    assert verified.roles == ("admin", "operator", "auditor")
    assert isinstance(verified.roles, tuple)


@pytest.mark.asyncio
async def test_expires_at_is_timezone_aware(
    keypair: rsa.RSAPrivateKey, jwks: dict[str, Any]
) -> None:
    async with respx.mock() as respx_mock:
        _mock_jwks(respx_mock, jwks)
        token = _make_token(keypair, exp_offset=3600)
        verified = await _verifier().verify(token)

    assert verified.expires_at.tzinfo is not None


# ---------------------------- rejection paths ----------------------------


@pytest.mark.asyncio
async def test_expired_token_rejected(keypair: rsa.RSAPrivateKey, jwks: dict[str, Any]) -> None:
    async with respx.mock() as respx_mock:
        _mock_jwks(respx_mock, jwks)
        token = _make_token(keypair, exp_offset=-60)
        with pytest.raises(JwtVerificationError):
            await _verifier().verify(token)


@pytest.mark.asyncio
async def test_bad_signature_rejected(
    keypair: rsa.RSAPrivateKey,
    other_keypair: rsa.RSAPrivateKey,
    jwks: dict[str, Any],
) -> None:
    """Verifier only knows about `keypair`; signing with `other_keypair` must fail."""
    async with respx.mock() as respx_mock:
        _mock_jwks(respx_mock, jwks)
        token = _make_token(other_keypair)
        with pytest.raises(JwtVerificationError):
            await _verifier().verify(token)


@pytest.mark.asyncio
async def test_wrong_issuer_rejected(keypair: rsa.RSAPrivateKey, jwks: dict[str, Any]) -> None:
    async with respx.mock() as respx_mock:
        _mock_jwks(respx_mock, jwks)
        token = _make_token(keypair, iss="https://evil.example.com/")
        with pytest.raises(JwtVerificationError):
            await _verifier().verify(token)


@pytest.mark.asyncio
async def test_wrong_audience_rejected(keypair: rsa.RSAPrivateKey, jwks: dict[str, Any]) -> None:
    async with respx.mock() as respx_mock:
        _mock_jwks(respx_mock, jwks)
        token = _make_token(keypair, aud="https://other-audience")
        with pytest.raises(JwtVerificationError):
            await _verifier().verify(token)


@pytest.mark.asyncio
async def test_missing_tenant_id_claim_rejected(
    keypair: rsa.RSAPrivateKey, jwks: dict[str, Any]
) -> None:
    async with respx.mock() as respx_mock:
        _mock_jwks(respx_mock, jwks)
        token = _make_token(keypair, tenant_id=None)
        with pytest.raises(JwtVerificationError):
            await _verifier().verify(token)


@pytest.mark.asyncio
async def test_unknown_kid_rejected(keypair: rsa.RSAPrivateKey, jwks: dict[str, Any]) -> None:
    async with respx.mock() as respx_mock:
        _mock_jwks(respx_mock, jwks)
        token = _make_token(keypair, kid="unknown-kid")
        with pytest.raises(JwtVerificationError):
            await _verifier().verify(token)


# ---------------------------- JWKS caching + transport -------------------


@pytest.mark.asyncio
async def test_jwks_cached_across_verifications(
    keypair: rsa.RSAPrivateKey, jwks: dict[str, Any]
) -> None:
    async with respx.mock() as respx_mock:
        route = _mock_jwks(respx_mock, jwks)
        verifier = _verifier()
        token1 = _make_token(keypair, sub="auth0|1")
        token2 = _make_token(keypair, sub="auth0|2")
        await verifier.verify(token1)
        await verifier.verify(token2)

    assert route.call_count == 1


@pytest.mark.asyncio
async def test_jwks_endpoint_5xx_raises(keypair: rsa.RSAPrivateKey) -> None:
    async with respx.mock() as respx_mock:
        respx_mock.get(JWKS_URL).mock(return_value=httpx.Response(503))
        token = _make_token(keypair)
        with pytest.raises(JwtVerificationError):
            await _verifier().verify(token)
