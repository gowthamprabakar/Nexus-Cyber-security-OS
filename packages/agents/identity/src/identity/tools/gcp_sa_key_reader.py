"""v0.5 Item 3 — live GCP SA-key list -> GcpServiceAccountKey (operator-gated leg).

Maps a live service-account-keys listing into the existing `GcpServiceAccountKey` dataclass that
`sa_key_ownership` converges (hashed `secret_fingerprint`, no plaintext). Injectable Protocol ->
unit-testable without the gcp sdk; the live client + NEXUS_LIVE_GCP lane is Task 14.
"""

from __future__ import annotations

from typing import Any, Protocol

from identity.tools.gcp_iam import GcpServiceAccountKey


class GcpSaKeyClient(Protocol):
    def list_service_account_keys(self) -> list[dict[str, Any]]: ...


class GcpSaKeyReader:
    __slots__ = ("_client",)

    def __init__(self, client: GcpSaKeyClient) -> None:
        self._client = client

    def read(self) -> tuple[GcpServiceAccountKey, ...]:
        return tuple(
            GcpServiceAccountKey(str(k["service_account"]), str(k["private_key_id"]))
            for k in self._client.list_service_account_keys()
            if k.get("service_account") and k.get("private_key_id")
        )


__all__ = ["GcpSaKeyClient", "GcpSaKeyReader"]
