"""v0.5 Item 3 — live Azure SP-secret list -> AzureAdServicePrincipal (operator-gated leg).

Maps a live service-principal listing into the existing `AzureAdServicePrincipal` dataclass that
`sp_credential_ownership` converges (hashed `secret_fingerprint` of app_id, no plaintext).
Injectable Protocol -> unit-testable without the azure sdk; the live client + NEXUS_LIVE_AZURE
lane is Task 14.
"""

from __future__ import annotations

from typing import Any, Protocol

from identity.tools.azure_ad import AzureAdServicePrincipal


class AzureSpSecretClient(Protocol):
    def list_service_principals(self) -> list[dict[str, Any]]: ...


class AzureSpSecretReader:
    __slots__ = ("_client",)

    def __init__(self, client: AzureSpSecretClient) -> None:
        self._client = client

    def read(self) -> tuple[AzureAdServicePrincipal, ...]:
        return tuple(
            AzureAdServicePrincipal(
                id=str(d["id"]),
                app_id=str(d["app_id"]),
                display_name=str(d.get("display_name", "")),
                sp_type=str(d.get("sp_type", "")),
                account_enabled=bool(d.get("account_enabled", True)),
            )
            for d in self._client.list_service_principals()
            if d.get("id") and d.get("app_id")
        )


__all__ = ["AzureSpSecretClient", "AzureSpSecretReader"]
