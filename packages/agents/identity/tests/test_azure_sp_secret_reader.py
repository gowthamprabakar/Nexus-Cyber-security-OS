"""v0.5 Item 3 — Azure SP-secret live reader maps into the convergence dataclass."""

from identity.tools.azure_ad import azure_sp_key, sp_credential_ownership
from identity.tools.azure_sp_secret_reader import AzureSpSecretReader


class _FakeSpClient:
    def list_service_principals(self):
        return [
            {
                "id": "o1",
                "app_id": "appid-123",
                "display_name": "svc",
                "sp_type": "Application",
                "account_enabled": True,
            }
        ]


def test_reader_output_drives_ownership_convergence():
    sps = AzureSpSecretReader(_FakeSpClient()).read()
    owners = sp_credential_ownership(sps)
    assert owners[0][0] == azure_sp_key("appid-123")  # "azuread:sp:appid-123"
    assert owners[0][1].startswith("secretfp:")  # hashed convergence, no plaintext
