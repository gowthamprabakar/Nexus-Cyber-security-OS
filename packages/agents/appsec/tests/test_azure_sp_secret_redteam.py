"""Red-team bank for the Azure SP-secret detector + cross-agent convergence (slice #3 Azure)."""

from appsec.azure_sp_secret import leaked_azure_sp_secrets
from charter.canonical import secret_fingerprint
from identity.tools.azure_ad import AzureAdServicePrincipal, sp_credential_ownership

_APPID = "11111111-2222-3333-4444-555555555555"


def test_client_id_and_secret_together_is_a_leak():
    env = [("AZURE_CLIENT_ID", _APPID), ("AZURE_CLIENT_SECRET", "s0me-secret-value~xyz")]
    assert leaked_azure_sp_secrets(env) == [secret_fingerprint(_APPID)]


def test_fingerprint_reveals_nothing():
    fp = leaked_azure_sp_secrets(
        [("client_id", _APPID), ("client_secret", "topsecret")]
    )[0]
    assert _APPID not in fp and "topsecret" not in fp


# --- traps → nothing ---


def test_trap_client_id_alone_is_not_a_leak():
    # A bare appId GUID is a public identifier, not a leaked credential.
    assert leaked_azure_sp_secrets([("AZURE_CLIENT_ID", _APPID)]) == []


def test_trap_secret_without_guid_client_id():
    assert leaked_azure_sp_secrets([("AZURE_CLIENT_SECRET", "x"), ("CLIENT_ID", "not-a-guid")]) == []


def test_owner_and_appsec_fingerprints_converge():
    sp = AzureAdServicePrincipal(id="obj-1", app_id=_APPID, display_name="ci", sp_type="Application", account_enabled=True)
    owner_fp = sp_credential_ownership((sp,))[0][1]
    leak_fp = leaked_azure_sp_secrets([("AZURE_CLIENT_ID", _APPID), ("AZURE_CLIENT_SECRET", "y")])[0]
    assert owner_fp == leak_fp, "leak and owner must hash to the SAME SECRET node key"
