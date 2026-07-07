"""W6 red-team bank — stored-credential extraction precision."""

import base64
import json

from charter.canonical import secret_fingerprint
from cloud_posture.tools.stored_secrets import gcp_stored_secret_grants, stored_secret_grants

_ARN = "arn:aws:ecs:us-east-1:111:service/web"
# Assembled so push-protection doesn't flag a literal key; AKIA + 16 chars.
_KEY = "AKIA" + "EXAMPLE0STORED01"

# GCP SA key fixture — synthetic values, never a real key.
_PRIVATE_KEY_ID = "aabbcc1122334455aabbcc1122334455aabbcc11"
_SA_KEY_JSON = json.dumps(
    {
        "type": "service_account",
        "project_id": "my-project",
        "private_key_id": _PRIVATE_KEY_ID,
        "private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIFAKE\n-----END RSA PRIVATE KEY-----\n",
        "client_email": "my-sa@my-project.iam.gserviceaccount.com",
        "client_id": "123456789",
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
    }
)
_SA_KEY_B64 = base64.b64encode(_SA_KEY_JSON.encode()).decode()


def test_extracts_access_key_id_from_env():
    out = stored_secret_grants([(_ARN, [f"AWS_ACCESS_KEY_ID={_KEY}"])])
    assert out == [(_ARN, _KEY)]


def test_bare_key_value():
    assert stored_secret_grants([(_ARN, [_KEY])]) == [(_ARN, _KEY)]


def test_dedup_same_key_twice():
    assert len(stored_secret_grants([(_ARN, [_KEY, f"X={_KEY}"])])) == 1


# --- traps → nothing ---


def test_trap_no_key_in_env():
    assert stored_secret_grants([(_ARN, ["LOG_LEVEL=debug", "PORT=8080"])]) == []


def test_trap_empty_env():
    assert stored_secret_grants([(_ARN, [])]) == []


# ---------------------------------------------------------------------------
# GCP SA key tests (W6 GCP extension)
# ---------------------------------------------------------------------------


def test_gcp_extracts_fingerprint_from_raw_json():
    """Raw SA key JSON in env value → (arn, fingerprint). SECURITY: no raw ids in output."""
    out = gcp_stored_secret_grants([(_ARN, [_SA_KEY_JSON])])
    assert len(out) == 1
    arn, fp = out[0]
    assert arn == _ARN
    assert fp == secret_fingerprint(_PRIVATE_KEY_ID)
    # SECURITY guard: raw private_key_id and private_key must NOT be in the emitted tuple.
    assert _PRIVATE_KEY_ID not in fp
    assert "FAKE" not in fp  # private_key content marker


def test_gcp_extracts_fingerprint_from_base64_json():
    """Base64-encoded SA key JSON in env value → (arn, fingerprint)."""
    out = gcp_stored_secret_grants([(_ARN, [_SA_KEY_B64])])
    assert len(out) == 1
    arn, fp = out[0]
    assert arn == _ARN
    assert fp == secret_fingerprint(_PRIVATE_KEY_ID)
    # SECURITY guard: raw ids must not appear in the fingerprint.
    assert _PRIVATE_KEY_ID not in fp


def test_gcp_fingerprint_starts_with_prefix():
    """Fingerprint uses the canonical secretfp: prefix (ADR-023)."""
    out = gcp_stored_secret_grants([(_ARN, [_SA_KEY_JSON])])
    _, fp = out[0]
    assert fp.startswith("secretfp:")


def test_gcp_dedup_same_key_twice():
    out = gcp_stored_secret_grants([(_ARN, [_SA_KEY_JSON, _SA_KEY_B64])])
    assert len(out) == 1


def test_gcp_trap_plain_string():
    assert gcp_stored_secret_grants([(_ARN, ["LOG_LEVEL=debug"])]) == []


def test_gcp_trap_non_sa_json():
    """JSON without service_account type → no grant."""
    other_json = json.dumps({"type": "authorized_user", "client_id": "x"})
    assert gcp_stored_secret_grants([(_ARN, [other_json])]) == []


def test_gcp_trap_missing_private_key():
    """JSON with type=service_account but missing private_key → no grant (incomplete blob)."""
    no_key = json.dumps(
        {
            "type": "service_account",
            "private_key_id": _PRIVATE_KEY_ID,
            "client_email": "sa@proj.iam.gserviceaccount.com",
            # private_key intentionally absent
        }
    )
    assert gcp_stored_secret_grants([(_ARN, [no_key])]) == []


def test_gcp_trap_missing_client_email():
    """JSON with type=service_account but missing client_email → no grant."""
    no_email = json.dumps(
        {
            "type": "service_account",
            "private_key_id": _PRIVATE_KEY_ID,
            "private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIFAKE\n-----END RSA PRIVATE KEY-----\n",
            # client_email intentionally absent
        }
    )
    assert gcp_stored_secret_grants([(_ARN, [no_email])]) == []


def test_gcp_trap_empty_env():
    assert gcp_stored_secret_grants([(_ARN, [])]) == []


def test_gcp_security_raw_private_key_not_in_output():
    """SECURITY: the raw private_key value must NEVER appear in any emitted tuple."""
    out = gcp_stored_secret_grants([(_ARN, [_SA_KEY_JSON])])
    assert out, "expected a grant"
    for tup in out:
        for item in tup:
            assert "FAKE" not in str(item), "raw private_key content leaked into output"
            assert _PRIVATE_KEY_ID not in str(item), "raw private_key_id leaked into output"
