"""Red-team bank for the structural GCP SA-key detector — slice #3 on GCP.

Precision crux: only a real service-account key JSON yields a fingerprint; non-SA JSON, malformed
text, and a key missing its id yield nothing. Privacy crux: the returned value reveals nothing of the
private key — it is a hash of the non-secret ``private_key_id`` only.
"""

import json

from appsec.gcp_sa_key import leaked_sa_key_fingerprints
from charter.canonical import secret_fingerprint

# A realistic SA-key shape. The "private key" here is a harmless placeholder, never a real key.
_SA_KEY = json.dumps(
    {
        "type": "service_account",
        "project_id": "prod-1",
        "private_key_id": "abc123def456",
        "private_key": "-----BEGIN PRIVATE KEY-----\nNOTAREALKEY\n-----END PRIVATE KEY-----\n",
        "client_email": "ci@prod-1.iam.gserviceaccount.com",
    }
)


def test_sa_key_yields_fingerprint_of_private_key_id():
    out = leaked_sa_key_fingerprints((_SA_KEY,))
    assert out == [secret_fingerprint("abc123def456")]


def test_fingerprint_leaks_nothing_of_the_private_key():
    fp = leaked_sa_key_fingerprints((_SA_KEY,))[0]
    assert "PRIVATE KEY" not in fp and "NOTAREALKEY" not in fp
    assert "abc123def456" not in fp  # even the id is hashed, not echoed


def test_dedup_same_key_twice():
    assert len(leaked_sa_key_fingerprints((_SA_KEY, _SA_KEY))) == 1


# ----------------------------- traps → nothing -----------------------------


def test_trap_non_sa_json_yields_nothing():
    # Valid JSON, but not a service-account key (a config file that happens to be JSON).
    assert leaked_sa_key_fingerprints((json.dumps({"type": "config", "value": 1}),)) == []


def test_trap_missing_private_key_id_yields_nothing():
    obj = {"type": "service_account", "private_key": "x", "client_email": "a@b"}
    assert leaked_sa_key_fingerprints((json.dumps(obj),)) == []


def test_trap_malformed_text_yields_nothing():
    assert leaked_sa_key_fingerprints(("not json at all", "{broken", "")) == []
