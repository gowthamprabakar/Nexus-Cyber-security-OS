"""GCP SA-key ownership detector + the cross-agent convergence proof — slice #3 on GCP.

The whole design rests on one fact: identity's fingerprint of a key's ``private_key_id`` must EQUAL
appsec's fingerprint of the same id, or leak and owner never meet on the graph. This pins that.
"""

from appsec.gcp_sa_key import leaked_sa_key_fingerprints
from identity.tools.gcp_iam import GcpServiceAccountKey, sa_key_ownership

_SA = "ci@prod-1.iam.gserviceaccount.com"
_KEY_ID = "abc123def456"


def test_ownership_maps_sa_to_fingerprint():
    grants = sa_key_ownership((GcpServiceAccountKey(_SA, _KEY_ID),))
    assert len(grants) == 1
    assert grants[0][0] == _SA


def test_owner_and_appsec_fingerprints_converge():
    # identity's fingerprint (from the IAM key list) == appsec's fingerprint (from the leaked JSON).
    sa_key_json = '{"type":"service_account","private_key":"x","private_key_id":"' + _KEY_ID + '"}'
    owner_fp = sa_key_ownership((GcpServiceAccountKey(_SA, _KEY_ID),))[0][1]
    leak_fp = leaked_sa_key_fingerprints((sa_key_json,))[0]
    assert owner_fp == leak_fp, "leak and owner must hash to the SAME SECRET node key"


def test_dedup_same_key():
    keys = (GcpServiceAccountKey(_SA, _KEY_ID), GcpServiceAccountKey(_SA, _KEY_ID))
    assert len(sa_key_ownership(keys)) == 1
