"""data-security's canonical helper is a thin re-export of the shared
``charter.canonical`` single source of truth (ADR-023)."""

from charter.canonical import s3_bucket_arn as charter_s3
from data_security.canonical import s3_bucket_arn as ds_s3


def test_data_security_reexports_charter_canonical():
    # Single source of truth: the agent helper IS the charter helper.
    assert ds_s3 is charter_s3
    assert ds_s3("acme-pii") == "arn:aws:s3:::acme-pii"
