"""v0.5 Item 3 — GCP SA-key live reader maps into the convergence dataclass."""

from identity.tools.gcp_iam import sa_key_ownership
from identity.tools.gcp_sa_key_reader import GcpSaKeyReader


class _FakeSaKeyClient:
    def list_service_account_keys(self):
        return [{"service_account": "svc@proj.iam", "private_key_id": "kid-123"}]


def test_reader_output_drives_ownership_convergence():
    keys = GcpSaKeyReader(_FakeSaKeyClient()).read()
    owners = sa_key_ownership(keys)
    assert owners[0][0] == "svc@proj.iam"
    assert owners[0][1].startswith("secretfp:")  # hashed convergence, no plaintext
