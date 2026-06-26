"""Unit tests for the cross-cloud grant resolvers (gap #13 access leg) — the parsing teeth."""

from charter.canonical import azure_blob_uri, gcs_uri
from identity.tools.azure_rbac import AzureRbacLiveReader, AzureRoleAssignment, blob_read_grants
from identity.tools.gcp_iam import GcpIamBinding, GcpIamLiveReader, storage_read_grants

_CONTAINER = (
    "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage"
    "/storageAccounts/acme/blobServices/default/containers/reports"
)
_ACCOUNT_SCOPE = (
    "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/acme"
)


def test_azure_container_scoped_blob_read_resolves_to_canonical_key() -> None:
    grants = blob_read_grants((AzureRoleAssignment("p1", "Storage Blob Data Reader", _CONTAINER),))
    assert grants == [("p1", azure_blob_uri("acme", "reports"))]


def test_azure_non_blob_role_is_skipped() -> None:
    # Owner is control-plane, not a blob *data* role → no data-plane read grant.
    assert blob_read_grants((AzureRoleAssignment("p1", "Owner", _CONTAINER),)) == []


def test_azure_account_level_scope_is_not_fine_grained() -> None:
    # Account-scoped is broad, not the per-container least-privilege path 4 is about.
    assert (
        blob_read_grants((AzureRoleAssignment("p1", "Storage Blob Data Reader", _ACCOUNT_SCOPE),))
        == []
    )


def test_azure_reader_skips_malformed_rows() -> None:
    class _C:
        def list_role_assignments(self) -> list[dict[str, object]]:
            return [{"principal_id": "p1"}, "nonsense", {"role_name": "x", "scope": "y"}]

    assert AzureRbacLiveReader(_C()).read() == ()


def test_gcp_object_read_binding_resolves_per_member() -> None:
    grants = storage_read_grants(
        (GcpIamBinding("reports", "roles/storage.objectViewer", ("user:a", "user:b")),)
    )
    assert grants == [("user:a", gcs_uri("reports")), ("user:b", gcs_uri("reports"))]


def test_gcp_public_member_is_dropped() -> None:
    # allUsers is bucket-level public exposure (storage writer's job), not a per-principal grant.
    grants = storage_read_grants(
        (GcpIamBinding("reports", "roles/storage.objectViewer", ("allUsers", "user:a")),)
    )
    assert grants == [("user:a", gcs_uri("reports"))]


def test_gcp_non_read_role_is_skipped() -> None:
    assert (
        storage_read_grants(
            (GcpIamBinding("reports", "roles/storage.legacyBucketWriter", ("user:a",)),)
        )
        == []
    )


def test_gcp_reader_flattens_and_skips_malformed() -> None:
    class _C:
        def list_bucket_bindings(self) -> list[dict[str, object]]:
            return [{"bucket": "b", "role": "roles/storage.admin", "members": ["user:a"]}, 7]

    parsed = GcpIamLiveReader(_C()).read()
    assert parsed == (GcpIamBinding("b", "roles/storage.admin", ("user:a",)),)
