"""Starting CIS Google Cloud Platform Foundation Benchmark rule subset (D.5 v0.2 Task 11).

**10 new non-IAM native rules** across 6 resource types — added to the existing
~5 IAM-binding rules (`tools/gcp_iam.py`, tagged `GCP_IAM`) for **~15 native GCP
detections total** at v0.2. A *starting subset* per Q4; the full CIS-GCP benchmark
is v0.3 (WI-D3 honesty). Each rule is a pure predicate over a `GcpResource`.
"""

from __future__ import annotations

from collections.abc import Iterable

from multi_cloud_posture.rules_gcp.engine import GcpNativeRule, GcpResource
from multi_cloud_posture.schemas import Severity

_PUBLIC_MEMBERS = {"allusers", "allauthenticatedusers"}
_ANY_CIDR = {"0.0.0.0/0", "::/0"}


def _bucket_public(r: GcpResource) -> bool:
    members: Iterable[str] = r.properties.get("iam_members", []) or []
    return any(str(m).split(":")[-1].lower() in _PUBLIC_MEMBERS for m in members)


def _firewall_allows_port_from_any(r: GcpResource, port: int) -> bool:
    if str(r.properties.get("direction", "INGRESS")).upper() != "INGRESS":
        return False
    src_ranges = {str(c).strip() for c in (r.properties.get("source_ranges", []) or [])}
    if not (src_ranges & _ANY_CIDR):
        return False
    for allowed in r.properties.get("allowed", []) or []:
        if str(allowed.get("IPProtocol", "")).lower() not in ("tcp", "all"):
            continue
        ports = allowed.get("ports")
        if ports is None:  # no ports => all ports
            return True
        if any(_port_in_spec(port, str(p)) for p in ports):
            return True
    return False


def _port_in_spec(port: int, spec: str) -> bool:
    spec = spec.strip()
    if "-" in spec:
        lo, _, hi = spec.partition("-")
        try:
            return int(lo) <= port <= int(hi)
        except ValueError:
            return False
    try:
        return int(spec) == port
    except ValueError:
        return False


GCP_CIS_RULES: tuple[GcpNativeRule, ...] = (
    GcpNativeRule(
        rule_id="MCSPM-GCP-STORAGE-001",
        title="Cloud Storage bucket is publicly accessible",
        description="The bucket grants access to allUsers / allAuthenticatedUsers; remove public IAM members.",
        severity=Severity.HIGH,
        resource_type="storage_bucket",
        is_violation=_bucket_public,
    ),
    GcpNativeRule(
        rule_id="MCSPM-GCP-STORAGE-002",
        title="Cloud Storage bucket uniform bucket-level access disabled",
        description="Uniform bucket-level access is off; enable it so ACLs cannot bypass IAM.",
        severity=Severity.MEDIUM,
        resource_type="storage_bucket",
        is_violation=lambda r: not r.properties.get("uniform_bucket_level_access", False),
    ),
    GcpNativeRule(
        rule_id="MCSPM-GCP-SQL-001",
        title="Cloud SQL instance exposes a public IP",
        description="The instance has a public IPv4 address; use private IP / authorized networks.",
        severity=Severity.HIGH,
        resource_type="cloud_sql_instance",
        is_violation=lambda r: bool(r.properties.get("public_ip", False)),
    ),
    GcpNativeRule(
        rule_id="MCSPM-GCP-SQL-002",
        title="Cloud SQL instance does not require SSL",
        description="SSL/TLS is not required for connections; enforce SSL.",
        severity=Severity.MEDIUM,
        resource_type="cloud_sql_instance",
        is_violation=lambda r: not r.properties.get("require_ssl", False),
    ),
    GcpNativeRule(
        rule_id="MCSPM-GCP-GCE-001",
        title="Compute instance has a public IP without firewall protection",
        description="The instance has an external IP; ensure ingress is tightly restricted.",
        severity=Severity.MEDIUM,
        resource_type="compute_instance",
        is_violation=lambda r: bool(r.properties.get("has_external_ip", False)),
    ),
    GcpNativeRule(
        rule_id="MCSPM-GCP-GCE-002",
        title="Compute instance uses the default service account with Editor",
        description="The instance runs as the default SA with project Editor; use a least-privilege SA.",
        severity=Severity.HIGH,
        resource_type="compute_instance",
        is_violation=lambda r: (
            bool(r.properties.get("default_service_account", False))
            and bool(r.properties.get("editor_role", False))
        ),
    ),
    GcpNativeRule(
        rule_id="MCSPM-GCP-FIREWALL-001",
        title="Firewall allows SSH (22) from 0.0.0.0/0",
        description="An ingress firewall rule allows TCP/22 from anywhere; restrict the source ranges.",
        severity=Severity.HIGH,
        resource_type="firewall",
        is_violation=lambda r: _firewall_allows_port_from_any(r, 22),
    ),
    GcpNativeRule(
        rule_id="MCSPM-GCP-FIREWALL-002",
        title="Firewall allows RDP (3389) from 0.0.0.0/0",
        description="An ingress firewall rule allows TCP/3389 from anywhere; restrict the source ranges.",
        severity=Severity.HIGH,
        resource_type="firewall",
        is_violation=lambda r: _firewall_allows_port_from_any(r, 3389),
    ),
    GcpNativeRule(
        rule_id="MCSPM-GCP-KMS-001",
        title="KMS crypto key rotation not configured",
        description="The key has no rotation period; configure rotation (<= 90 days).",
        severity=Severity.MEDIUM,
        resource_type="kms_key",
        is_violation=lambda r: not r.properties.get("rotation_period"),
    ),
    GcpNativeRule(
        rule_id="MCSPM-GCP-BIGQUERY-001",
        title="BigQuery dataset is publicly accessible",
        description="The dataset grants access to allUsers / allAuthenticatedUsers; remove public access.",
        severity=Severity.HIGH,
        resource_type="bigquery_dataset",
        is_violation=lambda r: any(
            str(m).split(":")[-1].lower() in _PUBLIC_MEMBERS
            for m in (r.properties.get("access_members", []) or [])
        ),
    ),
)
