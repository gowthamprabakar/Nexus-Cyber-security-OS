"""Multi-cloud posture schemas — re-export F.3's OCSF v1.3 Compliance Finding.

**Q1 resolution (per the D.5 plan).** D.5 emits the **identical wire shape**
as F.3 Cloud Posture (`class_uid 2003 Compliance Finding`) — no fork, no
duplication. The schema-as-typing-layer pattern is unchanged; D.5 adds a
`CloudProvider` enum and a `CSPMFindingType` discriminator that ride
inside the existing OCSF surface.

Cross-agent OCSF inventory after D.5 (CSPM family):

| Agent                            | OCSF class_uid | Class name             | Discriminator         |
| -------------------------------- | -------------- | ---------------------- | --------------------- |
| Cloud Posture (F.3) — AWS        | 2003           | Compliance Finding     | (none — AWS only)     |
| **Multi-Cloud Posture (D.5)**    | **2003**       | **Compliance Finding** | **CSPMFindingType**   |

Re-exports from `cloud_posture.schemas`:
- `OCSF_*` constants
- `Severity` enum
- `AffectedResource` model
- `CloudPostureFinding` typed wrapper
- `build_finding` constructor
- `FindingsReport` aggregate
- `FINDING_ID_RE` (validates `CSPM-<CLOUD>-<SVC>-<NNN>-<context>`)

D.5-specific additions:
- `CloudProvider` enum (AZURE / GCP) — explicit filter key
- `CSPMFindingType` enum (4 discriminators, one per source feed)
- helpers for D.5 finding-id construction
"""

from __future__ import annotations

import re
from enum import StrEnum

from cloud_posture.schemas import (
    FINDING_ID_RE,
    OCSF_CATEGORY_NAME,
    OCSF_CATEGORY_UID,
    OCSF_CLASS_NAME,
    OCSF_CLASS_UID,
    OCSF_VERSION,
    AffectedResource,
    CloudPostureFinding,
    FindingsReport,
    Severity,
    build_finding,
    severity_from_id,
    severity_to_id,
)


class CloudProvider(StrEnum):
    """The cloud whose findings produced this OCSF event."""

    AZURE = "azure"
    GCP = "gcp"


class CSPMFindingType(StrEnum):
    """The source-feed discriminator. Drives `finding_info.types[0]`."""

    AZURE_DEFENDER = "cspm_azure_defender"
    AZURE_ACTIVITY = "cspm_azure_activity"
    GCP_SCC = "cspm_gcp_scc"
    GCP_IAM = "cspm_gcp_iam"


# Maps the discriminator to the short token used in finding_id construction.
# F.3's FINDING_ID_RE is `CSPM-[A-Z]+-[A-Z0-9]+-\d{3}-[a-z0-9_-]+`; the first
# bracket is the cloud, the second is the service/source.
_FT_PROVIDER: dict[CSPMFindingType, CloudProvider] = {
    CSPMFindingType.AZURE_DEFENDER: CloudProvider.AZURE,
    CSPMFindingType.AZURE_ACTIVITY: CloudProvider.AZURE,
    CSPMFindingType.GCP_SCC: CloudProvider.GCP,
    CSPMFindingType.GCP_IAM: CloudProvider.GCP,
}

_FT_SOURCE_TOKEN: dict[CSPMFindingType, str] = {
    CSPMFindingType.AZURE_DEFENDER: "DEFENDER",
    CSPMFindingType.AZURE_ACTIVITY: "ACTIVITY",
    CSPMFindingType.GCP_SCC: "SCC",
    CSPMFindingType.GCP_IAM: "IAM",
}


def cloud_provider_for(finding_type: CSPMFindingType) -> CloudProvider:
    """Return the `CloudProvider` enum value for a `CSPMFindingType`."""
    return _FT_PROVIDER[finding_type]


def source_token(finding_type: CSPMFindingType) -> str:
    """Return the finding-id source-token for a `CSPMFindingType`."""
    return _FT_SOURCE_TOKEN[finding_type]


def short_resource_token(resource_id: str) -> str:
    """Extract a finding-id-safe token from an Azure/GCP resource ID.

    Azure resource IDs are slash-separated paths
    (`/subscriptions/<id>/resourceGroups/<rg>/...`); we extract a 12-char
    upper-case alphanumeric tail. GCP resource names follow
    `projects/<id>/locations/<l>/...` — same treatment.
    """
    safe = re.sub(r"[^A-Za-z0-9]", "", resource_id).upper()
    if not safe:
        return "UNKNOWN"
    return safe[-12:] if len(safe) >= 12 else safe


__all__ = [
    "FINDING_ID_RE",
    "OCSF_CATEGORY_NAME",
    "OCSF_CATEGORY_UID",
    "OCSF_CLASS_NAME",
    "OCSF_CLASS_UID",
    "OCSF_VERSION",
    "AffectedResource",
    "CSPMFindingType",
    "CloudPostureFinding",
    "CloudProvider",
    "FindingsReport",
    "Severity",
    "build_finding",
    "cloud_provider_for",
    "severity_from_id",
    "severity_to_id",
    "short_resource_token",
    "source_token",
]
