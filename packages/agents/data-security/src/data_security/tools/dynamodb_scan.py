"""``scan_dynamodb`` — live DynamoDB content classification (v0.4 Stage 1.2).

Scans DynamoDB table items (sample-bounded) and classifies their string attribute
values for sensitive data, returning **labels only** per table — the matched values
themselves are NEVER returned or persisted (the Q6 privacy contract, same as the S3
object-sample path). The classifier (`classify`) returns a `ClassifierLabel` enum
value; this tool aggregates the non-`NONE` labels per table.

Charter-registered tool (ADR-016 tool-proxy): the boto3 scan is the cloud call;
``dynamodb_to_findings`` (pure, no cloud) turns the labels into OCSF 2003 findings.
"""

from __future__ import annotations

import boto3

from data_security.classifiers import classify
from data_security.schemas import ClassifierLabel

#: Sample bound per table — caps classifier false-positive surface + scan cost,
#: matching the S3 sample-based posture (PRD §7.1.4).
DEFAULT_MAX_ITEMS = 100


async def scan_dynamodb(
    *,
    account_id: str,
    profile: str | None = None,
    region: str | None = None,
    max_items: int = DEFAULT_MAX_ITEMS,
) -> dict[str, list[str]]:
    """Scan every table's sampled items → ``{table_name: [sensitive label values]}``.

    Returns label values only (e.g. ``["email", "ssn"]``) — never the matched
    substrings. Tables with no sensitive data are omitted. ``account_id`` is part
    of the live-route contract (mirrors ``scan_s3_live``); the boto3 default
    credential chain / ``profile`` resolves the actual account.
    """
    del account_id  # resolved via the credential chain; part of the live contract
    session = boto3.Session(profile_name=profile) if profile else boto3.Session()
    client = session.client("dynamodb", region_name=region)

    hits: dict[str, list[str]] = {}
    table_names = client.list_tables().get("TableNames", [])
    for table in table_names:
        labels: set[ClassifierLabel] = set()
        scanned = client.scan(TableName=table, Limit=max_items)
        for item in scanned.get("Items", []):
            for attr_value in item.values():
                # DynamoDB attribute values are typed dicts; only string ("S")
                # attributes are classifiable text.
                text = attr_value.get("S") if isinstance(attr_value, dict) else None
                if not isinstance(text, str) or not text:
                    continue
                label = classify(text)
                if label is not ClassifierLabel.NONE:
                    labels.add(label)
        if labels:
            hits[table] = sorted(label.value for label in labels)
    return hits


__all__ = ["DEFAULT_MAX_ITEMS", "scan_dynamodb"]
