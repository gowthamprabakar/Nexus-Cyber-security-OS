"""Subject builders for the five fabric buses (per ADR-004).

NATS subjects are dot-separated tokens; only [A-Za-z0-9_-] is permitted in our
tokens (NATS itself allows more, but we narrow for predictability and to keep
ACL-by-prefix simple). Inputs that are user/cloud-supplied (asset ARNs etc.)
are SHA-256-truncated to a stable hash so the subject space is always safe.
"""

from __future__ import annotations

import hashlib
import re

_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_ASSET_HASH_LEN = 16  # hex chars of sha256 → 64 bits, ample for asset cardinality


def _validate_token(token: str, name: str) -> None:
    if not token or not _TOKEN_RE.match(token):
        raise ValueError(f"invalid {name}: {token!r} — must match {_TOKEN_RE.pattern}")


def _hash_asset(asset_id: str) -> str:
    return hashlib.sha256(asset_id.encode("utf-8")).hexdigest()[:_ASSET_HASH_LEN]


def events_subject(tenant_id: str, event_type: str) -> str:
    """`events.tenant.<tid>.<event_type>` — within-plane pub/sub."""
    _validate_token(tenant_id, "tenant_id")
    _validate_token(event_type, "event_type")
    return f"events.tenant.{tenant_id}.{event_type}"


def findings_subject(tenant_id: str, asset_id: str) -> str:
    """`findings.tenant.<tid>.asset.<sha256[:16]>` — normalized OCSF findings."""
    _validate_token(tenant_id, "tenant_id")
    if not asset_id:
        raise ValueError("asset_id must be non-empty")
    return f"findings.tenant.{tenant_id}.asset.{_hash_asset(asset_id)}"


def commands_subject(edge_id: str, command_type: str) -> str:
    """`commands.edge.<eid>.<command_type>` — control-plane → edge."""
    _validate_token(edge_id, "edge_id")
    _validate_token(command_type, "command_type")
    return f"commands.edge.{edge_id}.{command_type}"


def approvals_subject(tenant_id: str, finding_id: str) -> str:
    """`approvals.tenant.<tid>.finding.<fid>` — Tier-2 ChatOps loop."""
    _validate_token(tenant_id, "tenant_id")
    _validate_token(finding_id, "finding_id")
    return f"approvals.tenant.{tenant_id}.finding.{finding_id}"


def audit_subject(tenant_id: str) -> str:
    """`audit.tenant.<tid>` — append-only signed audit stream."""
    _validate_token(tenant_id, "tenant_id")
    return f"audit.tenant.{tenant_id}"
