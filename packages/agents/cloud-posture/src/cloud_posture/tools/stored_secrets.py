"""Stored-secret detector (W6) — a workload that embeds a long-lived credential.

A public workload carrying a long-lived AWS access key in its environment is a credential-access
foothold: compromise the box, read the key, become whoever owns it. This extracts the **access key
ID** (the approved-plaintext identifier — never the secret access key) from a workload's env values
and emits ``(resource_arn, access_key_id)``. The SECRET node converges with identity's
``OWNS``/``OWNED_BY`` (same key id), so the walk
``workload --STORES_SECRET--> secret --OWNED_BY--> identity --HAS_ACCESS_TO--> data`` emerges.

GCP extension: ``gcp_stored_secret_grants`` detects a GCP service-account key JSON blob embedded in
a workload env value (raw or base64-encoded). It emits ONLY ``(resource_arn,
secret_fingerprint(private_key_id))`` — no raw key material, no ``private_key``, no full JSON. The
fingerprint is the SAME convergence key identity writes via ``record_sa_credential_ownership``, so
the stored-credential and its owning SA collapse onto one SECRET node.

Injectable input (the env values), so it is unit-tested without reading live ECS/Lambda task
definitions; the live env reader is the operator-gated follow-on.
"""

from __future__ import annotations

import base64
import json
import re
from typing import TYPE_CHECKING

from charter.canonical import secret_fingerprint

if TYPE_CHECKING:
    from collections.abc import Sequence

#: AWS access key ID — the NON-secret identifier (CloudTrail logs it). The matching secret access
#: key is never extracted or stored.
_AKIA_RE = re.compile(r"(AKIA|ASIA)[0-9A-Z]{16}")


def stored_secret_grants(
    workloads: Sequence[tuple[str, Sequence[str]]],
) -> list[tuple[str, str]]:
    """``(resource_arn, access_key_id)`` for each workload env value that holds an AWS key id.

    ``workloads`` is ``(resource_arn, env_values)``. Only the access key ID is extracted (the secret
    value is irrelevant — the id is the convergence key). Deduped, order-stable.
    """
    out: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for resource_arn, env_values in workloads:
        for value in env_values:
            m = _AKIA_RE.search(str(value))
            if m is None:
                continue
            grant = (resource_arn, m.group(0))
            if grant not in seen:
                seen.add(grant)
                out.append(grant)
    return out


def _parse_sa_key(value: str) -> dict[str, object] | None:
    """Return the parsed SA key dict if *value* is a GCP SA key (raw or base64-encoded JSON).

    Returns ``None`` for anything that is not a GCP service-account key blob. The private_key
    and private_key_id fields are present in the returned dict only as structural confirmation;
    callers must extract ONLY the fingerprint of private_key_id and discard the dict immediately.
    """
    text = value.strip()
    # Try raw JSON first, then base64-decoded JSON.
    for candidate in (text, None):
        if candidate is None:
            try:
                candidate = base64.b64decode(text, validate=False).decode("utf-8", errors="replace")
            except Exception:
                break
        try:
            obj = json.loads(candidate)
        except (ValueError, TypeError):
            continue
        if (
            isinstance(obj, dict)
            and obj.get("type") == "service_account"
            and bool(obj.get("private_key"))
            and bool(obj.get("private_key_id"))
            and bool(obj.get("client_email"))
        ):
            return obj
    return None


def gcp_stored_secret_grants(
    workloads: Sequence[tuple[str, Sequence[str]]],
) -> list[tuple[str, str]]:
    """``(resource_arn, secret_fingerprint(private_key_id))`` for each env value that is a GCP SA key.

    ``workloads`` is ``(resource_arn, env_values)``. Each env value is inspected structurally for a
    GCP service-account key blob (JSON with ``type == "service_account"`` + ``private_key`` +
    ``private_key_id`` + ``client_email``). Both raw JSON and base64-encoded JSON are handled.

    SECURITY: only ``secret_fingerprint(private_key_id)`` is emitted — never the raw ``private_key``,
    ``private_key_id``, or the JSON blob. The fingerprint is the SAME convergence key identity's
    ``record_sa_credential_ownership`` writes (both hash the same ``private_key_id``), so the
    STORES_SECRET leg and the OWNED_BY leg collapse onto one SECRET node. Deduped, order-stable.
    """
    out: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for resource_arn, env_values in workloads:
        for value in env_values:
            obj = _parse_sa_key(str(value))
            if obj is None:
                continue
            fp = secret_fingerprint(str(obj["private_key_id"]))
            grant = (resource_arn, fp)
            if grant not in seen:
                seen.add(grant)
                out.append(grant)
    return out


__all__ = ["gcp_stored_secret_grants", "stored_secret_grants"]
