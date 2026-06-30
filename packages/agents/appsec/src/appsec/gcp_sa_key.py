"""Structural GCP service-account key detector — slice #3 on GCP (leaked-credential blast radius).

A GCP SA key is a JSON blob, not a single token: its secret (``private_key``) and its non-secret id
(``private_key_id``) are *different fields*, so a regex-on-the-match (the way ``AKIA…`` is extracted)
cannot recover a stable identifier. This parses the candidate file structurally and returns ONLY the
``secret_fingerprint(private_key_id)`` — the private key material is read to validate the blob but
never retained or returned. The fingerprint is the convergence key identity hashes from the same
``private_key_id`` (via the GCP IAM key list), so leak ⇄ owner collapse onto one SECRET node with
nothing readable stored (the operator-chosen hashed-convergence design).
"""

from __future__ import annotations

import json

from charter.canonical import secret_fingerprint


def _is_sa_key(obj: object) -> bool:
    return (
        isinstance(obj, dict)
        and obj.get("type") == "service_account"
        and bool(obj.get("private_key"))
        and bool(obj.get("private_key_id"))
    )


def leaked_sa_key_fingerprints(file_texts: tuple[str, ...]) -> list[str]:
    """``secret_fingerprint(private_key_id)`` for each candidate text that IS a GCP SA key.

    A text that is not valid JSON, or is JSON but not a service-account key (no ``private_key`` /
    ``private_key_id``), yields nothing — the precision crux. Deduped, order-stable. NOTHING from the
    private key is retained; only the fingerprint of the non-secret ``private_key_id`` is returned.
    """
    out: list[str] = []
    seen: set[str] = set()
    for text in file_texts:
        try:
            obj = json.loads(text)
        except (ValueError, TypeError):
            continue
        if not _is_sa_key(obj):
            continue
        fp = secret_fingerprint(str(obj["private_key_id"]))
        if fp not in seen:
            seen.add(fp)
            out.append(fp)
    return out


__all__ = ["leaked_sa_key_fingerprints"]
