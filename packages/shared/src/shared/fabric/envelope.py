"""OCSF v1.3 base event + Nexus extension envelope (per ADR-004).

The fabric wire format on `findings.>` is a vanilla OCSF v1.3 event dict with
a single extra key `nexus_envelope` carrying our cross-cutting metadata. We
keep OCSF as `dict[str, Any]` (no upstream stub library yet) and only typecheck
the Nexus envelope.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, fields
from typing import Any

_ENVELOPE_KEY = "nexus_envelope"


@dataclass(frozen=True, slots=True)
class NexusEnvelope:
    """Cross-cutting metadata attached to every fabric message.

    Carried alongside the OCSF payload so a consumer can reconstruct the full
    audit chain end-to-end: scanner → finding → agent reasoning → remediation.
    """

    correlation_id: str
    tenant_id: str
    agent_id: str
    nlah_version: str
    model_pin: str
    charter_invocation_id: str


_REQUIRED_FIELDS = tuple(f.name for f in fields(NexusEnvelope))


def wrap_ocsf(ocsf_event: dict[str, Any], envelope: NexusEnvelope) -> dict[str, Any]:
    """Return a new dict that is `ocsf_event` plus `nexus_envelope`.

    Does not mutate the input. The OCSF event is shallow-copied; nested
    structures inside are not deep-copied (callers are expected to treat
    fabric payloads as immutable once constructed).
    """
    if _ENVELOPE_KEY in ocsf_event:
        raise ValueError(f"ocsf_event already contains a {_ENVELOPE_KEY!r} key; cannot wrap twice")
    out = dict(ocsf_event)
    out[_ENVELOPE_KEY] = asdict(envelope)
    return out


def unwrap_ocsf(payload: dict[str, Any]) -> tuple[dict[str, Any], NexusEnvelope]:
    """Split a wrapped payload into (ocsf_event, envelope).

    Raises `ValueError` if the envelope is missing or malformed.
    """
    if _ENVELOPE_KEY not in payload:
        raise ValueError(f"payload missing {_ENVELOPE_KEY!r} key")
    raw_env = payload[_ENVELOPE_KEY]
    if not isinstance(raw_env, dict):
        raise ValueError(f"{_ENVELOPE_KEY!r} must be a dict, got {type(raw_env)}")

    missing = [f for f in _REQUIRED_FIELDS if f not in raw_env]
    if missing:
        raise ValueError(f"{_ENVELOPE_KEY!r} missing required fields: {missing}")
    extras = set(raw_env) - set(_REQUIRED_FIELDS)
    if extras:
        raise ValueError(f"{_ENVELOPE_KEY!r} contains unexpected fields: {sorted(extras)}")

    envelope = NexusEnvelope(**raw_env)
    event = {k: v for k, v in payload.items() if k != _ENVELOPE_KEY}
    return event, envelope
