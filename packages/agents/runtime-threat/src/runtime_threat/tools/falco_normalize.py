"""Falco live event normalization + enrichment (D.3 v0.2 Task 4).

Turns a raw Falco gRPC event dict into the same `FalcoAlert` the offline path produces
(so downstream stays byte-identical), plus **process-tree** and **container / k8s**
context enrichment pulled from `output_fields`. The receive timestamp is **caller-
provided** (`received_at`) so the normalizer stays deterministic — the real-time
subscriber stamps it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from runtime_threat.tools.falco import FalcoAlert, _parse_time


@dataclass(frozen=True, slots=True)
class ProcessContext:
    name: str = ""
    pid: str = ""
    ppid: str = ""
    parent_name: str = ""
    cmdline: str = ""


@dataclass(frozen=True, slots=True)
class ContainerContext:
    id: str = ""
    image: str = ""
    name: str = ""


@dataclass(frozen=True, slots=True)
class K8sContext:
    pod: str = ""
    namespace: str = ""


@dataclass(frozen=True, slots=True)
class FalcoEnrichment:
    process: ProcessContext = field(default_factory=ProcessContext)
    container: ContainerContext = field(default_factory=ContainerContext)
    k8s: K8sContext = field(default_factory=K8sContext)


@dataclass(frozen=True, slots=True)
class NormalizedFalcoEvent:
    alert: FalcoAlert
    enrichment: FalcoEnrichment


def _f(fields: dict[str, Any], key: str) -> str:
    v = fields.get(key)
    return str(v) if v is not None else ""


def enrich(alert: FalcoAlert) -> FalcoEnrichment:
    """Pull process-tree + container + k8s context out of an alert's output_fields."""
    f = alert.output_fields
    image = _f(f, "container.image.repository") or _f(f, "container.image")
    return FalcoEnrichment(
        process=ProcessContext(
            name=_f(f, "proc.name"),
            pid=_f(f, "proc.pid"),
            ppid=_f(f, "proc.ppid"),
            parent_name=_f(f, "proc.pname"),
            cmdline=_f(f, "proc.cmdline"),
        ),
        container=ContainerContext(
            id=_f(f, "container.id"),
            image=image,
            name=_f(f, "container.name"),
        ),
        k8s=K8sContext(pod=_f(f, "k8s.pod.name"), namespace=_f(f, "k8s.ns.name")),
    )


def normalize_falco_event(
    raw: dict[str, Any], *, received_at: datetime
) -> NormalizedFalcoEvent | None:
    """Normalize a raw Falco event → `(FalcoAlert, FalcoEnrichment)`. Returns `None` if the
    event has no rule name. ``received_at`` is used when the event carries no own time."""
    rule = raw.get("rule")
    if not isinstance(rule, str) or not rule:
        return None
    fields = raw.get("output_fields")
    if not isinstance(fields, dict):
        fields = {}
    alert = FalcoAlert(
        time=_parse_time(raw.get("time")) or received_at,
        rule=rule,
        priority=str(raw.get("priority", "")),
        output=str(raw.get("output", "")),
        output_fields=fields,
        tags=tuple(str(t) for t in raw.get("tags", [])),
    )
    return NormalizedFalcoEvent(alert=alert, enrichment=enrich(alert))
