"""BP4 — the candidate feedback loop: the growth mechanism of the generic engine.

The candidate tier (path_engine) surfaces novel paths no named detector covers. This module is the
analyst loop on top of it:

- **dismiss → suppress signature.** A reviewed-as-noise shape is recorded; the engine stops
  surfacing every candidate of that shape (``find_candidate_paths(..., suppressed=...)``).
- **confirm → auto-draft a named archetype.** A confirmed candidate becomes a ready-to-review draft
  — the suggested name/severity, the ``NAMED_SHAPES`` entry that retires it from the candidate tier
  once shipped, and a detector sketch + the exact slice checklist (the same touch-points every named
  detector needs). This is how the product grows detectors from discoveries instead of hand-guessing.

A candidate's **signature** ``(source_marker, sink_marker, edge_signature)`` is the stable key for
both: the shape, not the specific node instances. Suppress/confirm act on the shape.

Persistence is a seam: :class:`FeedbackLog` is in-memory + serializable (``to_dict`` / ``from_dict``)
so BP7 (continuous run) can persist decisions to the store or a file. The mechanics here are pure.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from meta_harness.path_taxonomy import SINK_MARKERS, SOURCE_MARKERS

if TYPE_CHECKING:
    from meta_harness.path_engine import CandidatePath, GenericPath

#: The stable promote/suppress key: (source_marker, sink_marker, edge_signature).
Signature = tuple[str, str, tuple[str, ...]]

_SOURCE_CATEGORY = {m.name: m.category.value for m in SOURCE_MARKERS}
_SINK_CATEGORY = {m.name: m.category.value for m in SINK_MARKERS}


def signature_of(path: GenericPath | CandidatePath) -> Signature:
    """The shape key of a candidate or its path — what suppress/confirm act on."""
    p = path.path if hasattr(path, "path") else path
    return (p.source_marker, p.sink_marker, p.edge_signature)


@dataclass(frozen=True, slots=True)
class ArchetypeDraft:
    """A ready-to-review named-detector draft auto-generated from a confirmed candidate.

    Not auto-merged: ``detector_sketch`` + ``checklist`` are a human's starting point (the same
    slice every named detector needs), and ``suggested_severity`` is a starting product judgment.
    """

    name: str
    label: str
    source_marker: str
    sink_marker: str
    edge_signature: tuple[str, ...]
    suggested_severity: int
    named_shape_entry: Signature
    detector_sketch: str
    checklist: tuple[str, ...]


def _draft_name(source_marker: str, sink_marker: str) -> str:
    """A snake_case path_type suggestion from the shape, e.g. ``runtime_detection_to_sensitive_data``."""
    return f"{source_marker}_to_{sink_marker}"


def _suggested_severity(candidate_score: int) -> int:
    """Lift the (capped-below-confirmed) candidate score into a sane named band as a starting point."""
    return min(90, max(58, round(candidate_score * 1.4)))


def _detector_sketch(
    name: str, source_marker: str, sink_marker: str, edges: tuple[str, ...]
) -> str:
    """A kg_query detector skeleton that walks the signature — a scaffold to complete, not to ship."""
    source_cat = _SOURCE_CATEGORY.get(source_marker, "<SOURCE_CATEGORY>")
    sink_cat = _SINK_CATEGORY.get(sink_marker, "<SINK_CATEGORY>")
    lines = [
        f"async def find_{name}(self) -> list[{name.title().replace('_', '')}]:",
        f'    """{source_marker} -> {sink_marker} via {"/".join(edges)} '
        '(auto-drafted from a confirmed candidate — REVIEW before shipping)."""',
        "    hits = []",
        "    sources = await self._semantic_store.list_entities_by_type(",
        f"        tenant_id=self._customer_id, entity_type={source_cat!r}",
        "    )",
        "    for src in sources:",
        f"        # TODO: assert src matches the {source_marker!r} marker predicate",
    ]
    indent = "        "
    node_ref = "src.entity_id"  # a node uses .entity_id; an edge row uses .dst_entity_id
    for i, edge in enumerate(edges):
        nxt = f"e{i}"
        lines.append(f"{indent}for {nxt} in await self._edges_from({node_ref}, ({edge!r},)):")
        indent += "    "
        node_ref = f"{nxt}.dst_entity_id"
    lines.append(f"{indent}sink = await self._semantic_store.get_entity(")
    lines.append(f"{indent}    tenant_id=self._customer_id, entity_id={node_ref}")
    lines.append(f"{indent})")
    lines.append(
        f"{indent}# TODO: assert sink is a {sink_cat!r} matching the {sink_marker!r} marker"
    )
    lines.append(f"{indent}# hits.append(...)")
    lines.append("    return hits")
    return "\n".join(lines)


def draft_archetype(candidate: CandidatePath) -> ArchetypeDraft:
    """Turn a confirmed candidate into a reviewable named-archetype draft (the growth loop)."""
    p = candidate.path
    name = _draft_name(p.source_marker, p.sink_marker)
    label = name.replace("_", " ").capitalize()
    severity = _suggested_severity(candidate.score)
    checklist = (
        f"add {(p.source_marker, p.sink_marker, p.edge_signature)!r} to path_engine.NAMED_SHAPES "
        "(retires it from the candidate tier)",
        f"add a find_{name} detector to kg_query.py (sketch below) + a frozen result dataclass",
        f"wire it into attack_paths.AttackPathRanker.find_all + _SEVERITY[{name!r}] = {severity} "
        "(review) + a _title branch",
        f"add attack_path_remediation.REMEDIATION[{name!r}] and attack_path_report._LABELS[{name!r}]",
        f"add a REAL e2e that drives the feeders producing this shape and asserts the {name!r} path",
    )
    return ArchetypeDraft(
        name=name,
        label=label,
        source_marker=p.source_marker,
        sink_marker=p.sink_marker,
        edge_signature=p.edge_signature,
        suggested_severity=severity,
        named_shape_entry=(p.source_marker, p.sink_marker, p.edge_signature),
        detector_sketch=_detector_sketch(name, p.source_marker, p.sink_marker, p.edge_signature),
        checklist=checklist,
    )


@dataclass(slots=True)
class FeedbackLog:
    """Analyst decisions keyed by candidate signature. In-memory + serializable (persistence = BP7).

    ``"dismiss"`` suppresses a shape (the engine stops surfacing it); ``"confirm"`` marks it for
    promotion to a named detector. Last decision per signature wins.
    """

    decisions: dict[Signature, str] = field(default_factory=dict)

    def record(self, decision: str, signature: Signature) -> None:
        if decision not in ("confirm", "dismiss"):
            raise ValueError(f"decision must be 'confirm' or 'dismiss', got {decision!r}")
        self.decisions[signature] = decision

    def dismiss(self, candidate: CandidatePath) -> None:
        self.record("dismiss", signature_of(candidate))

    def confirm(self, candidate: CandidatePath) -> None:
        self.record("confirm", signature_of(candidate))

    def suppressed_signatures(self) -> frozenset[Signature]:
        """The dismissed shapes — pass to ``find_candidate_paths(suppressed=...)``."""
        return frozenset(sig for sig, d in self.decisions.items() if d == "dismiss")

    def confirmed_signatures(self) -> frozenset[Signature]:
        return frozenset(sig for sig, d in self.decisions.items() if d == "confirm")

    def to_dict(self) -> dict[str, str]:
        """Serializable form (signature -> decision), for persistence. Keys are ``src|sink|e1,e2``."""
        return {f"{s}|{k}|{','.join(sig)}": d for (s, k, sig), d in self.decisions.items()}

    @classmethod
    def from_dict(cls, data: dict[str, str]) -> FeedbackLog:
        decisions: dict[Signature, str] = {}
        for key, decision in data.items():
            src, sink, edges = key.split("|")
            decisions[(src, sink, tuple(e for e in edges.split(",") if e))] = decision
        return cls(decisions=decisions)


__all__ = [
    "ArchetypeDraft",
    "FeedbackLog",
    "Signature",
    "draft_archetype",
    "signature_of",
]
