"""`map_to_mitre` — MITRE ATT&CK v14.x heuristic mapper (D.7 Task 7).

Walks evidence (str / dict / list / nested), matches keywords against a
bundled ATT&CK 14.1 table, and returns the matched techniques ranked by
hit count.

The table lives at `packages/agents/investigation/data/mitre_attack_14.json`
and is loaded once at module import. v0.1 carries 10 techniques covering
the kinds of evidence the five shipped Nexus agents emit (shell-in-container,
S3 public bucket, CVE exploit, crypto-mining, IAM credential abuse, etc.).
Phase 1c expands to a full ATT&CK table + ML-based mapping.

Ranking: hits-descending, then technique_id ascending (stable). Operators
read the report top-down, so the strongest signal lands first.

No fallback to "T0000 Unknown" — if nothing matches, the empty tuple is
the signal that the evidence shape didn't map to ATT&CK. The synthesizer
(Task 11) interprets the empty case.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from importlib.resources import files
from typing import Any

from investigation.schemas import MitreTechnique


def _load_table() -> tuple[tuple[MitreTechnique, tuple[str, ...]], ...]:
    """Read the bundled JSON table. Returns (technique, lowercase-keywords) pairs.

    The data file ships inside the `investigation.data` package so it
    travels with the wheel; no relative-path traversal needed.
    """
    raw = json.loads(
        (files("investigation") / "data" / "mitre_attack_14.json").read_text(encoding="utf-8")
    )
    rows: list[tuple[MitreTechnique, tuple[str, ...]]] = []
    for entry in raw["techniques"]:
        technique = MitreTechnique(
            technique_id=entry["technique_id"],
            technique_name=entry["technique_name"],
            tactic_id=entry["tactic_id"],
            tactic_name=entry["tactic_name"],
            sub_technique_id=entry.get("sub_technique_id"),
            sub_technique_name=entry.get("sub_technique_name"),
        )
        keywords = tuple(str(k).lower() for k in entry.get("keywords", []))
        rows.append((technique, keywords))
    return tuple(rows)


_TABLE: tuple[tuple[MitreTechnique, tuple[str, ...]], ...] | None = None


def _table() -> tuple[tuple[MitreTechnique, tuple[str, ...]], ...]:
    global _TABLE
    if _TABLE is None:
        _TABLE = _load_table()
    return _TABLE


def map_to_mitre(evidence: Any) -> tuple[MitreTechnique, ...]:
    """Return matched techniques ranked by keyword-hit count (desc).

    Empty / unmatched evidence → empty tuple (no T0000 fallback).
    """
    leaves = list(_collect_strings(evidence))
    if not leaves:
        return ()
    haystack = "\n".join(leaves).lower()
    if not haystack.strip():
        return ()

    hits: list[tuple[int, MitreTechnique]] = []
    for technique, keywords in _table():
        count = sum(haystack.count(kw) for kw in keywords if kw)
        if count > 0:
            hits.append((count, technique))

    # Rank: hits descending, then technique_id ascending (stable secondary).
    hits.sort(key=lambda pair: (-pair[0], pair[1].technique_id))
    return tuple(technique for _, technique in hits)


def _collect_strings(content: Any) -> Iterable[str]:
    """Flatten nested str/dict/list/tuple into a stream of leaf strings."""
    if content is None:
        return
    if isinstance(content, str):
        yield content
        return
    if isinstance(content, dict):
        for value in content.values():
            yield from _collect_strings(value)
        return
    if isinstance(content, (list, tuple)):
        for value in content:
            yield from _collect_strings(value)
        return
    yield str(content)


__all__ = ["map_to_mitre"]
