"""``read_mitre_attack`` — filesystem ingest for MITRE ATT&CK STIX 2.1 bundles.

Reads an operator-staged STIX 2.1 enterprise-ATT&CK bundle JSON and
extracts the ``attack-pattern`` (technique) objects. Per ADR-005 the
filesystem read happens on ``asyncio.to_thread``; the wrapper is
``async`` for TaskGroup fan-out from the agent driver (Task 12).

**Operator workflow.** Per the D.8 v0.1 runbook:

.. code-block:: bash

    curl -sL https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json \\
        > /tmp/mitre-attack-snapshot.json

D.8 v0.2 replaces this with live HTTP polling behind the same async
wrapper signature.

**Wire shape (STIX 2.1).** Top-level:

.. code-block:: json

    {
        "type": "bundle",
        "id": "bundle--...",
        "spec_version": "2.1",
        "objects": [
            {
                "type": "attack-pattern",
                "id": "attack-pattern--...",
                "name": "Command and Scripting Interpreter",
                "description": "...",
                "external_references": [
                    {"source_name": "mitre-attack",
                     "external_id": "T1059",
                     "url": "https://attack.mitre.org/techniques/T1059"}
                ],
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack",
                     "phase_name": "execution"}
                ],
                "x_mitre_platforms": ["Linux", "Windows", "macOS"],
                "x_mitre_is_subtechnique": false,
                "revoked": false,
                "x_mitre_deprecated": false
            },
            ... (malware / intrusion-set / tool / threat-actor /
                 relationship objects — filtered out in v0.1)
        ]
    }

v0.1 scope: ``attack-pattern`` objects only. Malware / intrusion-set /
tool / threat-actor / relationship objects are filtered out (v0.3+
active-campaign tracking surfaces those).

**Forgiving** on malformed objects — bad entries dropped; raises
``MitreAttackReaderError`` on missing file, bad file type, or malformed
top-level JSON.

**Licence.** MITRE ATT&CK® is Creative Commons Attribution 4.0
(CC-BY-4.0). The summarizer (Task 11) emits a fixed attribution
footer in ``report.md``. Q6 of the D.8 plan.
"""

from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, ValidationError, field_validator


class MitreAttackReaderError(RuntimeError):
    """The MITRE ATT&CK STIX bundle could not be read."""


# ATT&CK technique-ID format: ``T<num>`` or ``T<num>.<sub>`` for sub-techniques.
_TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


class TechniqueRecord(BaseModel):
    """One parsed ATT&CK technique (or sub-technique).

    Surfaces the fields the technique-observation correlator needs to
    join D.3 Runtime Threat process / file evidence against ATT&CK
    behaviour catalogues. v0.1 doesn't yet ship that correlator — the
    technique index is built in Stage 2 ENRICH and used by future
    correlators / D.13 Synthesis narration.
    """

    technique_id: str = Field(min_length=4, max_length=10)
    name: str = Field(min_length=1)
    description: str = ""
    tactics: list[str] = Field(default_factory=list)
    platforms: list[str] = Field(default_factory=list)
    is_subtechnique: bool = False
    url: str = ""

    @field_validator("technique_id")
    @classmethod
    def _check_technique_id(cls, value: str) -> str:
        if not _TECHNIQUE_ID_RE.match(value):
            raise ValueError(f"technique_id must match {_TECHNIQUE_ID_RE.pattern} (got {value!r})")
        return value


async def read_mitre_attack(*, path: Path) -> tuple[TechniqueRecord, ...]:
    """Read a MITRE ATT&CK STIX 2.1 bundle and return the parsed techniques.

    Raises ``MitreAttackReaderError`` if the file is missing, not a
    file, or malformed JSON. Individual STIX objects that aren't
    valid ATT&CK techniques (wrong type, revoked, deprecated, missing
    technique_id) are dropped silently.

    The reader is pure I/O.
    """
    return await asyncio.to_thread(_read_sync, path)


def _read_sync(path: Path) -> tuple[TechniqueRecord, ...]:
    if not path.exists():
        raise MitreAttackReaderError(f"mitre attack bundle not found: {path}")
    if not path.is_file():
        raise MitreAttackReaderError(f"mitre attack bundle is not a file: {path}")

    try:
        with path.open("r", encoding="utf-8") as f:
            blob = json.load(f)
    except json.JSONDecodeError as exc:
        raise MitreAttackReaderError(f"mitre attack bundle is malformed json: {exc}") from exc

    raw_objects = _extract_objects(blob)
    out: list[TechniqueRecord] = []
    for raw in raw_objects:
        rec = _try_parse(raw)
        if rec is not None:
            out.append(rec)
    return tuple(out)


def _extract_objects(blob: Any) -> list[dict[str, Any]]:
    """Pull the STIX object list out of the top-level bundle."""
    if isinstance(blob, dict):
        raw = blob.get("objects", [])
        if isinstance(raw, list):
            return [o for o in raw if isinstance(o, dict)]
        return []
    if isinstance(blob, list):
        return [o for o in blob if isinstance(o, dict)]
    return []


def _try_parse(raw: dict[str, Any]) -> TechniqueRecord | None:
    """Filter for ``attack-pattern`` objects + parse into TechniqueRecord.

    v0.1 scope filter:
    - ``type == "attack-pattern"`` (drops malware, intrusion-set, tool,
      threat-actor, relationship, x-mitre-tactic, etc.).
    - ``revoked != True``.
    - ``x_mitre_deprecated != True``.
    - Has external reference with ``source_name == "mitre-attack"`` and
      a parseable ``external_id`` matching the technique-ID regex.
    """
    if raw.get("type") != "attack-pattern":
        return None
    if raw.get("revoked") is True:
        return None
    if raw.get("x_mitre_deprecated") is True:
        return None

    technique_id, url = _extract_technique_ref(raw.get("external_references", []))
    if not technique_id:
        return None

    try:
        return TechniqueRecord.model_validate(
            {
                "technique_id": technique_id,
                "name": raw.get("name", ""),
                "description": raw.get("description", ""),
                "tactics": _extract_tactics(raw.get("kill_chain_phases", [])),
                "platforms": _extract_platforms(raw.get("x_mitre_platforms", [])),
                "is_subtechnique": bool(raw.get("x_mitre_is_subtechnique", False)),
                "url": url,
            }
        )
    except ValidationError:
        return None
    except (TypeError, ValueError, KeyError):
        return None


def _extract_technique_ref(refs: Any) -> tuple[str, str]:
    """Find the ATT&CK external reference; return ``(technique_id, url)``."""
    if not isinstance(refs, list):
        return "", ""
    for ref in refs:
        if not isinstance(ref, dict):
            continue
        if ref.get("source_name") != "mitre-attack":
            continue
        external_id = ref.get("external_id", "")
        if not isinstance(external_id, str):
            continue
        if not _TECHNIQUE_ID_RE.match(external_id):
            continue
        url = ref.get("url", "")
        return external_id, url if isinstance(url, str) else ""
    return "", ""


def _extract_tactics(phases: Any) -> list[str]:
    """Extract ATT&CK tactic names (``execution``, ``persistence``, etc.)."""
    if not isinstance(phases, list):
        return []
    out: list[str] = []
    for phase in phases:
        if not isinstance(phase, dict):
            continue
        if phase.get("kill_chain_name") != "mitre-attack":
            continue
        name = phase.get("phase_name")
        if isinstance(name, str) and name:
            out.append(name)
    return out


def _extract_platforms(platforms: Any) -> list[str]:
    """Extract platform names from ``x_mitre_platforms``."""
    if not isinstance(platforms, list):
        return []
    return [p for p in platforms if isinstance(p, str) and p]
