"""Tests — ``threat_intel.tools.mitre_attack``.

Task 5. Verifies the MITRE ATT&CK STIX 2.1 bundle reader.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from threat_intel.tools.mitre_attack import (
    MitreAttackReaderError,
    TechniqueRecord,
    read_mitre_attack,
)


def _write_json(tmp_path: Path, content: object) -> Path:
    path = tmp_path / "attack.json"
    path.write_text(json.dumps(content), encoding="utf-8")
    return path


def _technique(
    technique_id: str = "T1059",
    *,
    name: str = "Command and Scripting Interpreter",
    revoked: bool = False,
    deprecated: bool = False,
    is_subtechnique: bool = False,
    **overrides: Any,
) -> dict[str, Any]:
    base: dict[str, Any] = {
        "type": "attack-pattern",
        "id": f"attack-pattern--{technique_id.lower()}",
        "name": name,
        "description": f"Description for {technique_id}",
        "external_references": [
            {
                "source_name": "mitre-attack",
                "external_id": technique_id,
                "url": f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}",
            }
        ],
        "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}],
        "x_mitre_platforms": ["Linux", "Windows"],
        "x_mitre_is_subtechnique": is_subtechnique,
        "revoked": revoked,
        "x_mitre_deprecated": deprecated,
    }
    base.update(overrides)
    return base


def _bundle(objects: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "type": "bundle",
        "id": "bundle--test",
        "spec_version": "2.1",
        "objects": objects,
    }


# ---------------------------------------------------------------------------
# Happy-path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_reads_canonical_bundle_shape(tmp_path: Path) -> None:
    path = _write_json(tmp_path, _bundle([_technique("T1059")]))
    result = await read_mitre_attack(path=path)
    assert len(result) == 1
    assert result[0].technique_id == "T1059"
    assert result[0].name == "Command and Scripting Interpreter"
    assert result[0].tactics == ["execution"]
    assert result[0].platforms == ["Linux", "Windows"]


@pytest.mark.asyncio
async def test_extracts_subtechnique_flag(tmp_path: Path) -> None:
    path = _write_json(tmp_path, _bundle([_technique("T1059.003", is_subtechnique=True)]))
    result = await read_mitre_attack(path=path)
    assert result[0].technique_id == "T1059.003"
    assert result[0].is_subtechnique is True


@pytest.mark.asyncio
async def test_empty_bundle_returns_empty_tuple(tmp_path: Path) -> None:
    path = _write_json(tmp_path, _bundle([]))
    result = await read_mitre_attack(path=path)
    assert result == ()


# ---------------------------------------------------------------------------
# v0.1 scope filter — only attack-pattern objects
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_filters_out_malware_intrusion_set_tool_threat_actor(tmp_path: Path) -> None:
    """Per plan: v0.1 ships techniques only; other STIX object types are dropped."""
    objects = [
        _technique("T1059"),
        {"type": "malware", "id": "malware--abc", "name": "Mimikatz"},
        {"type": "intrusion-set", "id": "intrusion-set--abc", "name": "APT29"},
        {"type": "tool", "id": "tool--abc", "name": "Cobalt Strike"},
        {"type": "threat-actor", "id": "threat-actor--abc", "name": "FIN7"},
        {"type": "relationship", "id": "relationship--abc"},
        {"type": "x-mitre-tactic", "id": "x-mitre-tactic--abc"},
    ]
    path = _write_json(tmp_path, _bundle(objects))
    result = await read_mitre_attack(path=path)
    assert len(result) == 1
    assert result[0].technique_id == "T1059"


@pytest.mark.asyncio
async def test_filters_out_revoked_techniques(tmp_path: Path) -> None:
    """Revoked techniques are dropped — they're historical references."""
    path = _write_json(
        tmp_path,
        _bundle(
            [
                _technique("T1059"),
                _technique("T9999", revoked=True),
            ]
        ),
    )
    result = await read_mitre_attack(path=path)
    assert {r.technique_id for r in result} == {"T1059"}


@pytest.mark.asyncio
async def test_filters_out_deprecated_techniques(tmp_path: Path) -> None:
    """Deprecated techniques are dropped — superseded by replacements."""
    path = _write_json(
        tmp_path,
        _bundle(
            [
                _technique("T1059"),
                _technique("T9998", deprecated=True),
            ]
        ),
    )
    result = await read_mitre_attack(path=path)
    assert {r.technique_id for r in result} == {"T1059"}


# ---------------------------------------------------------------------------
# Error cases
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(MitreAttackReaderError, match="not found"):
        await read_mitre_attack(path=tmp_path / "missing.json")


@pytest.mark.asyncio
async def test_directory_path_raises(tmp_path: Path) -> None:
    with pytest.raises(MitreAttackReaderError, match="not a file"):
        await read_mitre_attack(path=tmp_path)


@pytest.mark.asyncio
async def test_malformed_json_raises(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text("{not valid", encoding="utf-8")
    with pytest.raises(MitreAttackReaderError, match="malformed"):
        await read_mitre_attack(path=path)


# ---------------------------------------------------------------------------
# Forgiving parse
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_drops_attack_pattern_without_mitre_external_ref(tmp_path: Path) -> None:
    """attack-pattern without an ``external_references[*].source_name='mitre-attack'``
    entry — drop silently (not a MITRE-tracked technique).
    """
    bad = _technique("T1059")
    bad["external_references"] = [{"source_name": "capec", "external_id": "CAPEC-242"}]
    path = _write_json(tmp_path, _bundle([_technique("T1059"), bad]))
    result = await read_mitre_attack(path=path)
    assert len(result) == 1


@pytest.mark.asyncio
async def test_drops_invalid_technique_id_format(tmp_path: Path) -> None:
    """Even an attack-pattern with the right shape — if ``external_id`` doesn't
    match ``T<num>`` format, drop silently.
    """
    bad = _technique("T1059")
    bad["external_references"] = [
        {"source_name": "mitre-attack", "external_id": "G0001"}  # group id, not a technique
    ]
    path = _write_json(tmp_path, _bundle([_technique("T1059"), bad]))
    result = await read_mitre_attack(path=path)
    assert len(result) == 1


@pytest.mark.asyncio
async def test_bare_list_shape_supported(tmp_path: Path) -> None:
    """Bare list (no bundle wrapper) accepted."""
    path = _write_json(tmp_path, [_technique("T1059"), _technique("T1003")])
    result = await read_mitre_attack(path=path)
    assert {r.technique_id for r in result} == {"T1059", "T1003"}


# ---------------------------------------------------------------------------
# Direct TechniqueRecord validation
# ---------------------------------------------------------------------------


def test_technique_record_rejects_bad_technique_id() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        TechniqueRecord(technique_id="T59", name="x")  # missing 3+ trailing digits


def test_technique_record_subtechnique_format() -> None:
    """Sub-techniques use ``T<num>.<sub>`` format."""
    record = TechniqueRecord(
        technique_id="T1059.003",
        name="Windows Command Shell",
        is_subtechnique=True,
    )
    assert record.technique_id == "T1059.003"
    assert record.is_subtechnique is True
