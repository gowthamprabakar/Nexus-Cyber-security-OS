"""D.8 v0.2 Task 7 — live MITRE ATT&CK STIX/TAXII tests (injected transport)."""

from __future__ import annotations

from typing import Any

import pytest
from threat_intel.tools.mitre_live import MitreAttackLiveReader
from threat_intel.tools.stix_taxii import TaxiiClient

_TECH = {
    "type": "attack-pattern",
    "id": "attack-pattern--1",
    "name": "Command and Scripting Interpreter",
    "modified": "2026-06-10T00:00:00.000Z",
    "external_references": [
        {
            "source_name": "mitre-attack",
            "external_id": "T1059",
            "url": "https://attack.mitre.org/techniques/T1059",
        }
    ],
    "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}],
}
# A non-technique STIX object that must be ignored by the technique parser.
_MALWARE = {
    "type": "malware",
    "id": "malware--9",
    "name": "Emotet",
    "modified": "2026-06-11T00:00:00.000Z",
}


class _FakeTaxii:
    def __init__(self, envelope: dict[str, Any]) -> None:
        self._env = envelope
        self.calls: list[tuple[str, dict[str, str] | None]] = []

    async def get(
        self,
        url: str,
        *,
        params: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, Any]]:
        self.calls.append((url, params))
        return 200, self._env


def _reader(envelope: dict[str, Any]) -> MitreAttackLiveReader:
    return MitreAttackLiveReader(
        TaxiiClient(_FakeTaxii(envelope)), collection_url="https://taxii/api/collections/c1"
    )


@pytest.mark.asyncio
async def test_poll_parses_attack_patterns_only() -> None:
    techniques, cursor = await _reader({"objects": [_TECH, _MALWARE], "more": False}).poll()
    assert [t.technique_id for t in techniques] == ["T1059"]  # malware ignored
    assert techniques[0].name == "Command and Scripting Interpreter"
    assert "execution" in techniques[0].tactics
    assert cursor == "2026-06-11T00:00:00.000Z"  # max modified across STIX objects


@pytest.mark.asyncio
async def test_empty_collection() -> None:
    techniques, cursor = await _reader({"objects": [], "more": False}).poll()
    assert techniques == () and cursor is None


@pytest.mark.asyncio
async def test_resume_passes_added_after() -> None:
    fake = _FakeTaxii({"objects": [], "more": False})
    reader = MitreAttackLiveReader(
        TaxiiClient(fake), collection_url="https://taxii/api/collections/c1"
    )
    await reader.poll(since="2026-06-05T00:00:00Z")
    assert fake.calls[0][1] == {"added_after": "2026-06-05T00:00:00Z"}


def test_read_mitre_attack_live_is_charter_registered() -> None:
    from threat_intel.agent import build_registry

    assert "read_mitre_attack_live" in build_registry().known_tools()
