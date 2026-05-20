"""Tests — ``threat_intel.tools.cisa_kev``.

Task 4. Verifies the CISA KEV catalog reader.
"""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path
from typing import Any

import pytest
from threat_intel.tools.cisa_kev import (
    CisaKevReaderError,
    KevEntry,
    read_cisa_kev,
)


def _write_json(tmp_path: Path, content: object) -> Path:
    path = tmp_path / "kev.json"
    path.write_text(json.dumps(content), encoding="utf-8")
    return path


def _kev_dict(cve_id: str = "CVE-2024-12345", **overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "cveID": cve_id,
        "vendorProject": "Microsoft",
        "product": "Exchange Server",
        "vulnerabilityName": "Exchange RCE",
        "dateAdded": "2024-01-15",
        "shortDescription": "Pre-auth RCE in Exchange.",
        "requiredAction": "Apply updates per vendor instructions.",
        "dueDate": "2024-02-15",
        "knownRansomwareCampaignUse": "Known",
        "notes": "https://example.com/advisory",
        "cwes": ["CWE-78"],
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Happy-path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_reads_canonical_kev_shape(tmp_path: Path) -> None:
    path = _write_json(
        tmp_path,
        {
            "title": "CISA Catalog of Known Exploited Vulnerabilities",
            "catalogVersion": "2024.01.15",
            "count": 1,
            "vulnerabilities": [_kev_dict("CVE-2024-00001")],
        },
    )
    result = await read_cisa_kev(path=path)
    assert len(result) == 1
    assert result[0].cve_id == "CVE-2024-00001"
    assert result[0].vendor_project == "Microsoft"
    assert result[0].known_ransomware_campaign_use is True


@pytest.mark.asyncio
async def test_reads_bare_list_shape(tmp_path: Path) -> None:
    path = _write_json(tmp_path, [_kev_dict("CVE-2024-00002")])
    result = await read_cisa_kev(path=path)
    assert len(result) == 1
    assert result[0].cve_id == "CVE-2024-00002"


@pytest.mark.asyncio
async def test_empty_vulnerabilities_returns_empty_tuple(tmp_path: Path) -> None:
    path = _write_json(tmp_path, {"vulnerabilities": []})
    result = await read_cisa_kev(path=path)
    assert result == ()


# ---------------------------------------------------------------------------
# Error cases
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(CisaKevReaderError, match="not found"):
        await read_cisa_kev(path=tmp_path / "missing.json")


@pytest.mark.asyncio
async def test_directory_path_raises(tmp_path: Path) -> None:
    with pytest.raises(CisaKevReaderError, match="not a file"):
        await read_cisa_kev(path=tmp_path)


@pytest.mark.asyncio
async def test_malformed_json_raises(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text("{not valid", encoding="utf-8")
    with pytest.raises(CisaKevReaderError, match="malformed"):
        await read_cisa_kev(path=path)


# ---------------------------------------------------------------------------
# Forgiving parse
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_drops_malformed_entry_keeps_good_ones(tmp_path: Path) -> None:
    bad = {"cveID": "not-a-cve", "dateAdded": "2024-01-15"}
    path = _write_json(
        tmp_path,
        {
            "vulnerabilities": [
                _kev_dict("CVE-2024-00100"),
                bad,
                _kev_dict("CVE-2024-00200"),
            ]
        },
    )
    result = await read_cisa_kev(path=path)
    assert {r.cve_id for r in result} == {"CVE-2024-00100", "CVE-2024-00200"}


@pytest.mark.asyncio
async def test_non_dict_entries_ignored(tmp_path: Path) -> None:
    path = _write_json(
        tmp_path,
        {"vulnerabilities": [_kev_dict("CVE-2024-00001"), "not-a-dict", 42, None]},
    )
    result = await read_cisa_kev(path=path)
    assert len(result) == 1


# ---------------------------------------------------------------------------
# Ransomware-context derivation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ransomware_known_is_true(tmp_path: Path) -> None:
    path = _write_json(
        tmp_path,
        {"vulnerabilities": [_kev_dict(knownRansomwareCampaignUse="Known")]},
    )
    result = await read_cisa_kev(path=path)
    assert result[0].known_ransomware_campaign_use is True


@pytest.mark.asyncio
async def test_ransomware_unknown_is_false(tmp_path: Path) -> None:
    """Conservative posture: only ``"Known"`` triggers True. ``"Unknown"`` → False."""
    path = _write_json(
        tmp_path,
        {"vulnerabilities": [_kev_dict(knownRansomwareCampaignUse="Unknown")]},
    )
    result = await read_cisa_kev(path=path)
    assert result[0].known_ransomware_campaign_use is False


@pytest.mark.asyncio
async def test_ransomware_missing_is_false(tmp_path: Path) -> None:
    """Missing field → False (conservative)."""
    kev = _kev_dict()
    del kev["knownRansomwareCampaignUse"]
    path = _write_json(tmp_path, {"vulnerabilities": [kev]})
    result = await read_cisa_kev(path=path)
    assert result[0].known_ransomware_campaign_use is False


# ---------------------------------------------------------------------------
# Date parsing + CWE list
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dates_parsed_as_date_objects(tmp_path: Path) -> None:
    path = _write_json(
        tmp_path,
        {"vulnerabilities": [_kev_dict(dateAdded="2024-01-15", dueDate="2024-02-15")]},
    )
    result = await read_cisa_kev(path=path)
    assert result[0].date_added == date(2024, 1, 15)
    assert result[0].due_date == date(2024, 2, 15)


@pytest.mark.asyncio
async def test_due_date_optional_none(tmp_path: Path) -> None:
    kev = _kev_dict()
    del kev["dueDate"]
    path = _write_json(tmp_path, {"vulnerabilities": [kev]})
    result = await read_cisa_kev(path=path)
    assert result[0].due_date is None


@pytest.mark.asyncio
async def test_cwes_list_extracted(tmp_path: Path) -> None:
    path = _write_json(
        tmp_path,
        {"vulnerabilities": [_kev_dict(cwes=["CWE-78", "CWE-79", "CWE-89"])]},
    )
    result = await read_cisa_kev(path=path)
    assert result[0].cwes == ["CWE-78", "CWE-79", "CWE-89"]


@pytest.mark.asyncio
async def test_cwes_non_string_entries_filtered(tmp_path: Path) -> None:
    """Non-string entries in cwes are dropped (defensive)."""
    path = _write_json(
        tmp_path,
        {"vulnerabilities": [_kev_dict(cwes=["CWE-78", 42, None, "CWE-79"])]},
    )
    result = await read_cisa_kev(path=path)
    assert result[0].cwes == ["CWE-78", "CWE-79"]


# ---------------------------------------------------------------------------
# Direct KevEntry validation
# ---------------------------------------------------------------------------


def test_kev_entry_rejects_bad_cve_id() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        KevEntry(
            cve_id="not-a-cve",
            date_added=date(2024, 1, 15),
        )
