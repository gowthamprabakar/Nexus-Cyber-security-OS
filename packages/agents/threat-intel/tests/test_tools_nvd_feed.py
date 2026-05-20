"""Tests — ``threat_intel.tools.nvd_feed``.

Task 3. Verifies the NVD CVE JSON 2.0 reader:

- Happy-path parse (canonical ``{"vulnerabilities": [{"cve": {...}}]}``).
- Bare-list shape.
- Empty input → empty tuple.
- Missing file / not-a-file / malformed JSON → raises.
- Per-CVE malformed → dropped silently (forgiving).
- CVSS v3.1 score + severity extraction.
- CVSS v3.0 fallback when v3.1 absent.
- Missing CVSS → ``None`` (graceful).
- English description selection across multi-language descriptions.
- vuln_status preserved.
- References extracted.
- Unicode in description handled.
- Bad CVE-ID format rejected at validation.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from threat_intel.tools.nvd_feed import (
    NvdCveRecord,
    NvdFeedReaderError,
    read_nvd_feed,
)


def _write_json(tmp_path: Path, content: object) -> Path:
    path = tmp_path / "nvd.json"
    path.write_text(json.dumps(content), encoding="utf-8")
    return path


def _cve_dict(cve_id: str = "CVE-2024-12345", **overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": cve_id,
        "published": "2024-01-15T12:00:00.000",
        "lastModified": "2024-02-01T00:00:00.000",
        "vulnStatus": "Analyzed",
        "descriptions": [{"lang": "en", "value": "Remote code execution flaw."}],
        "metrics": {
            "cvssMetricV31": [
                {
                    "cvssData": {
                        "baseScore": 9.8,
                        "baseSeverity": "CRITICAL",
                    }
                }
            ]
        },
        "references": [{"url": "https://example.com/advisory/abc"}],
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Happy-path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_reads_canonical_nvd_shape(tmp_path: Path) -> None:
    path = _write_json(
        tmp_path,
        {
            "format": "NVD_CVE",
            "version": "2.0",
            "vulnerabilities": [{"cve": _cve_dict("CVE-2024-00001")}],
        },
    )
    result = await read_nvd_feed(path=path)
    assert len(result) == 1
    assert result[0].cve_id == "CVE-2024-00001"
    assert result[0].cvss_v3_score == 9.8
    assert result[0].cvss_v3_severity == "CRITICAL"


@pytest.mark.asyncio
async def test_reads_bare_list_shape(tmp_path: Path) -> None:
    path = _write_json(tmp_path, [_cve_dict("CVE-2024-00002")])
    result = await read_nvd_feed(path=path)
    assert len(result) == 1
    assert result[0].cve_id == "CVE-2024-00002"


@pytest.mark.asyncio
async def test_empty_vulnerabilities_returns_empty_tuple(tmp_path: Path) -> None:
    path = _write_json(tmp_path, {"vulnerabilities": []})
    result = await read_nvd_feed(path=path)
    assert result == ()


@pytest.mark.asyncio
async def test_multiple_cves_parsed(tmp_path: Path) -> None:
    path = _write_json(
        tmp_path,
        {
            "vulnerabilities": [
                {"cve": _cve_dict("CVE-2024-00010")},
                {"cve": _cve_dict("CVE-2024-00020")},
                {"cve": _cve_dict("CVE-2024-00030")},
            ]
        },
    )
    result = await read_nvd_feed(path=path)
    assert {r.cve_id for r in result} == {
        "CVE-2024-00010",
        "CVE-2024-00020",
        "CVE-2024-00030",
    }


# ---------------------------------------------------------------------------
# Error cases
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(NvdFeedReaderError, match="not found"):
        await read_nvd_feed(path=tmp_path / "missing.json")


@pytest.mark.asyncio
async def test_directory_path_raises(tmp_path: Path) -> None:
    with pytest.raises(NvdFeedReaderError, match="not a file"):
        await read_nvd_feed(path=tmp_path)


@pytest.mark.asyncio
async def test_malformed_json_raises(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text("{not valid json", encoding="utf-8")
    with pytest.raises(NvdFeedReaderError, match="malformed"):
        await read_nvd_feed(path=path)


# ---------------------------------------------------------------------------
# Forgiving parse
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_drops_malformed_cve_keeps_good_ones(tmp_path: Path) -> None:
    """A single bad CVE entry is dropped; the rest of the file parses."""
    bad_cve = {"id": "bad-format", "descriptions": []}  # invalid CVE-ID format
    path = _write_json(
        tmp_path,
        {
            "vulnerabilities": [
                {"cve": _cve_dict("CVE-2024-00100")},
                {"cve": bad_cve},
                {"cve": _cve_dict("CVE-2024-00200")},
            ]
        },
    )
    result = await read_nvd_feed(path=path)
    assert {r.cve_id for r in result} == {"CVE-2024-00100", "CVE-2024-00200"}


@pytest.mark.asyncio
async def test_non_dict_entries_ignored(tmp_path: Path) -> None:
    path = _write_json(
        tmp_path,
        {
            "vulnerabilities": [
                {"cve": _cve_dict("CVE-2024-00001")},
                "not-a-dict",
                42,
                None,
            ]
        },
    )
    result = await read_nvd_feed(path=path)
    assert len(result) == 1


# ---------------------------------------------------------------------------
# CVSS extraction
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cvss_v30_fallback_when_v31_absent(tmp_path: Path) -> None:
    """Older CVEs only have v3.0 metrics."""
    cve = _cve_dict(
        "CVE-2019-00001",
        metrics={"cvssMetricV30": [{"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}}]},
    )
    path = _write_json(tmp_path, {"vulnerabilities": [{"cve": cve}]})
    result = await read_nvd_feed(path=path)
    assert result[0].cvss_v3_score == 7.5
    assert result[0].cvss_v3_severity == "HIGH"


@pytest.mark.asyncio
async def test_no_cvss_metrics_returns_none(tmp_path: Path) -> None:
    cve = _cve_dict("CVE-2024-99999", metrics={})
    path = _write_json(tmp_path, {"vulnerabilities": [{"cve": cve}]})
    result = await read_nvd_feed(path=path)
    assert result[0].cvss_v3_score is None
    assert result[0].cvss_v3_severity is None


@pytest.mark.asyncio
async def test_v31_takes_precedence_over_v30(tmp_path: Path) -> None:
    """When both v3.1 and v3.0 are present, v3.1 wins."""
    cve = _cve_dict(
        metrics={
            "cvssMetricV31": [{"cvssData": {"baseScore": 9.0, "baseSeverity": "CRITICAL"}}],
            "cvssMetricV30": [{"cvssData": {"baseScore": 5.0, "baseSeverity": "MEDIUM"}}],
        }
    )
    path = _write_json(tmp_path, {"vulnerabilities": [{"cve": cve}]})
    result = await read_nvd_feed(path=path)
    assert result[0].cvss_v3_score == 9.0
    assert result[0].cvss_v3_severity == "CRITICAL"


# ---------------------------------------------------------------------------
# Descriptions
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_english_description_picked_across_languages(tmp_path: Path) -> None:
    cve = _cve_dict(
        descriptions=[
            {"lang": "es", "value": "Descripción en español"},
            {"lang": "en", "value": "English description"},
            {"lang": "fr", "value": "Description en français"},
        ]
    )
    path = _write_json(tmp_path, {"vulnerabilities": [{"cve": cve}]})
    result = await read_nvd_feed(path=path)
    assert result[0].description == "English description"


@pytest.mark.asyncio
async def test_unicode_description_handled(tmp_path: Path) -> None:
    cve = _cve_dict(
        descriptions=[{"lang": "en", "value": "Vulnerability in 漢字 module — ñoño handler"}]
    )
    path = _write_json(tmp_path, {"vulnerabilities": [{"cve": cve}]})
    result = await read_nvd_feed(path=path)
    assert "漢字" in result[0].description
    assert "ñoño" in result[0].description


# ---------------------------------------------------------------------------
# References + vuln_status
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_references_extracted(tmp_path: Path) -> None:
    cve = _cve_dict(
        references=[
            {"url": "https://example.com/a"},
            {"url": "https://example.com/b"},
            {"source": "no-url-key"},  # skipped
        ]
    )
    path = _write_json(tmp_path, {"vulnerabilities": [{"cve": cve}]})
    result = await read_nvd_feed(path=path)
    assert result[0].references == ["https://example.com/a", "https://example.com/b"]


@pytest.mark.asyncio
async def test_vuln_status_preserved(tmp_path: Path) -> None:
    cve = _cve_dict(vulnStatus="Awaiting Analysis")
    path = _write_json(tmp_path, {"vulnerabilities": [{"cve": cve}]})
    result = await read_nvd_feed(path=path)
    assert result[0].vuln_status == "Awaiting Analysis"


# ---------------------------------------------------------------------------
# Direct NvdCveRecord validation
# ---------------------------------------------------------------------------


def test_cve_record_rejects_bad_id_format() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        NvdCveRecord(
            cve_id="not-a-cve",
            description="x",
            published="2024-01-01T00:00:00",  # type: ignore[arg-type]
            last_modified="2024-01-01T00:00:00",  # type: ignore[arg-type]
        )


def test_cve_record_rejects_oversized_cvss_score() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        NvdCveRecord(
            cve_id="CVE-2024-12345",
            description="x",
            published="2024-01-01T00:00:00",  # type: ignore[arg-type]
            last_modified="2024-01-01T00:00:00",  # type: ignore[arg-type]
            cvss_v3_score=12.0,
        )


def test_cve_record_rejects_unknown_severity() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        NvdCveRecord(
            cve_id="CVE-2024-12345",
            description="x",
            published="2024-01-01T00:00:00",  # type: ignore[arg-type]
            last_modified="2024-01-01T00:00:00",  # type: ignore[arg-type]
            cvss_v3_severity="UNKNOWN_LEVEL",
        )
