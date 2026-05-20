"""``read_nvd_feed`` — filesystem ingest for NVD CVE JSON 2.0 dumps.

Reads an operator-staged JSON file from the National Vulnerability
Database (NVD) CVE feed and converts each entry into a typed
``NvdCveRecord``. Per ADR-005 the filesystem read happens on
``asyncio.to_thread``; the wrapper is ``async`` for TaskGroup fan-out
from the agent driver (Task 12).

**Operator workflow.** Per the D.8 v0.1 runbook, operators stage the
NVD feed by downloading + decompressing:

.. code-block:: bash

    curl -sL https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz \\
        | gunzip > /tmp/nvd-snapshot.json

D.8 v0.2 replaces this with live HTTP polling behind the same async
wrapper signature.

**Wire shape (NVD CVE 2.0).** Top-level:

.. code-block:: json

    {
        "format": "NVD_CVE",
        "version": "2.0",
        "vulnerabilities": [
            {"cve": {
                "id": "CVE-2024-12345",
                "published": "2024-01-15T12:00:00.000",
                "lastModified": "2024-02-01T00:00:00.000",
                "vulnStatus": "Analyzed",
                "descriptions": [{"lang": "en", "value": "..."}],
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL", ...}}]},
                "references": [{"url": "https://..."}]
            }}
        ]
    }

**Forgiving** on malformed CVE entries — a single bad vulnerability is
dropped, not the whole file. Mirrors F.3 / multi-cloud-posture
forgiving pattern. Raises ``NvdFeedReaderError`` on missing file, bad
file type, or malformed top-level JSON.

**Licence.** NVD data is U.S. Government work, public domain
(17 U.S.C. § 105). Q6 of the D.8 plan.
"""

from __future__ import annotations

import asyncio
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, ValidationError, field_validator


class NvdFeedReaderError(RuntimeError):
    """The NVD CVE JSON feed could not be read."""


# CVE ID format: ``CVE-YYYY-NNNN+``.
_CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")

# CVSS severity labels we accept verbatim.
_CVSS_SEVERITIES = frozenset({"CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"})


class NvdCveRecord(BaseModel):
    """One parsed CVE record from the NVD feed.

    Stable across NVD CVE JSON 2.0 schema; v0.1 surfaces the fields the
    correlator (Task 7) needs to join D.1 Vulnerability findings against
    the KEV catalog (Task 4).
    """

    cve_id: str = Field(min_length=10, max_length=20)
    description: str
    published: datetime
    last_modified: datetime
    vuln_status: str = ""
    cvss_v3_score: float | None = Field(default=None, ge=0.0, le=10.0)
    cvss_v3_severity: str | None = None
    references: list[str] = Field(default_factory=list)

    @field_validator("cve_id")
    @classmethod
    def _check_cve_id_format(cls, value: str) -> str:
        if not _CVE_ID_RE.match(value):
            raise ValueError(f"cve_id must match {_CVE_ID_RE.pattern} (got {value!r})")
        return value

    @field_validator("cvss_v3_severity")
    @classmethod
    def _check_severity(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if value.upper() not in _CVSS_SEVERITIES:
            raise ValueError(f"cvss_v3_severity must be one of {sorted(_CVSS_SEVERITIES)}")
        return value.upper()


async def read_nvd_feed(*, path: Path) -> tuple[NvdCveRecord, ...]:
    """Read an NVD CVE JSON 2.0 dump and return the parsed CVE records.

    Raises ``NvdFeedReaderError`` if the file is missing, not a file,
    or malformed JSON. Individual CVE entries that fail validation are
    dropped silently (forgiving — mirrors F.3 / multi-cloud-posture).

    The reader is pure I/O: no correlator calls, no SemanticStore
    writes, no side effects beyond the filesystem read.
    """
    return await asyncio.to_thread(_read_sync, path)


def _read_sync(path: Path) -> tuple[NvdCveRecord, ...]:
    if not path.exists():
        raise NvdFeedReaderError(f"nvd feed not found: {path}")
    if not path.is_file():
        raise NvdFeedReaderError(f"nvd feed is not a file: {path}")

    try:
        with path.open("r", encoding="utf-8") as f:
            blob = json.load(f)
    except json.JSONDecodeError as exc:
        raise NvdFeedReaderError(f"nvd feed is malformed json: {exc}") from exc

    raw_records = _extract_vulnerabilities(blob)
    out: list[NvdCveRecord] = []
    for raw in raw_records:
        rec = _try_parse(raw)
        if rec is not None:
            out.append(rec)
    return tuple(out)


def _extract_vulnerabilities(blob: Any) -> list[dict[str, Any]]:
    """Pull the list of vulnerability dicts out of the top-level JSON.

    Supports canonical NVD 2.0 (``{"vulnerabilities": [{"cve": {...}}]}``)
    + bare list of CVE dicts.
    """
    if isinstance(blob, dict):
        raw = blob.get("vulnerabilities", [])
        if isinstance(raw, list):
            # Canonical NVD 2.0 wraps each CVE in a ``{"cve": {...}}`` envelope.
            out: list[dict[str, Any]] = []
            for entry in raw:
                if isinstance(entry, dict):
                    cve = entry.get("cve")
                    if isinstance(cve, dict):
                        out.append(cve)
                    elif "id" in entry:  # bare-CVE shape inside the list
                        out.append(entry)
            return out
        return []
    if isinstance(blob, list):
        # Bare list of CVE dicts (some toolchains flatten the response).
        return [c for c in blob if isinstance(c, dict)]
    return []


def _try_parse(raw: dict[str, Any]) -> NvdCveRecord | None:
    """Parse one raw CVE dict; return None if validation fails."""
    try:
        return NvdCveRecord.model_validate(_normalize(raw))
    except ValidationError:
        return None
    except (TypeError, ValueError, KeyError):
        return None


def _normalize(raw: dict[str, Any]) -> dict[str, Any]:
    """Flatten the NVD 2.0 nested structure into NvdCveRecord field names."""
    cve_id = raw.get("id", "")
    description = _english_description(raw.get("descriptions", []))
    published_raw = raw.get("published", "")
    last_modified_raw = raw.get("lastModified", "")
    vuln_status = raw.get("vulnStatus", "")
    cvss_score, cvss_severity = _extract_cvss(raw.get("metrics", {}))
    refs = _extract_refs(raw.get("references", []))

    return {
        "cve_id": cve_id,
        "description": description,
        "published": published_raw,
        "last_modified": last_modified_raw,
        "vuln_status": vuln_status,
        "cvss_v3_score": cvss_score,
        "cvss_v3_severity": cvss_severity,
        "references": refs,
    }


def _english_description(descriptions: Any) -> str:
    """Pick the English-language description; fall back to the first
    language or empty string.
    """
    if not isinstance(descriptions, list):
        return ""
    for entry in descriptions:
        if isinstance(entry, dict) and entry.get("lang") == "en":
            value = entry.get("value")
            if isinstance(value, str):
                return value
    # Fallback: first entry with a string value.
    for entry in descriptions:
        if isinstance(entry, dict):
            value = entry.get("value")
            if isinstance(value, str):
                return value
    return ""


def _extract_cvss(metrics: Any) -> tuple[float | None, str | None]:
    """Prefer CVSS v3.1, fall back to v3.0. Returns ``(score, severity)``."""
    if not isinstance(metrics, dict):
        return None, None
    for key in ("cvssMetricV31", "cvssMetricV30"):
        items = metrics.get(key, [])
        if isinstance(items, list) and items:
            first = items[0]
            if isinstance(first, dict):
                data = first.get("cvssData", {})
                if isinstance(data, dict):
                    score = data.get("baseScore")
                    severity = data.get("baseSeverity")
                    score_f: float | None = (
                        float(score) if isinstance(score, (int, float)) else None
                    )
                    severity_s: str | None = (
                        severity.upper()
                        if isinstance(severity, str) and severity.upper() in _CVSS_SEVERITIES
                        else None
                    )
                    return score_f, severity_s
    return None, None


def _extract_refs(refs: Any) -> list[str]:
    """Extract URL strings from the NVD references array."""
    if not isinstance(refs, list):
        return []
    out: list[str] = []
    for entry in refs:
        if isinstance(entry, dict):
            url = entry.get("url")
            if isinstance(url, str) and url:
                out.append(url)
    return out
