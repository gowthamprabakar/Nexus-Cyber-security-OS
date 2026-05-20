"""``read_cisa_kev`` — filesystem ingest for CISA KEV catalog JSON dumps.

Reads an operator-staged JSON file from the CISA Known Exploited
Vulnerabilities (KEV) catalog and converts each entry into a typed
``KevEntry``. Per ADR-005 the filesystem read happens on
``asyncio.to_thread``; the wrapper is ``async`` for TaskGroup fan-out
from the agent driver (Task 12).

**Operator workflow.** Per the D.8 v0.1 runbook:

.. code-block:: bash

    curl -sL https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json \\
        > /tmp/kev-snapshot.json

D.8 v0.2 replaces this with live HTTP polling behind the same async
wrapper signature.

**Wire shape (CISA KEV catalog).** Top-level:

.. code-block:: json

    {
        "title": "CISA Catalog of Known Exploited Vulnerabilities",
        "catalogVersion": "2024.01.15",
        "dateReleased": "2024-01-15T...",
        "count": 1234,
        "vulnerabilities": [
            {
                "cveID": "CVE-2024-12345",
                "vendorProject": "Microsoft",
                "product": "Exchange Server",
                "vulnerabilityName": "Microsoft Exchange Server RCE",
                "dateAdded": "2024-01-15",
                "shortDescription": "...",
                "requiredAction": "Apply updates per vendor instructions.",
                "dueDate": "2024-02-15",
                "knownRansomwareCampaignUse": "Known",
                "notes": "...",
                "cwes": ["CWE-78"]
            }
        ]
    }

**Forgiving** on malformed KEV entries — a single bad entry is dropped,
not the whole file. Raises ``CisaKevReaderError`` on missing file, bad
file type, or malformed top-level JSON.

**Licence.** CISA KEV catalog is U.S. Government work, public domain
(CC0). Q6 of the D.8 plan.
"""

from __future__ import annotations

import asyncio
import json
import re
from datetime import date
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, ValidationError, field_validator


class CisaKevReaderError(RuntimeError):
    """The CISA KEV catalog JSON feed could not be read."""


_CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


class KevEntry(BaseModel):
    """One parsed KEV catalog entry.

    Surfaces the fields the CVE-KEV correlator (Task 7) needs to flag
    D.1 Vulnerability findings as actively exploited.

    The ``known_ransomware_campaign_use`` boolean is derived from the
    string field in the source: ``"Known"`` → ``True``; anything else
    (``"Unknown"``, missing) → ``False``. This is the conservative
    posture — only "Known" triggers the ransomware-context flag.
    """

    cve_id: str = Field(min_length=10, max_length=20)
    vendor_project: str = ""
    product: str = ""
    vulnerability_name: str = ""
    date_added: date
    short_description: str = ""
    required_action: str = ""
    due_date: date | None = None
    known_ransomware_campaign_use: bool = False
    notes: str = ""
    cwes: list[str] = Field(default_factory=list)

    @field_validator("cve_id")
    @classmethod
    def _check_cve_id_format(cls, value: str) -> str:
        if not _CVE_ID_RE.match(value):
            raise ValueError(f"cve_id must match {_CVE_ID_RE.pattern} (got {value!r})")
        return value


async def read_cisa_kev(*, path: Path) -> tuple[KevEntry, ...]:
    """Read the CISA KEV catalog JSON and return the parsed entries.

    Raises ``CisaKevReaderError`` if the file is missing, not a file,
    or malformed JSON. Individual KEV entries that fail validation are
    dropped silently (forgiving).

    The reader is pure I/O.
    """
    return await asyncio.to_thread(_read_sync, path)


def _read_sync(path: Path) -> tuple[KevEntry, ...]:
    if not path.exists():
        raise CisaKevReaderError(f"cisa kev catalog not found: {path}")
    if not path.is_file():
        raise CisaKevReaderError(f"cisa kev catalog is not a file: {path}")

    try:
        with path.open("r", encoding="utf-8") as f:
            blob = json.load(f)
    except json.JSONDecodeError as exc:
        raise CisaKevReaderError(f"cisa kev catalog is malformed json: {exc}") from exc

    raw_records = _extract_vulnerabilities(blob)
    out: list[KevEntry] = []
    for raw in raw_records:
        rec = _try_parse(raw)
        if rec is not None:
            out.append(rec)
    return tuple(out)


def _extract_vulnerabilities(blob: Any) -> list[dict[str, Any]]:
    """Pull the list of KEV entries out of the top-level JSON.

    Supports canonical CISA KEV (``{"vulnerabilities": [...]}``) + bare
    list of entries.
    """
    if isinstance(blob, dict):
        raw = blob.get("vulnerabilities", [])
        if isinstance(raw, list):
            return [r for r in raw if isinstance(r, dict)]
        return []
    if isinstance(blob, list):
        return [r for r in blob if isinstance(r, dict)]
    return []


def _try_parse(raw: dict[str, Any]) -> KevEntry | None:
    """Parse one raw KEV entry; return None if validation fails."""
    try:
        return KevEntry.model_validate(_normalize(raw))
    except ValidationError:
        return None
    except (TypeError, ValueError, KeyError):
        return None


def _normalize(raw: dict[str, Any]) -> dict[str, Any]:
    """Flatten the CISA KEV wire-format names into KevEntry field names."""
    return {
        "cve_id": raw.get("cveID", ""),
        "vendor_project": raw.get("vendorProject", ""),
        "product": raw.get("product", ""),
        "vulnerability_name": raw.get("vulnerabilityName", ""),
        "date_added": raw.get("dateAdded", ""),
        "short_description": raw.get("shortDescription", ""),
        "required_action": raw.get("requiredAction", ""),
        "due_date": raw.get("dueDate") or None,
        "known_ransomware_campaign_use": (
            raw.get("knownRansomwareCampaignUse", "").lower() == "known"
        ),
        "notes": raw.get("notes", ""),
        "cwes": _extract_cwes(raw.get("cwes", [])),
    }


def _extract_cwes(cwes: Any) -> list[str]:
    """Extract CWE IDs from the KEV entry; tolerate non-string entries."""
    if not isinstance(cwes, list):
        return []
    return [c for c in cwes if isinstance(c, str) and c]
