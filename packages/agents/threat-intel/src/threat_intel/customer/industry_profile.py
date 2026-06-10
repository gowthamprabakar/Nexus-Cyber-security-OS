"""Customer industry profile loading (D.8 v0.2 Task 10).

Loads the customer's industry vertical from ``customer_context.md`` and maps it to a
known vertical + correlation keywords. Per **Q3** the profile is **loaded + available**
at v0.2 but does **not** yet drive correlation behavior — full industry-driven
correlation is v0.3.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

#: Known industry → (vertical, correlation keywords). Extended in v0.3.
INDUSTRY_VERTICALS: dict[str, tuple[str, tuple[str, ...]]] = {
    "financial-services": ("finance", ("banking", "payment", "fintech", "swift")),
    "healthcare": ("healthcare", ("hospital", "phi", "ehr", "medical")),
    "technology": ("technology", ("saas", "cloud", "software")),
    "government": ("public-sector", ("federal", "agency", "gov")),
    "energy": ("energy", ("utility", "scada", "ics", "grid")),
    "retail": ("retail", ("ecommerce", "pos", "payment")),
    "manufacturing": ("manufacturing", ("ot", "ics", "scada", "plc")),
}

_INDUSTRY_RE = re.compile(r"industry\s*[:=]\s*\*{0,2}\s*([A-Za-z][\w &/-]*)", re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class IndustryProfile:
    industry: str
    vertical: str
    keywords: tuple[str, ...] = field(default_factory=tuple)


def normalize_industry(raw: str) -> str:
    """``"Financial Services"`` / ``"financial_services"`` → ``"financial-services"``."""
    slug = re.sub(r"[\s_]+", "-", raw.strip().lower())
    slug = re.sub(r"[^a-z0-9-]", "", slug).strip("-")
    return slug


def parse_industry(text: str) -> str | None:
    """Extract the raw industry value from ``customer_context.md`` text — supports a
    YAML-frontmatter ``industry:`` key or a markdown ``**Industry:** X`` line."""
    m = _INDUSTRY_RE.search(text)
    return m.group(1).strip() if m else None


def load_industry_profile(text: str) -> IndustryProfile | None:
    """Build an `IndustryProfile` from customer-context text, or `None` if no industry
    is declared. Unknown industries get the ``"other"`` vertical (still loaded)."""
    raw = parse_industry(text)
    if not raw:
        return None
    industry = normalize_industry(raw)
    if not industry:
        return None
    vertical, keywords = INDUSTRY_VERTICALS.get(industry, ("other", ()))
    return IndustryProfile(industry=industry, vertical=vertical, keywords=keywords)


def load_industry_profile_from_path(path: Path) -> IndustryProfile | None:
    """Load the profile from a ``customer_context.md`` file; `None` if absent/empty."""
    if not path.is_file():
        return None
    return load_industry_profile(path.read_text(encoding="utf-8"))
