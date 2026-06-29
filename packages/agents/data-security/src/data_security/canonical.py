"""Canonical cross-agent resource identifiers — re-exported from the shared
``charter.canonical`` single source of truth (ADR-023).

Kept as a thin re-export so existing data-security call sites
(``from data_security.canonical import s3_bucket_arn``) are unchanged.
"""

from __future__ import annotations

from charter.canonical import s3_bucket_arn

__all__ = ["s3_bucket_arn"]
