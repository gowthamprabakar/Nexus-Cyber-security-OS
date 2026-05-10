"""JSON serialization — schema-stable wire format for Meta-Harness consumption.

Per F.2 plan Task 11. Wraps pydantic's `model_dump_json` /
`model_validate_json` with consistent indent + UTC datetimes. The key set
emitted is exactly the model field names; downstream consumers
(Meta-Harness, comparison-over-time tools) can rely on it as a stable
contract.

All four functions are thin wrappers — the heavy lifting is the model
schemas in `results.py` and `compare.py`. Round-trip equality is
guaranteed because the models are frozen and the encoders are pydantic-
canonical.
"""

from __future__ import annotations

from eval_framework.compare import ComparisonReport
from eval_framework.results import SuiteResult

__all__ = [
    "comparison_from_json",
    "comparison_to_json",
    "suite_from_json",
    "suite_to_json",
]


def suite_to_json(suite: SuiteResult, *, indent: int | None = 2) -> str:
    """Serialize a `SuiteResult` to JSON.

    Args:
        suite: The suite result.
        indent: Pretty-print indent (default 2). Pass `None` for a compact
            single-line payload.
    """
    return suite.model_dump_json(indent=indent)


def suite_from_json(payload: str | bytes) -> SuiteResult:
    """Parse JSON into a `SuiteResult`. Raises `pydantic.ValidationError`
    on shape mismatch."""
    return SuiteResult.model_validate_json(payload)


def comparison_to_json(report: ComparisonReport, *, indent: int | None = 2) -> str:
    return report.model_dump_json(indent=indent)


def comparison_from_json(payload: str | bytes) -> ComparisonReport:
    return ComparisonReport.model_validate_json(payload)
