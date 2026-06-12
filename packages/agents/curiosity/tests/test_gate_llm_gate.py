"""curiosity v0.2 Task 17 — assert_llm_only_with_gaps tests (WI-X15/H4, NEW)."""

from __future__ import annotations

import pytest
from curiosity.gate.llm_gate import UnnecessaryLLMCallError, assert_llm_only_with_gaps


def test_gaps_present_llm_called_ok() -> None:
    assert_llm_only_with_gaps(["region:eu-west-1"], llm_called=True)


def test_no_gaps_llm_skipped_ok() -> None:
    # The common H4 path: no gaps, LLM not called.
    assert_llm_only_with_gaps([], llm_called=False)


def test_gaps_present_llm_skipped_ok() -> None:
    # Skipping with gaps present is allowed (e.g. budget exhausted) — only empty+called is illegal.
    assert_llm_only_with_gaps(["region:eu-west-1"], llm_called=False)


def test_no_gaps_llm_called_raises() -> None:
    with pytest.raises(UnnecessaryLLMCallError, match="empty gaps"):
        assert_llm_only_with_gaps([], llm_called=True)


def test_message_mentions_h4_discipline() -> None:
    with pytest.raises(UnnecessaryLLMCallError, match="skip the LLM"):
        assert_llm_only_with_gaps((), llm_called=True)


def test_accepts_tuple_gaps() -> None:
    assert_llm_only_with_gaps(("region:x",), llm_called=True)
