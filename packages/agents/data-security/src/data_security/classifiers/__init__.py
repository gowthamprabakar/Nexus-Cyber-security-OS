"""Sensitive-data classifiers for the D.5 Data Security agent.

Public API: ``classify(text: str) -> ClassifierLabel``.

The classifier returns a label enum only — NEVER the matched substring.
This is the load-bearing Q6 privacy-contract invariant from the D.5 v0.1
plan. See ``patterns.py`` for the implementation + the rationale.
"""

from __future__ import annotations

from data_security.classifiers.patterns import classify, classify_bytes

__all__ = ["classify", "classify_bytes"]
