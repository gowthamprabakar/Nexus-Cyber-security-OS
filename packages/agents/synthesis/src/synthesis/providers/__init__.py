"""LLM provider resilience for D.13 (synthesis v0.2 — Q5; DeepSeek primary + Anthropic fallback).

Composes charter providers only (ADR-007 v1.1 — no per-agent llm.py; this is a resilience
wrapper under a non-llm namespace, consuming charter.llm/charter.llm_adapter)."""
