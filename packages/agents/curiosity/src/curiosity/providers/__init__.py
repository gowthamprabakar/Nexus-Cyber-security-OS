"""LLM provider resilience for the curiosity agent (v0.2, Q3).

DeepSeek-primary + Anthropic-fallback, composing **charter providers only** — no per-agent
``llm.py`` (the ``test_no_per_agent_llm_module`` guard). The wrapper lives HERE under
``providers/`` (NOT ``curiosity/llm/``) per the Cycle-13/14 institutional lesson (WI-X12).
"""
