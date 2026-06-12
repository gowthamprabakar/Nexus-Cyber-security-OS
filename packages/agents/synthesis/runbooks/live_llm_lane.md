# Runbook — Live LLM Lane (synthesis v0.2)

## Gate

```bash
NEXUS_LIVE_SYNTHESIS=1 \
NEXUS_LLM_PROVIDER=anthropic ANTHROPIC_API_KEY=sk-... \
uv run pytest packages/agents/synthesis/tests/integration/test_synthesis_live_llm_e2e.py -v
```

The live lane (`synthesis.live_lane`) is **separate** from the byte-identical stub harness
(Q6/WI-Y5): it validates real LLM capability, not byte-identity. `synthesis_live_skip_reason`
skips it in CI (no provider configured). (The older `NEXUS_LIVE_LLM` smoke test still exists.)
