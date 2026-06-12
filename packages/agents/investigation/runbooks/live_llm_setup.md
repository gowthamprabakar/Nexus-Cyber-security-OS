# Runbook — Live-LLM Setup (investigation v0.2)

D.7 synthesizes hypotheses with a load-bearing LLM via `charter.llm_adapter` only (no per-agent
`llm.py`; provider wrappers live under `investigation/providers/`). The synthesizer is resilient:
DeepSeek → Anthropic fallback, then a **deterministic enumeration fallback** so an investigation
never fails for want of an LLM (H3).

## Running the live e2e gate (WI-I4)

The HARD acceptance gate drives the full 6-stage pipeline against a real provider and asserts that
every produced hypothesis survives **all six** invariants. CI skips it; operators run it:

```bash
NEXUS_LIVE_INVESTIGATION=1 \
  NEXUS_LLM_PROVIDER=anthropic \
  NEXUS_LLM_MODEL_PIN=claude-haiku-4-5-20251001 \
  ANTHROPIC_API_KEY=... \
  uv run pytest \
  packages/agents/investigation/tests/integration/test_investigation_live_e2e.py -v
```

For DeepSeek (OpenAI-compatible), set `NEXUS_LLM_PROVIDER=openai-compatible` plus its base-URL and
key env vars (see `charter.llm_adapter.config_from_env`).

## What the gate proves

The deterministic eval suite proves the _contract_. This gate proves the _real_ path: prompts
elicit valid grounded hypotheses, the model_pin is reachable, the adapter budget fires, and — the
D.7-specific risk — real LLM output passes the categorical-only / evidence-chain / no-speculation
guards rather than tripping them.
