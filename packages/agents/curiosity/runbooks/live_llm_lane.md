# Runbook — Live-LLM Lane (curiosity v0.2)

The HARD acceptance gate (WI-X4) drives the full 7-stage pipeline against a real provider and
asserts every produced hypothesis survives all six invariants. CI skips it; operators run it:

```bash
NEXUS_LIVE_CURIOSITY=1 \
  NEXUS_LLM_PROVIDER=anthropic \
  NEXUS_LLM_MODEL_PIN=claude-haiku-4-5-20251001 \
  ANTHROPIC_API_KEY=... \
  uv run pytest \
  packages/agents/curiosity/tests/integration/test_curiosity_live_e2e.py -v
```

What it proves: a gap-bearing scan drives a real hypothesize call whose output passes
categorical-only / coverage-gap-cited / bounded-retry, emits OCSF 2004 + the claims.> envelope,
stays tenant-scoped, and never subscribes to claims.>.
