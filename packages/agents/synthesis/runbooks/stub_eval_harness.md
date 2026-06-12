# Runbook — Stub-LLM Eval Harness (synthesis v0.2)

## Run the deterministic offline eval

```bash
uv run pytest packages/agents/synthesis -q
```

The 10 stub-LLM eval cases run offline + deterministically. The OCSF 2004 emission is additive,
so the cases stay **byte-identical** (WI-Y5) as v0.2 features land — `eval_continuity.py` asserts
the count + the emission determinism. The live lane never runs here.
