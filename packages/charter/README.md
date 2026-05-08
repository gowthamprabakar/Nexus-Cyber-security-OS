# `nexus-charter`

The runtime charter is the universal physics every Nexus agent obeys.

## What it does

- **Execution contracts** — typed YAML envelope for each invocation (Pydantic-validated)
- **Budget enforcement** — 5-dimensional limits (LLM calls, tokens, wall-clock, cloud-API calls, MB written)
- **Tool whitelisting** — version-pinned registry; calls outside the whitelist raise `ToolNotPermitted`
- **Workspace management** — path-addressable per-invocation files + persistent memory mounts
- **Audit hash chain** — append-only, SHA-256-chained, tamper-detected
- **Verifier** — re-derives hashes to detect tampering or chain breaks

## Usage

```python
from charter import Charter, ExecutionContract, ToolRegistry, load_contract

contract = load_contract("invocation.yaml")
registry = ToolRegistry()
registry.register("my_tool", my_tool_fn, version="1.0.0", cloud_calls=0)

with Charter(contract, tools=registry) as ctx:
    result = ctx.call_tool("my_tool", llm_calls=1, tokens=50, arg="x")
    ctx.write_output("findings.json", b"{...}")
    ctx.assert_complete()
```

The CLI:

```bash
charter validate invocation.yaml
charter audit verify /workspaces/cust/agent/run-id/audit.jsonl
```

## License

Apache 2.0 — this is one of the open-source foundations of Nexus Cyber OS.

## See also

- Reference agent: `src/charter/examples/hello_world_agent/`
- Architecture: `docs/architecture/runtime_charter.md`
- Build plan: `docs/superpowers/plans/2026-05-08-f-1-runtime-charter-v0.1.md`
