# ADR-005 — Async-by-default tool wrapper convention

- **Status:** accepted
- **Date:** 2026-05-09
- **Authors:** AI/Agent Eng, Detection Eng
- **Stakeholders:** every agent author; tool integrators

## Context

The platform architecture assumes concurrent agent execution: Supervisor spawns parallel specialists, Investigation Agent fans out sub-agents (depth ≤ 3, parallel ≤ 5), Curiosity Agent runs idle loops alongside detection agents, and the fabric ([ADR-004](ADR-004-fabric-layer.md)) is event-driven with async consumers.

Current implementation contradicts this. The first tool wrapper, [`packages/agents/cloud-posture/src/cloud_posture/tools/prowler.py`](../../../packages/agents/cloud-posture/src/cloud_posture/tools/prowler.py), uses blocking `subprocess.run(...)` ([line 48](../../../packages/agents/cloud-posture/src/cloud_posture/tools/prowler.py#L48)). The second, [`tools/aws_s3.py`](../../../packages/agents/cloud-posture/src/cloud_posture/tools/aws_s3.py), uses synchronous `boto3` calls. If 18 agents × N tools each ship sync, the rewrite is cross-cutting.

The decision belongs _now_, before F.3 Task 5 (IAM analyzer) and Task 10 (agent driver) bake the sync assumption deeper.

## Decision

**All tool wrappers are async-by-default.** Concrete rules:

1. **Subprocess invocations** use `asyncio.create_subprocess_exec` (not `subprocess.run`). Wrappers expose `async def` entrypoints.
2. **Boto3 / cloud SDKs** that have no native async are wrapped via `asyncio.to_thread(...)` so the wrapper signature stays `async def`. (We do _not_ adopt `aioboto3` in Phase 1a — additional dep, less mature, smaller maintenance pool. Revisit when boto3-native async lands.)
3. **HTTP clients** use `httpx.AsyncClient` (not `requests`).
4. **Per-resource concurrency** is the wrapper's responsibility. Each wrapper accepts an optional `semaphore: asyncio.Semaphore | None` parameter. Default behavior: no semaphore (caller controls); if the wrapper has known cloud-API rate-limit caveats, it documents the recommended bound.
5. **Timeouts** are passed as `timeout: float` (seconds) and enforced via `asyncio.wait_for`. Default: per-tool sensible default; per-call override.
6. **Cancellation** must be honored. Wrappers do not catch `asyncio.CancelledError`.
7. **Failures** raise typed exceptions (e.g. `ProwlerError`); they do not return error sentinels. Caller (the agent driver) decides degraded-mode behavior; wrappers don't make that decision.
8. **Tests** use `pytest-asyncio` with `asyncio_mode = "strict"` (already in [`pyproject.toml`](../../../pyproject.toml)) and the `@pytest.mark.asyncio` marker.

### Standard wrapper shape

```python
async def run_tool(
    *args,
    timeout: float,
    semaphore: asyncio.Semaphore | None = None,
) -> ToolResult:
    if semaphore is not None:
        async with semaphore:
            return await asyncio.wait_for(_run(...), timeout=timeout)
    return await asyncio.wait_for(_run(...), timeout=timeout)
```

### What changes immediately

- F.3 Task 4.5 (added by this ADR): convert the existing Prowler + S3 wrappers to async. ~1 hour of work; small diff. Tests update to `@pytest.mark.asyncio`.
- F.3 Task 5 onward: every new wrapper is async from the first commit. Plan tasks update accordingly when this ADR lands.
- Charter's `LLMProvider.complete` ([ADR-003](ADR-003-llm-provider-strategy.md)) is `async def`.

## Consequences

### Positive

- Concurrency story is real, not aspirational. Investigation Agent's depth-3 / parallel-5 fanout works without thread-pool gymnastics.
- Single concurrency model across the entire platform: charter, fabric ([ADR-004](ADR-004-fabric-layer.md)), tool wrappers, LLM provider. No sync/async bridging at hot paths.
- Per-tool rate-limit management via semaphores composes naturally with per-tenant fanout.
- Cancellation propagates: a cancelled agent invocation actually stops in-flight tool calls, freeing budget.

### Negative

- Boto3-via-`to_thread` adds a thread per concurrent AWS call. Acceptable: cloud-API calls are I/O-bound, the GIL releases on socket I/O, and concurrency cap is the AWS rate limit, not Python threads.
- New engineers must know `async/await`. Charter examples + a short `packages/agents/README.md` make this trivial; idiomatic Python 3.12 in any case.
- Sync code paths (CLI smoke tests, ad-hoc scripts) need `asyncio.run(...)`. Acceptable boilerplate.

### Neutral / unknown

- Whether to standardize on `anyio` for structured concurrency primitives (TaskGroup, etc.). Defer; stdlib `asyncio.TaskGroup` (Python 3.12) covers Phase 1a needs. Revisit when sub-agent orchestration land in D.7.

## Alternatives considered

### Alt 1: Sync-by-default, run agents in `ThreadPoolExecutor`

- Why rejected: the platform isn't a synchronous request-response service. Investigation Agent's fanout, fabric subscribers, and LLM streaming are all natively async. Wrapping sync tools in threads is a workaround at the wrong layer.

### Alt 2: Sync wrappers + an async layer above

- Why rejected: doubles the surface area (every tool has a sync core and an async wrapper). The single async wrapper is simpler.

### Alt 3: `aioboto3` for native async AWS

- Why rejected (for Phase 1a): smaller maintenance pool than upstream `boto3`, occasional API drift. `asyncio.to_thread(boto3_call)` is a 5-line abstraction with the same effective behavior. Revisit when native-async boto3 ships.

## References

- Triggering wrappers: [`packages/agents/cloud-posture/src/cloud_posture/tools/prowler.py`](../../../packages/agents/cloud-posture/src/cloud_posture/tools/prowler.py), [`tools/aws_s3.py`](../../../packages/agents/cloud-posture/src/cloud_posture/tools/aws_s3.py).
- Companion: [ADR-003](ADR-003-llm-provider-strategy.md), [ADR-004](ADR-004-fabric-layer.md).
- Plan delta: F.3 gets a new "Task 4.5 — Async refactor of existing tool wrappers" inserted before Task 5; subsequent tasks adopt async wrapper shape from the first commit.
- pytest config: `addopts` and `asyncio_mode` already configured in root [`pyproject.toml`](../../../pyproject.toml).
