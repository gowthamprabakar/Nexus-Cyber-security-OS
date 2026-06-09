# ADR-016 — Tool-proxy hard boundary for `permitted_tools` enforcement

- **Status:** **proposed**
- **Date:** 2026-06-09
- **Authors:** AI/Agent Eng
- **Stakeholders:** every agent author; charter substrate maintainers; every PR reviewer; compliance (the tool-call audit trail is part of the change-management evidence)
- **Cycle:** NLAH Framework Full Backfill — Milestone 1, Task 1 (design). Implementation lands in Task 2 ([feat/charter-tool-proxy-hard-boundary]); the three bypass fixes it unblocks land in Tasks 3–5.
- **Audit reference:** [NLAH framework quality audit (PR #316)](../nlah-framework-audit-2026-06-09.md)

## Context

The NLAH framework quality audit ([#316](../nlah-framework-audit-2026-06-09.md)) surfaced one root-cause governance defect from which three concrete bypasses (C-1/C-2/C-3) descend:

> **`permitted_tools` is opt-in, not a choke point.** `ToolRegistry.call(name, permitted=…)` raises `ToolNotPermitted` when `name ∉ contract.permitted_tools` ([tools.py:32–37](../../../packages/charter/src/charter/tools.py)), and it consumes budget + writes a `tool_call` audit event — **but it is reached only when an agent voluntarily routes a call through `Charter.call_tool()`** ([context.py:88–105](../../../packages/charter/src/charter/context.py)). Nothing forces tool invocations through that path. An agent can `import` a tool function and call it directly, fully bypassing the whitelist, the budget meter, and the charter audit.

Consequences confirmed by direct code reading in the audit:

- **C-1 (HIGH, safety-critical)** — remediation calls `apply_patch` directly in EXECUTE mode (`dry_run=False`, real `kubectl` mutation) at [agent.py:477](../../../packages/agents/remediation/src/remediation/agent.py); the one agent that mutates customer infrastructure is not charter-gated at the mutation boundary.
- **C-2 (MEDIUM)** — vulnerability calls `is_kev` / `nvd_enrich` (external httpx network calls) directly and they are not registered at all; `tools.md` falsely claims charter routing.
- **C-3 (LOW–MEDIUM)** — investigation calls 5 registered worker tools directly, bypassing the whitelist and charter tool-audit.

The audit also found the `ExecutionContract` schema has **no `forbidden_tools` field** ([contract.py](../../../packages/charter/src/charter/contract.py)), so the spec's forbidden-tool concept is unenforced.

Patching the three call sites one-by-one (audit Option C) leaves the **category** open: any future agent, or any future NLAH/code change to an existing agent, can re-introduce a bypass simply by importing a tool function. The operator's standard for this cycle is explicit — _when an agent works, it works 100% per spec; no debt accumulation_. That standard requires removing the bypass **as a class**, not as three instances.

This ADR adopts **Option D** from the audit: make `permitted_tools` a **hard structural boundary** so that direct invocation is not merely discouraged but **prevented and detected**.

## Decision

**A registered tool is reachable only through the charter at runtime, and a CI guard makes direct-import bypass detectable at build time.** The boundary is enforced by two complementary mechanisms — a runtime proxy (catches it when it happens) and a static guard (catches it before it ships) — because neither alone is sufficient in Python.

### Why not "make the import fail"

The directive's Task-2 sketch proposed that "direct import of tool functions fails or returns proxy stubs." We deliberately **do not** rely on import-level magic. In Python you cannot make a plain `from vulnerability.tools.kev import is_kev` raise without invasive `sys.meta_path` import hooks, which would (a) fight the test suite that imports tool modules to unit-test them, (b) break IDE/static analysis, and (c) be fragile across the workspace's editable installs. Import-blocking is the wrong layer. We enforce at the **call layer** (runtime proxy) and the **source layer** (CI guard) instead — same guarantee, no fragility.

### Mechanism 1 — Runtime: registry-owned proxies, raw callables not directly callable

1. **Tools are registered as today** via `ToolRegistry.register(name, func, *, version, cloud_calls)`. The registry remains the single source of truth for what a tool _is_.
2. **The registry wraps each registered callable in a `_ProxiedTool`.** A proxied tool, when called **outside** an active `Charter.call_tool` dispatch, raises `DirectInvocationBlocked(tool_name)` instead of executing. The registry sets a per-call re-entrancy flag (a `ContextVar`) that is true only for the duration of a `Charter.call_tool` dispatch; the proxy checks it.
3. **`Charter.call_tool(name, …)` remains the only sanctioned entry point.** It performs, in order: wall-clock check → permitted-tools check (`ToolNotPermitted` if denied) → **forbidden-tools check** (new; see Mechanism 3) → budget consume → `tool_call` audit append → dispatch through the proxy with the re-entrancy flag set.
4. **Agents that already use `ctx.call_tool` are unaffected.** cloud-posture and the other 8 fully-gated specialists work unchanged — this is the backward-compatibility anchor verified in Task 2's regression evidence.

This converts "an agent _should_ call `ctx.call_tool`" into "a registered tool _physically cannot_ run except through `ctx.call_tool`." A direct call to a registered tool function raises at runtime, surfacing the bug immediately rather than silently bypassing governance.

> **Scope boundary — what a proxy is NOT.** Pure helper functions (normalizers, detectors, scorers, summarizers, context-bundle builders) are **not tools** and are **not registered or proxied**. They take data and return data, touch no external state, and consume no budget. Calling them directly is correct and stays correct (see audit §5 — the "pure fns only" column). The proxy governs exactly the set of side-effecting / external / stateful operations that belong in the registry. Deciding tool-vs-helper is a per-function judgment recorded in each agent's `tools.md` during M3; ADR-007 v1.7 will give the objective test (does it perform I/O, touch cloud/network/store, or mutate state? → tool).

### Mechanism 2 — Build time: CI guard against direct tool imports

A static check (lives in CI alongside lint) fails the build when an agent driver imports a registered-tool callable directly instead of reaching it through the registry. Concretely: a test that walks each agent's `agent.py` / `normalizer.py` (and equivalent driver modules) and asserts they do not `from <pkg>.tools.<mod> import <registered_tool_callable>`. Importing the tool **module** to _register_ it in `build_registry()` is allowed; importing a tool **callable** for direct invocation is not. This catches a re-introduced bypass at PR time, before the runtime proxy would ever fire in production.

The allowed/blocked distinction is name-based against the registry manifest, so the guard cannot be defeated by aliasing without also failing registration.

### Mechanism 3 — Schema: `forbidden_tools` as documented defense-in-depth

Add `forbidden_tools: list[NonEmptyStr] = Field(default_factory=list)` to `ExecutionContract` ([contract.py](../../../packages/charter/src/charter/contract.py)), with a validator: **`forbidden_tools` and `permitted_tools` must not overlap** (an overlapping name is a contract authoring error → validation failure).

**Honest framing:** once `permitted_tools` is a hard allowlist enforced by the proxy, `forbidden_tools` is **functionally redundant for enforcement** — anything not permitted is already denied. We add it for two non-enforcement reasons only, and the ADR records this so nobody later mistakes it for the load-bearing control:

1. **Explicit-denial documentation** — a contract author can state "this agent must _never_ touch `execute_*`," making intent auditable rather than implied by omission.
2. **Defense-in-depth** — `Charter.call_tool` checks `forbidden_tools` before `permitted_tools`, so an accidentally over-broad `permitted_tools` (or a future wildcard) can be explicitly clawed back.

`forbidden_tools` is **not** the boundary. The proxy + allowlist is the boundary.

### New exception

`DirectInvocationBlocked(ToolError)` — raised by a proxied tool invoked outside a charter dispatch. Message names the tool and points to `ctx.call_tool`. Lives in [exceptions.py](../../../packages/charter/src/charter/exceptions.py) beside `ToolNotPermitted`.

## Migration strategy

The shift is **opt-out-proof but backward-compatible** for already-correct agents:

| Cohort                                                                                                                      | Today                                                       | After Task 2                                                                                  | Action required                            |
| --------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------- | --------------------------------------------------------------------------------------------- | ------------------------------------------ |
| 9 fully-gated specialists (cloud-posture, identity, multi-cloud, runtime, network, data-sec, k8s, compliance, threat-intel) | route registered tools via `ctx.call_tool`; pure fns direct | **unchanged** — proxies allow their existing path                                             | none (regression-verify only)              |
| remediation (C-1)                                                                                                           | `apply_patch` direct                                        | proxy raises `DirectInvocationBlocked` until routed                                           | **Task 3** — route through `ctx.call_tool` |
| vulnerability (C-2)                                                                                                         | `is_kev`/`nvd_enrich` direct + unregistered                 | register + route                                                                              | **Task 4**                                 |
| investigation (C-3)                                                                                                         | 5 worker tools direct                                       | route through child-scoped charter                                                            | **Task 5**                                 |
| curiosity, synthesis                                                                                                        | empty registry by design                                    | unaffected (nothing registered)                                                               | none                                       |
| supervisor, meta-harness, audit                                                                                             | by-design (router / orchestrator / always-on)               | unaffected; audit's always-on direct reads stay registered-but-policy-exempt per ADR-007 v1.3 | document deviation (M3)                    |

**Sequencing guarantee:** Task 2 ships the proxy + `forbidden_tools` + CI guard, but the guard is introduced **failing-closed only for agents already migrated**. Because Tasks 3–5 land _after_ Task 2, the proxy's `DirectInvocationBlocked` is exactly the mechanism that _proves_ each fix: before the fix the proxy raises; after the fix the call succeeds through the gate. Task 2's own test suite asserts the proxy fires for a deliberately-direct call and passes for a gated call. The CI guard is wired in Task 2 but its agent-by-agent assertions are added as each of Tasks 3–5 migrates its agent, so CI never goes red on an un-migrated agent mid-cycle.

## Backward compatibility

- **Agent code using `ctx.call_tool`:** no change.
- **Unit tests that import tool callables directly** (e.g. `test_kev.py` importing `is_kev` to test the function in isolation): **still allowed** — the CI guard scopes to _driver_ modules (`agent.py`, `normalizer.py`, and the per-agent driver set), not to `tests/`. Testing a tool function directly is legitimate; _invoking it in the agent's run path_ is not.
- **`build_registry()` importing tool modules to register them:** allowed (it imports to register, not to invoke).
- **Existing contracts without `forbidden_tools`:** the field defaults to `[]`, so all current contracts validate unchanged.

## Consequences

**Positive**

- The bypass becomes a **class-level impossibility**: a registered tool cannot execute outside the charter, and a re-introduced direct import fails CI.
- C-1/C-2/C-3 fixes (Tasks 3–5) become _verifiable by construction_ — the proxy raising `DirectInvocationBlocked` pre-fix is the regression evidence.
- Every future agent inherits the hard boundary for free; the "100% or don't ship" standard is structurally enforced for tool-calling integrity, not policed by review vigilance.
- `tool_call` audit events become complete (no off-charter tool execution), restoring the charter audit chain as a faithful record.

**Negative / costs**

- One indirection layer (`_ProxiedTool`) on every tool dispatch — negligible runtime cost (a `ContextVar` read), but it is new substrate surface to maintain.
- Agents that _legitimately_ need a non-charter fast path (audit's always-on reads) require an explicit, documented exemption rather than silent direct calls — slightly more ceremony, which is the point.
- The tool-vs-helper classification must be made deliberately for every registered surface during M3; ambiguous cases (audit §5 "taxonomy ambiguity" for multi-cloud/network/data-sec `tools.md`) must be resolved, not left implicit.

## Alternatives considered

1. **Option C — patch the three call sites only.** Rejected: leaves the category open; the next agent re-introduces it. Fails the cycle's "no debt" standard.
2. **Import-level blocking (`sys.meta_path` hooks).** Rejected: fragile, fights tests/IDEs/editable installs, wrong layer (see "Why not make the import fail").
3. **Pure CI guard, no runtime proxy.** Rejected: a static check can be evaded (dynamic dispatch, `getattr`) and gives no runtime guarantee; production could still execute an off-charter tool if the guard has a blind spot.
4. **Pure runtime proxy, no CI guard.** Rejected: catches the bypass only when the code path executes (which env-gated/live paths may not in CI), so a bug could merge and only surface in production. The static guard shifts detection left.
5. **Make `forbidden_tools` the primary control.** Rejected: a denylist is unbounded and fails open (anything not listed is allowed); the allowlist + proxy fails closed. `forbidden_tools` stays as documentation/defense-in-depth only.

## Test plan (implemented in Task 2)

- `DirectInvocationBlocked` raised when a registered tool is called outside `ctx.call_tool`.
- A gated call through `ctx.call_tool` succeeds and (a) checks `permitted_tools`, (b) checks `forbidden_tools` first, (c) consumes budget, (d) appends a `tool_call` audit event.
- `ToolNotPermitted` still raised for a registered-but-unpermitted tool.
- `forbidden_tools` ∩ `permitted_tools` ≠ ∅ → contract validation error.
- Contract without `forbidden_tools` validates (default `[]`).
- Re-entrancy flag correctly scopes a single dispatch (nested/concurrent dispatch via `asyncio.TaskGroup` each gated independently — covers the parallel-ingest agents).
- **Backward-compat regression:** cloud-posture (the only fully-gated agent today) runs end-to-end unchanged.
- CI-guard unit: a synthetic driver module importing a registered tool callable directly fails the guard; importing the tool module in `build_registry()` passes; importing the callable in `tests/` passes.

~15 tests, per the directive's Task-2 estimate.

## References

- [NLAH framework quality audit (#316)](../nlah-framework-audit-2026-06-09.md) — §5 (tool-calling integrity), C-1/C-2/C-3, S- root cause
- [ADR-002 — Charter as context manager](ADR-002-charter-as-context-manager.md)
- [ADR-007 — Cloud Posture reference agent](ADR-007-cloud-posture-as-reference-agent.md) — v1.3 always-on class (audit exemption); v1.7 (this cycle) will fold the hard boundary into the universal compliance checklist
- [ADR-011 — SAFETY-CRITICAL PR-flow discipline](ADR-011-pr-flow-and-branch-protection-discipline.md) — Tasks 2–5 are SAFETY-CRITICAL by its standard
- Charter substrate: [contract.py](../../../packages/charter/src/charter/contract.py) · [context.py](../../../packages/charter/src/charter/context.py) · [tools.py](../../../packages/charter/src/charter/tools.py) · [exceptions.py](../../../packages/charter/src/charter/exceptions.py)
