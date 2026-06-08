# Backlog — flaky audit `caplog` test — 2026-06-08

> **🛑 NOT EXECUTING NOW** — opportunistic fix only; the detection-arc discipline holds. This is **tech debt**, not architectural work, so it is not gated on the Level-3 arc.

- **Test:** `packages/agents/audit/tests/test_agent.py::test_run_logs_warning_when_non_wall_clock_budget_overrun`
- **Symptom:** a **cross-package `caplog` logging-state flake**. **Passes 3/3 in isolation, 2/2 in-package, and in CI.** It failed exactly once during the F.3 v0.2 Task 9 cross-agent sweep (PR #262), only in the _combined_ `charter + audit` run.
- **Root-cause hypothesis:** pytest's `caplog` capture state bleeds across module boundaries when running cross-package suites in sequence — another package's logging config intermittently swallows the WARNING record this test asserts on. Not a product bug.
- **Severity:** **LOW** — pre-existing, blocks no cycle, CI-green, represents no real F.6 behavior regression.
- **Trigger:** a convenient time **OR** before the **F.6 Audit v0.2** cycle begins (whichever is earlier).
- **Estimated effort:** ~30 min — likely a pytest fixture-isolation fix (e.g. `caplog.set_level(logging.WARNING, logger=<the driver's logger>)` and/or asserting on the specific logger with `propagate=True`, rather than relying on root-level capture).
- **Source:** F.3 v0.2 Task 9 cross-agent sweep ([`f-3-cloud-posture-v0-2-cross-agent-sweep-2026-06-08.md`](../f-3-cloud-posture-v0-2-cross-agent-sweep-2026-06-08.md) §4), 2026-06-08.

## On trigger — first step (do NOT do now)

Reproduce by running the combined suite a few times (`uv run pytest packages/charter/tests/ packages/agents/audit/`), then make the test robust to cross-test logging state (scope the `caplog` capture to the driver's named logger). Fix lands as its **own** small PR — **not** inside any detection-arc task, and **not** by changing F.6 product code.

> Note: this item is **not** part of the architectural [parked-work master list](2026-06-08-parked-architectural-work.md) (that tracks work gated on the Level-3 arc / design-partner triggers). It is captured here so the flake is written down with a trigger + source rather than relying on memory.

---

— recorded 2026-06-08 (F.3 v0.2 Task 9 follow-up; opportunistic, LOW severity, no fix made).
