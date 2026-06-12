# Runbook — Failure Recovery + Escalation (supervisor v0.2)

## Classification (Q3)

`failure/classifier.py::classify_failure` -> transient / permanent / timeout. Unknown errors
classify as **permanent** (escalate, never retried blindly — H4).

## Retry policy (Q3/H4)

`failure/retry.py::run_with_retry` — transient -> **at most 1** retry (total attempts <= 2);
permanent + timeout escalate immediately. A retry emits `supervisor.delegation.retried`.

## Escalation (H4)

One attempt per delegation (except the single transient retry). On failure: emit an escalation
finding + audit entry; **the operator decides recovery**. No automatic recovery beyond the
bounded retry. Full circuit-breaker is v0.3.
