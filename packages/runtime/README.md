# `nexus-runtime`

Cross-fleet **production-loop driver** for Phase C (v0.2 INFRASTRUCTURE → v0.2 OPERATING).

`agent.run()` is single-shot (one invocation = one scan); each agent's `continuous/` scheduler only
computes _which tenants are due_. This package holds the one shared loop that turns those due-sets
into actual runs — **A.0 (supervisor) orchestrated**: the supervisor owns a `ContinuousDriver`,
registers each agent's scheduler, and on each `tick(now)` the driver computes the due
`(agent, tenant)` set and dispatches each through the supervisor's existing signed-contract
dispatch path.

Deliberately dependency-light and substrate-free (a non-`charter`/`shared` home, per the Phase C
substrate-policy decision): pure orchestration over a scheduler protocol + an injected dispatch
callable, deterministic given a caller-supplied `now`. No agent imports, no charter coupling.
