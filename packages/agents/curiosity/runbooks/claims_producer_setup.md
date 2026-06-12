# Runbook — claims.> Producer Setup (curiosity v0.2)

D.12 is the **first publisher** on the `claims.>` substrate (ADR-012) and is **producer-only**: it
publishes `claims.tenant.<tid>.agent.curiosity` and **never subscribes** to `claims.>` (WI-X14).

At subscription setup, run the producer-only fence:

```python
from curiosity.claims.producer_only import assert_no_claims_subscription

assert_no_claims_subscription(my_subscription_subjects)  # raises on any claims.* subject
```

A self-subscription would create a generative feedback loop (curiosity reads its own claims and
generates more), so the fence is a hard guard mirroring supervisor's `_FORBIDDEN_SUBSCRIPTIONS`.
v0.2 also adds a `schema_version` field to the CuriosityClaim envelope (additive, Q7); existing
fields stay byte-identical (WI-X6).
