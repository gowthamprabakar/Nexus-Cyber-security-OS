# Runbook — Privacy Contract Testing (curiosity v0.2)

D.12 emits LLM-generated text (hypothesis statements, rationale, probe directives) that must
discuss sensitive data **categorically** — by classification label, never by value (WI-X9).

```python
from nexus_runtime.llm_invariants.categorical import assert_categorical_only

assert_categorical_only(hypothesis.statement)   # raises on plaintext SSN / AWS key / JWT / PAN
assert_categorical_only(hypothesis.rationale)
```

Tenant scope is the other privacy pillar: every scan is tenant-scoped, always; cross-tenant
aggregation is forbidden at every version (WI-X13).

```python
from curiosity.tenant.scoped import assert_tenant_scoped

assert_tenant_scoped(contract)   # raises if customer_id missing/empty
```

The live e2e (`test_curiosity_live_e2e.py`) exercises both against real LLM output.
