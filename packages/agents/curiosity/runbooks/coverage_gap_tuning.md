# Runbook — Coverage-Gap Tuning per Tenant (curiosity v0.2)

v0.2 detects three gap kinds (Q4), each tracked separately (WI-X1) with its own
`coverage_gap_id` namespace:

| Kind      | Module              | Trigger                                                 | gap_id               |
| --------- | ------------------- | ------------------------------------------------------- | -------------------- |
| region    | `gaps/region.py`    | `asset_count >= N` AND no/stale findings                | `region:<region>`    |
| technique | `gaps/technique.py` | MITRE technique (from D.8) unseen in D.3/D.4 for N days | `technique:<id>`     |
| time      | `gaps/time_gap.py`  | asset class unscanned (F.3/D.5/k8s) for N hours         | `time:<asset_class>` |

Per-tenant region thresholds:

```python
from curiosity.gaps.region import RegionGapThresholds, resolve_region_thresholds, detect_region_gaps

overrides = {tenant_id: RegionGapThresholds(min_asset_count=5, min_gap_days=14)}
thresholds = resolve_region_thresholds(tenant_id, overrides=overrides)
gaps = detect_region_gaps(state, thresholds)
```

The fleet default is identical to the v0.1 floor (asset_count ≥ 10, gap ≥ 30 days) so the
deterministic eval stays byte-identical.
