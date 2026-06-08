# Parked architectural work — master list (2026-06-08)

> **🛑 NOT EXECUTING NOW.** Every item below is **parked**. The detection-maturity arc (all 17 agents → Level 3) has **absolute priority** (operator decision, 2026-06-08). Each item lists an **explicit trigger** and a **source** — nothing is "we'll remember." When a trigger fires, open the linked item file.

- **Operating rule (locked 2026-06-08):** anything parked but **not** part of the detection arc must be captured here with a named trigger + source. Not in memory, not implicit — written down.
- **Default trigger:** _all 17 agents at Level 3_ (= Platform v1.0). **One exception** has its own trigger: Wazuh compliance enrichment (design-partner compliance pitch).

## The parked landscape

| #   | Parked item                                                     | Trigger to open                                                                        | Source                                                                                                      | Detail                                                                                           |
| --- | --------------------------------------------------------------- | -------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| 1   | **ADR-013 — cross-agent correlation + diagnostician reasoning** | All 17 agents at Level 3                                                               | 2026-06-08 operator conversation                                                                            | [`2026-06-08-adr-013-cross-agent-correlation.md`](2026-06-08-adr-013-cross-agent-correlation.md) |
| 2   | **Hermes agents**                                               | All 17 agents at Level 3                                                               | 2026-06-08 operator conversation                                                                            | [`2026-06-08-hermes-agents.md`](2026-06-08-hermes-agents.md)                                     |
| 3   | **Wazuh compliance enrichment (narrowed)**                      | **Design-partner sales conversation needs a compliance pitch** (NOT the detection arc) | [PR #245 benchmark §4](../competitive-benchmark-2026-06-08.md) · operator decisions 2026-06-07 + 2026-06-08 | [`2026-06-08-wazuh-compliance-enrichment.md`](2026-06-08-wazuh-compliance-enrichment.md)         |
| 4   | **AppSec / IaC / secrets-in-code agent** (net-new)              | All 17 agents at Level 3                                                               | [PR #245 benchmark §7.3](../competitive-benchmark-2026-06-08.md)                                            | net-new agent; ~0.04 Wiz weight, 0% today                                                        |
| 5   | **AI-SPM / SaaS posture (SSPM) agent** (net-new)                | All 17 agents at Level 3                                                               | [PR #245 benchmark §7.3](../competitive-benchmark-2026-06-08.md)                                            | net-new agent; ~0.02 Wiz weight, 0% today                                                        |
| 6   | **Surface Track — UI / dashboards**                             | All 17 agents at Level 3                                                               | [PR #245 benchmark §8.5](../competitive-benchmark-2026-06-08.md)                                            | console / dashboards (0 LOC today)                                                               |
| 7   | **v2.0 Security Graph — component build**                       | **After ADR-013 locks**                                                                | [PR #245 benchmark §7.3](../competitive-benchmark-2026-06-08.md) · item #1                                  | the attack-path / blast-radius layer; greenfield, partly gated by the tenant-RLS substrate fix   |

## Trigger groups (at a glance)

- **`all 17 agents at Level 3`** → items 1, 2, 4, 5, 6.
- **`after ADR-013 locks`** → item 7 (depends on #1).
- **`design-partner compliance pitch`** → item 3 (Wazuh) — _independent of the detection arc._

## What is NOT parked (the active arc)

The **per-agent detection-maturity cycles** (Level 1 → 2 → 3, strict serial, one agent at a time) per the [maturity roadmap](../../strategy/nexus-agent-maturity-roadmap-2026-06-07.md) §4. Currently in flight: **F.3 Cloud Posture v0.2** (live AWS). The parallel **tenant-RLS substrate fix** brainstorm (PR #253) is the one authorized substrate cycle (γ sequencing) and is not parked.

---

— recorded 2026-06-08 (operator decision: detection arc absolute priority; parked work captured with explicit triggers).
