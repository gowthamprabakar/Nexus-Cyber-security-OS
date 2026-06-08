# Backlog — ADR-013: cross-agent correlation + diagnostician reasoning — 2026-06-08

> **🛑 NOT EXECUTING NOW.** Parked. **This is framing capture, NOT an ADR draft** — no ADR-013 is to be written until triggered.
> **Trigger:** **all 17 agents at Level 3** (= Platform v1.0). Cross-agent correlation consumes analyst-grade findings, so it cannot start until the detection arc completes.

- **Source:** **2026-06-08 operator conversation** (the framing below is captured from it). Related: [PR #245 benchmark §7.3](../competitive-benchmark-2026-06-08.md) (the v2.0 security-graph is the single largest residual Wiz gap).
- **Downstream dependency:** the **v2.0 Security Graph component build** (master list item #7) is gated on **ADR-013 locking** first.

## Framing seeds to preserve (expand into the ADR when triggered)

The 2026-06-08 conversation named three framing elements. They are recorded here as **seeds**, not as a finished design — the detailed framing lives in that conversation and is to be developed at trigger time.

1. **The two-problem distinction.** Cross-agent correlation is **two distinct problems**, not one — they must be separated in the ADR (do not conflate them). _(Exact boundary to be restated from the 2026-06-08 conversation when the ADR is drafted.)_

2. **The three-component split.** The build decomposes into **three components**. The ADR must define each component's boundary, interface, and ownership separately. _(Component definitions to be restated from the 2026-06-08 conversation at draft time.)_

3. **Diagnostician epistemic discipline.** The correlating/"diagnostician" reasoning layer carries an **epistemic discipline** — explicit rules about what it may _assert_ vs. _hypothesize_, evidence standards, and how it avoids laundering a guess into a confident conclusion (cf. the Supervisor `claims.>` trust-boundary fence in PR #245 §8). _(Discipline rules to be restated from the 2026-06-08 conversation at draft time.)_

## Why captured this way

Per the 2026-06-08 operating rule: parked work that is not in the detection arc must be written down with a named trigger + source, so a future session sees the full landscape and does not lose framing. The three seeds above are the load-bearing distinctions to **not forget**; their full content is to be reconstructed from the source conversation when the trigger fires.

## On trigger — first step (do NOT do now)

Reopen the 2026-06-08 operator conversation, restate the two-problem distinction + the three-component split + the diagnostician epistemic discipline in full, then draft ADR-013. Only after ADR-013 locks does the v2.0 Security Graph component build (item #7) begin.

---

— recorded 2026-06-08 (framing capture; trigger = all 17 agents at Level 3; no ADR drafted now).
