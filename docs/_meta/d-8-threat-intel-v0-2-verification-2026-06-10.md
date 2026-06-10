# D.8 Threat Intel (CTI) v0.2 — Verification Record & Cycle Closure

**Date:** 2026-06-10 · **Cycle 5 of 17** (Phase 3 of the Option α roadmap) · **Maturity:
Level 1 → Level 2 (Continuous Ingestion).** Single comprehensive directive, self-merge
cascade (Tasks 1–21), operator review at close (Task 22).

---

## §1. Cycle summary

D.8 took the Threat Intel agent from **v0.1** (3 offline file-snapshot feeds + 3
sibling-workspace correlators) to **v0.2**: a **continuous-ingestion** framework, live
**STIX 2.1 / TAXII 2.1** + **HTTP-polling** transports, **5 live feeds** (NVD, CISA KEV,
MITRE ATT&CK, abuse.ch ×3, AlienVault OTX) alongside the offline readers, **industry +
tech-stack profiles**, a **briefing** skeleton + template, and **basic threat-actor
matching**.

- **22 tasks, 22 PRs** (#367–#387 + this record). 7 milestones.
- **Tests:** threat-intel **249 → 400 passed** (+151) + 2 gated-live skips. Full repo
  **5535 passed, 59 skipped, 0 failed**.
- **Substrate seal EMPTY the entire cycle** — no charter touch (WI-T2: the continuous
  pattern is documented for a future ADR-007 third-consumer hoist, not hoisted; D.8 is
  the only consumer).
- **No charter hoist** fired (as planned — distinct from the D.2 hoist cycle).

## §2. Task execution table

| #   | Task                                                 | PR        | Risk                  |
| --- | ---------------------------------------------------- | --------- | --------------------- |
| 1   | Bootstrap (version + ADR-010 + smoke)                | #367      | LOW                   |
| 2   | Continuous-ingestion framework                       | #368      | LOW                   |
| 3   | STIX 2.1 deserializer + TAXII 2.1 client             | #369      | LOW                   |
| 4   | HTTP polling fallback                                | #370      | LOW                   |
| 5   | Live NVD CVE feed                                    | #371      | LOW                   |
| 6   | Live CISA KEV catalog                                | #372      | LOW                   |
| 7   | Live MITRE ATT&CK STIX/TAXII                         | #373      | LOW                   |
| 8   | abuse.ch feeds (URLhaus + ThreatFox + MalwareBazaar) | #374      | LOW                   |
| 9   | AlienVault OTX live feed                             | #375      | LOW                   |
| 10  | Customer industry profile loading                    | #376      | LOW                   |
| 11  | Customer tech-stack profile loading                  | #377      | LOW                   |
| 12  | Briefing generator skeleton + API                    | #378      | LOW                   |
| 13  | Briefing template + sectioning                       | #379      | LOW                   |
| 14  | Basic threat-actor matching                          | #380      | LOW                   |
| 15  | NEXUS_LIVE_THREAT_INTEL gated lane                   | #381      | LOW                   |
| 16  | Industry-vertical lane stub                          | #382      | LOW                   |
| 17  | WI-T4 live continuous-ingestion e2e                  | #383      | LOW                   |
| 18  | Lane coexistence with prior cycles                   | #384      | LOW                   |
| 19  | Cross-agent OCSF 2004 sweep                          | #385      | LOW                   |
| 20  | Per-feed coverage notes                              | #386      | LOW                   |
| 21  | Per-feed runbooks + README v0.2                      | #387      | LOW                   |
| 22  | Verification record + cycle closure                  | _this PR_ | LOW (operator review) |

## §3. Q-lock mapping (all 7 honored)

| Q   | Lock                                                 | Where honored                                                                     |
| --- | ---------------------------------------------------- | --------------------------------------------------------------------------------- |
| Q1  | (B) Continuous ingestion                             | `continuous.py` — bounded-queue backpressure + graceful shutdown (Task 2)         |
| Q2  | (A) NVD+KEV+MITRE+abuse.ch+OTX; Wiz/Unit42 → v0.3    | Live feeds Tasks 5–9; industry-feed stub Task 16                                  |
| Q3  | (C) Industry profile LOADED; full correlation → v0.3 | `customer/industry_profile.py` — loaded, does **not** drive correlation (Task 10) |
| Q4  | (B) Tech stack optional input                        | `cve_relevant_to_stack` filter, optional (Task 11)                                |
| Q5  | (B) Briefing skeleton + API; full content → v0.3     | `briefing/` skeleton + template, no LLM narration (Tasks 12–13)                   |
| Q6  | (B) Basic threat-actor detection                     | `correlators/threat_actor.py` coverage heuristic (Task 14)                        |
| Q7  | (C) STIX/TAXII + HTTP polling fallback               | `stix_taxii.py` + `http_poller.py` (Tasks 3–4)                                    |

## §4. Gates passed

- **All 5 CI checks green** on every one of the 21 self-merged PRs (server-side merge
  gate enforced each merge).
- **Substrate seal EMPTY** for all 22 tasks (no charter/shared edit; Task 15 _consumes_
  the hoisted `charter.live_lane` Pattern D without editing it).
- **OCSF 2004 byte-identical** every task: live readers were added _alongside_ the
  offline readers; `run()`'s tool-calls + the 10 offline eval cases are unchanged (WI-T5).
- **WI-T4 live continuous lane** green: two-layer e2e (offline every push + gated
  `NEXUS_LIVE_THREAT_INTEL=1`), Task 17.
- **Cross-agent sweep** (Task 19, WI-T6): 3 OCSF 2004 emitters + 8 consumers,
  2442 passed / 9 skipped / **0 failed**.
- **ruff + ruff format + mypy strict** clean per task; tool-proxy boundary inherited.

## §5. Honest findings (WI-T3)

- **The defining gap — continuous live → OCSF production loop is NOT wired (v0.3).** v0.2
  ships the continuous-ingestion _infrastructure_ + live feeds + the briefing / profile /
  threat-actor _building blocks_, all unit- and e2e-tested through **normalization**. But
  the live readers are **not** driven from the agent's `run()` correlation→OCSF path —
  the **offline `run()` remains the only OCSF-2004-emitting path** (deliberately, to keep
  the eval byte-identical, WI-T5). So "subscribe to live feeds → emit OCSF findings
  continuously" is **not** an end-to-end production capability at v0.2; it is the largest
  v0.3 carry-forward.
- **Wiz-weight target was ~80%; realistic realized ~70–75% `[estimate]`.** The live-feed
  breadth + continuous framework move the agent toward L2, but because the production
  loop above is deferred, the _realized_ capability is nearer the v0.1 baseline than the
  80% target. Stated plainly per WI-T3 rather than claimed.
- **Coverage is breadth, not depth, measured per-feed (WI-T1, no aggregate):** KEV
  ~80–90%, NVD ~45–55%, OTX ~45–55%, abuse.ch (URLhaus ~55–65 / ThreatFox ~50–60 /
  MalwareBazaar ~40–50%), MITRE ~30–40% — all `[estimate]`, see the per-feed coverage
  docs.
- **Profiles + briefing + threat-actor are loaded/structured but not yet driving
  outcomes:** industry profile doesn't change correlation (Q3); tech-stack filter is
  built but unwired into the run loop (Q4); briefing bodies are skeleton (Q5); threat-
  actor is a coverage heuristic, not attribution (Q6) — all per their locks.
- **Industry-vertical lane is a stub** (Task 16): always skips at v0.2; Wiz Landscape +
  Unit42 are v0.3 (Q2).

## §6. Watch-items carry-forward

- **WI-T2:** the continuous-ingestion pattern is documented (`continuous.py` docstring);
  re-evaluate the ADR-007 third-consumer hoist when a 2nd consumer appears (likely D.4).
- The 5 honest-findings gaps above, foremost the **continuous live → OCSF run-loop
  wiring**.
- TAXII/feed endpoint drift: the MITRE collection UUID + abuse.ch auth terms may move —
  runbooks flag this.

## §7. v0.3 deferred handoff

Wiz Cloud Threat Landscape + Unit42 industry feeds (Q2) · full industry-driven
correlation (Q3) · tech-stack CVE-filter wired into the run loop (Q4) · full briefing
content generation (Q5) · full threat-actor attribution (Q6) · **and the headline item:
wiring the live continuous readers into the agent's correlation→OCSF run loop** so live
feeds emit OCSF 2004 findings end-to-end.

## §8. Cross-references

- Cross-agent sweep: `d-8-threat-intel-v0-2-cross-agent-sweep-2026-06-10.md`
- Per-feed coverage: `d-8-threat-intel-v0-2-{nvd,kev,mitre,abuse-ch,otx}-coverage-2026-06-10.md`
- Runbooks: `packages/agents/threat-intel/runbooks/`
- v0.1 closure: `d-8-threat-intel-v0-1-verification-2026-05-21.md`

---

**D.8 Threat Intel (CTI) v0.2 — CYCLE CLOSED ✅** (pending operator merge of this record).
22/22 tasks, 7/7 milestones, substrate seal empty throughout, 0 failures.
