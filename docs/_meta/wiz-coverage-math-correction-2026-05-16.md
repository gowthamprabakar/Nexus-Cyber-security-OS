# Wiz weighted-coverage math correction — 2026-05-16

**What this is.** A definitive recompute of the Wiz weighted-coverage metric reported in every system-readiness snapshot since 2026-05-11-EOD. The prior reports had two compounding errors that this document closes.

**Why now.** Discovered while writing the post-A.1 readiness snapshot. The user direction was: "Recompute the entire column from scratch, pin the real number, note the correction in the next report." This file is the recompute; the post-A.1 readiness report ([`system-readiness-2026-05-16-post-a1.md`](system-readiness-2026-05-16-post-a1.md)) now references this file for the corrected numbers.

**Scope of correction.** This affects only the **weighted-coverage** metric. None of the underlying per-capability coverage percentages are wrong — Trivy + OSV + KEV + EPSS in D.1 is still 20% of the vulnerability surface, F.6 hash-chained audit is still 100% of the compliance surface, etc. The arithmetic on top of those percentages was where the errors lived.

---

## What was wrong

### Error 1: Weights summed to 1.15, not 1.00

Every Wiz-weight table since 2026-05-11-EOD has used the same 12-row weight distribution:

| Row               | Stated weight |
| ----------------- | ------------: |
| CSPM              |          0.40 |
| Vulnerability     |          0.15 |
| CIEM              |          0.10 |
| CWPP              |          0.10 |
| Compliance/Audit  |          0.05 |
| CDR/Investigation |          0.07 |
| Network Threat    |          0.05 |
| DSPM              |          0.08 |
| AppSec            |          0.05 |
| Remediation       |          0.05 |
| Threat Intel      |          0.03 |
| AI/SaaS Posture   |          0.02 |
| **Sum**           |      **1.15** |

The headline row labeled the total as `1.00`, but the actual column summed to `1.15`. A row (probably DSPM at 0.08, added when D.5 was reframed from DSPM to multi-cloud CSPM on 2026-05-13) entered without rebalancing the rest.

### Error 2: Stated totals didn't match contribution-column sums

Even granting the 1.15 weight base, the stated totals were hand-computed and drifted from the actual column sums. Here is each report's claimed total versus the real sum:

| Report                                         | Stated total | Real column sum (at 1.15 base) | Normalized to 1.00 base |
| ---------------------------------------------- | -----------: | -----------------------------: | ----------------------: |
| `system-readiness-2026-05-11-eod.md`           |      `0.118` |                       (varies) |                       — |
| `system-readiness-2026-05-13.md`               |      `0.308` |                          0.435 |               **37.8%** |
| `system-readiness-2026-05-13-eod.md`           |      `0.468` |                          0.590 |               **51.3%** |
| `system-readiness-2026-05-16.md` (morning)     |      `0.508` |                          0.600 |               **52.2%** |
| `system-readiness-2026-05-16-post-a1.md` (eve) |      `0.530` |                          0.622 |               **54.1%** |

The trend was directionally right (coverage really has been rising), but the absolute numbers have been wrong by 2-9 percentage points in either direction. The post-A.1 number was, coincidentally, only 1.1pp off — but that's coincidence, not correctness.

---

## The corrected weight distribution

I'm preserving the original relative emphasis but normalizing the column to sum to exactly 1.00 by dividing every weight by 1.15 and rounding to two decimal places (with the largest weight absorbing the rounding residual to keep the sum exact).

| Capability                    | Old weight | Old / 1.15 | **Corrected weight** |
| ----------------------------- | ---------: | ---------: | -------------------: |
| **CSPM (F.3+D.5+D.6)**        |       0.40 |     0.3478 |             **0.35** |
| **Vulnerability (D.1)**       |       0.15 |     0.1304 |             **0.13** |
| **CIEM (D.2)**                |       0.10 |     0.0870 |             **0.09** |
| **CWPP (D.3)**                |       0.10 |     0.0870 |             **0.09** |
| **DSPM**                      |       0.08 |     0.0696 |             **0.07** |
| **CDR / Investigation (D.7)** |       0.07 |     0.0609 |             **0.06** |
| **Network Threat (D.4)**      |       0.05 |     0.0435 |             **0.04** |
| **Compliance / Audit (F.6)**  |       0.05 |     0.0435 |             **0.04** |
| **AppSec**                    |       0.05 |     0.0435 |             **0.04** |
| **Remediation (A.1+)**        |       0.05 |     0.0435 |             **0.04** |
| **Threat Intel (D.8)**        |       0.03 |     0.0261 |             **0.03** |
| **AI / SaaS Posture**         |       0.02 |     0.0174 |             **0.02** |
| **TOTAL**                     |   **1.15** |     1.0000 |             **1.00** |

Verification: `0.35 + 0.13 + 0.09 + 0.09 + 0.07 + 0.06 + 0.04 + 0.04 + 0.04 + 0.04 + 0.03 + 0.02 = 1.00` ✓

---

## The corrected weighted coverage (post-A.1, 2026-05-16 EOD)

Using the corrected weights, this morning's coverage percentages (pre-A.1), and the post-A.1 lift:

| Capability                    | Corrected weight | Coverage (post-A.1) | Weighted contribution |
| ----------------------------- | ---------------: | ------------------: | --------------------: |
| **CSPM (F.3+D.5+D.6)**        |         **0.35** |                 84% |                0.2940 |
| **Vulnerability (D.1)**       |         **0.13** |                 20% |                0.0260 |
| **CIEM (D.2)**                |         **0.09** |                 30% |                0.0270 |
| **CWPP (D.3)**                |         **0.09** |                 50% |                0.0450 |
| **DSPM**                      |         **0.07** |                  0% |                     0 |
| **CDR / Investigation (D.7)** |         **0.06** |                 85% |                0.0510 |
| **Network Threat (D.4)**      |         **0.04** |                 80% |                0.0320 |
| **Compliance / Audit (F.6)**  |         **0.04** |                100% |                0.0400 |
| **AppSec**                    |         **0.04** |                  0% |                     0 |
| **Remediation (A.1+)**        |         **0.04** |                 50% |                0.0200 |
| **Threat Intel (D.8)**        |         **0.03** |                 15% |                0.0045 |
| **AI / SaaS Posture**         |         **0.02** |                  0% |                     0 |
| **TOTAL (weighted)**          |         **1.00** |                     |   **0.5395 (~54.0%)** |

Column-sum verification: `0.2940 + 0.0260 + 0.0270 + 0.0450 + 0 + 0.0510 + 0.0320 + 0.0400 + 0 + 0.0200 + 0.0045 + 0 = 0.5395` ✓

**Real corrected weighted coverage post-A.1: ~54.0%.**

### A.1's actual lift, recomputed

Pre-A.1 (this morning) Remediation row: `0.04 × 5% = 0.0020`
Post-A.1 Remediation row: `0.04 × 50% = 0.0200`
**A.1 lift: +0.018 in weighted terms ≈ +1.8pp.**

The post-A.1 report claimed +2.2pp on the prior 0.05-weight basis. The corrected lift is **+1.8pp** — slightly smaller than reported, but still a real, single-session shift.

---

## Backcasting: the corrected history

For accountability, here's what the prior reports' headline numbers would have been under corrected math (using each report's stated coverage percentages):

| Snapshot                           | Stated coverage | **Corrected coverage** | Error magnitude |
| ---------------------------------- | --------------: | ---------------------: | --------------: |
| 2026-05-09 (Phase 1a baseline)     |          ~1.25% |                  ~1.1% |         -0.15pp |
| 2026-05-10 (post-F.2)              |           ~6.7% |                  ~5.8% |          -0.9pp |
| 2026-05-11-EOD (post-D.1)          |          ~11.8% |                 ~10.3% |          -1.5pp |
| 2026-05-13 (post-D.7)              |          ~30.8% |                 ~26.8% |          -4.0pp |
| 2026-05-13-EOD (post-D.5)          |          ~46.8% |                 ~40.7% |          -6.1pp |
| 2026-05-16 morning (post-D.6 v0.2) |          ~50.8% |                 ~52.2% |      **+1.4pp** |
| 2026-05-16 evening (post-A.1)      |          ~53.0% |                 ~54.0% |      **+1.0pp** |

The error was small at low coverage levels and grew with the CSPM family — which makes sense, since CSPM was the over-weighted row (0.40 → 0.35 corrected). The May-13-EOD report was the worst-affected: claimed 46.8% real was 40.7% (-6.1pp).

**Direction-of-error note:** the recent reports (post-D.6 v0.2 onwards) under-reported coverage by ~1-1.4pp. The earlier reports over-reported. The post-A.1 number changes by only +1.0pp under correction — so the prior report's framing ("largest single-session delta since F.3 v0.1") survives correction, but only barely.

---

## Hygiene rules going forward

To prevent this from recurring:

1. **Pin the weights once in this file** and link to it from every subsequent readiness report's §8. No more inline-rewriting of the weight column.
2. **Sum-check the column** by hand or by a one-line script before publishing. The check is `sum(weights) == 1.00` and `sum(contributions) == stated_total`.
3. **When a new capability row is added** (e.g. when a future "do" agent makes a new OCSF class meaningful), explicitly rebalance the existing 12 rows down by the new row's weight. Do not introduce 13-row, 14-row distributions that drift the sum.
4. **Distinguish coverage delta vs reported delta** in commentary. Coverage moves with real shipping; reported numbers can change for math reasons too. Both kinds of delta deserve transparent annotation.

---

## What this changes in next-steps planning

Nothing material. The Phase-1c slice ordering, critical path, and recommendations in the post-A.1 readiness report all hinge on **what's actually shipped** (10 agents, 1 cure-quadrant agent, A.1's three modes operational) — not on the headline-coverage decimal point. The corrected 54.0% is still in the "50-60% by M2" band the post-A.1 report described, and Phase 1 GA timing claims stand.

The thing that does shift is **investor/board comms**: previous board-deck numbers cited 50.8% and 53.0%. The board should be quietly told of the math correction at the next scheduled update. The corrected 54.0% is a marginally better story, but the credibility hit from a discovered math error is real — naming it ourselves is cheaper than having a board member find it.

---

## Sign-off

**Corrected number pinned: ~54.0% Wiz weighted coverage at HEAD `3e0577f` (post-A.1, post-D.6 v0.3).**

This file is the authoritative reference. The post-A.1 readiness report (and every future readiness report) cites this file rather than re-deriving the math inline.

— recorded 2026-05-16 (post-A.1, math-correction record)
