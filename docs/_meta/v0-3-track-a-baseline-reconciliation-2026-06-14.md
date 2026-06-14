# v0.3 / Phase D — Track A baseline reconciliation vs #647-verified (2026-06-14)

> **Status:** Correction-of-record (doc-only). Resolves the standing flag that the
> **v0.3 directive DRAFT** carried Track A baselines contradicting the Phase D readiness
> audit (#647). The **final** directive corrected them; this doc is the committed record
> so every Track A coverage claim anchors to #647-verified, not the draft.

## 1. What was wrong (the draft) vs what's right (final + #647)

The directive **draft** carried inflated/under-stated baselines for three Track A agents.
The **final** directive (operator paste, 2026-06-14) corrected them. All final baselines
now match #647's verified per-agent coverage table (`phase-d-readiness-audit-2026-06-14.md`
§Dimension-2, the 0.5673 total).

| workstream / agent         | DRAFT baseline (wrong) | FINAL directive | #647-verified                     | aligned?        |
| -------------------------- | ---------------------- | --------------- | --------------------------------- | --------------- |
| A-2 D.1 Vulnerability      | ~40%                   | **20%**         | **20%** (0.13 wt)                 | ✅              |
| A-3 CSPM (F.3+D.5+k8s)     | —                      | **84%**         | **84%** (0.35 wt)                 | ✅              |
| A-4 D.2 CIEM               | —                      | **37.5%**       | **37.5%** (0.09 wt, AWS-primary)  | ✅              |
| A-5 D.3 CWPP               | —                      | **52.5%**       | **52.5%** (0.09 wt)               | ✅              |
| A-6 DSPM / data-security   | ~35%                   | **50%**         | **50%** (0.07 wt)                 | ✅              |
| (dropped) D.8 Threat Intel | ~35%                   | **dropped**     | **72.5%** (already > v0.3 target) | ✅ drop correct |

**Verified platform baseline: ~56.7% (range 55.4–58.1%)** — replaces the unsupported ~63%
the draft narrative implied.

## 2. Caveats that MUST travel with every Track A coverage claim

Straight from #647 — these bound any "+Npp" statement:

1. **All values are `[estimate]` ranges, never instrumented.** No coverage number is
   measured; they are bounded judgements.
2. **CSPM 84% (A-3) is a carried-forward F.3 judgement** — F.3 had _zero_ rule movement in
   v0.2 and k8s realized only ~30-35%. Re-rating the Compliance/Audit 100% row (audit
   saturation vs compliance _breadth_ ~35%) drops the total ~2pp to ~55%.
3. **A-2 surface-vs-recount (FLAG-3, A-2 launch doc §2):** Trivy already does OS + language
   vuln matching _within images_. The A-2 +5.9pp is **surface expansion** (host / serverless
   / filesystem / process targets) + the **deep reachability correlator** (operator-chosen
   Fork A) — NOT re-counting image SCA that already works. The +5.9pp is only fully earned
   when the deep correlator (A-2.3) lands.
4. **A-1 live-loop lift (~+5–8pp) is realized when the gated live lanes RUN** (operator-run),
   not by the wiring alone (A-1 verification record #661).
5. **Honest ceiling:** detector depth caps **~75–80%**; the final push to the 85% PRD target
   needs the v2.0 inventory graph (greenfield) — out of v0.3 scope.

## 3. Anchor

Track A's stated close target is **~74–76%** (from the ~56.7% verified baseline). Every
workstream-close coverage recompute cites the #647-verified per-agent number as its
baseline and applies the caveats above. No Track A coverage claim references the draft
figures. This closes the standing baseline-correction debt.

## 4. References

- Phase D readiness audit — `phase-d-readiness-audit-2026-06-14.md` §Dimension-2 (0.5673
  total; per-agent table; caveats 1-4; ceiling).
- A-2 launch doc — `v0-3-track-a-2-launch-2026-06-14.md` §2 (FLAG-3 surface-vs-recount).
- A-1 verification record — `v0-3-track-a-1-verification-2026-06-14.md` §5 (live-lift realized when live lanes run).
- v0.3 / Phase D directive (operator, 2026-06-14) — final Track A table.
