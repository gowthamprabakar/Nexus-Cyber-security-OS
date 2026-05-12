# Example: LLM unavailable → deterministic fallback

A scheduled investigation runs nightly under a contract whose LLM provider has rotated credentials and isn't authenticated yet. The cron job calls `investigation-agent run --no-llm` (or the contract's `llm_provider=None` propagates through).

D.7's response when the synthesizer can't reach the LLM:

1. **SCOPE / SPAWN / SYNTHESIZE (sub-agents)** — identical to the happy-path example. Sub-investigations don't need the LLM; they're pure tool calls.
2. **SYNTHESIZE (hypothesis generation)** — instead of asking the LLM to draft hypotheses, the synthesizer emits **one hypothesis per finding** with:
   - `hypothesis_id = "H-<finding_uid>"`
   - `statement = "Evidence: " + finding_info.title`
   - `confidence = 0.5` (uncalibrated; the operator interprets)
   - `evidence_refs = ("finding:<uid>",)`
3. **VALIDATE** — every evidence_ref is by construction valid (it points at a finding the agent itself collected). No drops.
4. **PLAN** — runs the deterministic containment template per finding class_uid:
   - 2003 Compliance → "Re-run remediation playbook for `<finding.path>`"
   - 2004 Detection → "Quarantine the affected resource pending operator review"
   - 2002 Vulnerability → "Apply patch per the CVE's vendor advisory"
5. **HANDOFF** — writes the same four artifacts. The markdown `hypotheses.md` includes a banner: `> Note: this report was generated without LLM synthesis. Hypotheses are enumerated from collected findings; an operator should re-run with LLM enabled for richer correlation.`

The operator sees a clear signal that the LLM was unavailable and decides whether to re-run. **Compliance correctness is unaffected** — the OCSF 2005 wire shape is the same; the evidence chain is the same; the timeline is the same. NL synthesis is a UX nicety, not load-bearing for the audit trail.
