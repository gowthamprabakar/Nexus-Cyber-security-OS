# v0.3 / Phase D — progress snapshot (2026-06-15, morning)

> Operator-facing snapshot after the 2026-06-14→15 overnight cascade. Records what merged
> overnight, what is recon-ready for operator decision, and the operator-presence work queued
> for the morning. All overnight work obeyed the SAFE mandate (no scaffolds/stubs, no substrate
> touch, no operator-presence work, self-merge on green CI only).

## 1. Overnight cascade — merged clean (self-merge, all CI green)

| PR   | What                                                                     | Track     |
| ---- | ------------------------------------------------------------------------ | --------- |
| #676 | hoist `osquery` wrapper → `nexus_runtime` (canary deps=[] preserved)     | A-2.3 PR1 |
| #677 | reachability correlator — CVE→process tri-state join                     | A-2.3 PR2 |
| #678 | reachability **live lane** via `NEXUS_LIVE_REACHABILITY` + osqueryi gate | A-2.3 PR3 |

**A-2.3 is CLOSED** (PR1+PR2+PR3). The CVE→runtime-process reachability correlator is built,
tri-state-honest (`reachable` / `not_loaded` / `indeterminate`), default-OFF, byte-identical
offline, and operator-runnable against real osqueryi behind the gate. Substrate seal EMPTY.

> Implementation note carried for operator review: PR3 consolidated the directive's separately
> named `live_reachability` / `reachability_snapshot` flags into the single existing
> `assess_reachability` + an `osquery_runner` injection seam — same capability (gated real
> osqueryi + deterministic CI + byte-identical default), one fewer redundant flag. Flagged, not assumed.

## 2. Recon delivered overnight (doc-only — forks await operator decision)

| Doc                              | Subject                                  | Headline finding                                                                                                                                                                                 |
| -------------------------------- | ---------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `v0-3-a-2-4-recon-2026-06-14.md` | secrets-in-runtime → DSPM                | Trivy already _detects_ secrets; normalizer _silently drops_ them (no CVE-ID). Route to DSPM via additive OCSF-2003 discriminator + sibling-workspace. Feeds **ADR-015** (operator-morning).     |
| `v0-3-a-4-recon-2026-06-14.md`   | D.2 effective-perms (built-but-undriven) | Simulator fully built + unit-tested; `run()` short-circuits to a hardcoded pattern-match. Gap = one call site. Substrate CLEAR. ~7-11d.                                                          |
| `v0-3-a-3-recon-2026-06-14.md`   | CSPM breadth + "MCP" + k8s-posture       | **Premise correction: "MCP" = Multi-Cloud-Posture agent, NOT Model Context Protocol — no MCP scanner exists.** CSPM breadth small (AWS ~3 native + Prowler subprocess). k8s RBAC heuristic-only. |

**Forks surfaced for operator (not actioned overnight):** A-2.4 emission class + transport;
A-4 simulation scope + emission shape + cadence; A-3 CSPM path (Prowler-map vs Steampipe/#23)

- k8s depth + speculative-hoist question + "genuine MCP scanner = net-new #20?".

## 3. Track status (as of this snapshot)

- **Track A (depth):** A-1 CLOSED (#661). A-2.1/A-2.2 merged (#671/#672). **A-2.3 CLOSED**
  (#676-678). A-2.4 / A-3 / A-4 = **recon-ready, awaiting operator forks**.
- **Track B (AppSec D.14):** Q-AppSec-1..5 answered; **B-1 first PR is operator-presence work**
  (queued for morning, NOT done overnight).
- **Track C (meta-harness):** C-1 DSPy compilation_cadence wired (#662). C-2 recon delivered
  (#673, Hermes Phase 1); **C-2 PR1 (minimal hoist) is per-PR operator-review** (queued).
- **Track D (continuous infra):** D-1 (#658) + D-2 cadence/freshness/metrics/audit/status
  (#663-667) merged. NOTE: continuous infra is built but **loop-activation = v0.4** (pause
  trigger #25 honored — not activated).

## 4. Queued for operator-presence (deliberately NOT done overnight)

1. **ADR-015** — secrets-in-runtime ownership decision (fed by the A-2.4 recon above).
2. **B-1 first PR** — D.14 AppSec agent first build.
3. **C-2 PR1** — meta-harness minimal hoist (`detect_skill_trigger`), opened for per-PR review.
4. Any **substrate touch** (#19/#29), **license adoption** (#23 — esp. Steampipe SSPL), or
   **continuous-loop activation** (#25) — all operator-gated.

## 5. Integrity / safety ledger

- Substrate seal (`packages/shared` + `packages/charter`) **EMPTY** across all overnight PRs.
- No scaffolds/placeholders/stubs introduced (the `continuous status-page stub` #667 predates
  the overnight window).
- No pause trigger fired overnight; cascade ran to completion.
- All live paths (`NEXUS_LIVE_*`) remain gated/default-OFF; CI deterministic.

## 6. Suggested next operator step

Decide the A-2.4 / A-3 / A-4 forks (§2) so Track A depth can resume self-merge, then take up the
operator-presence queue (§4) — ADR-015 first (unblocks A-2.4), then B-1 and C-2 PR1.

## 7. References

- Recon docs — §2 table. A-2.3 cycle — PRs #676/#677/#678.
- Branch-protection state — `v0-3-branch-protection-status-2026-06-14.md` (Python CI now required).
- Track-A progress — institutional memory `project_v0_3_track_a_progress.md`.
