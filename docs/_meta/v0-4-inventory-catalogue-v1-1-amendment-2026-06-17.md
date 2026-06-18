# Inventory Catalogue v1.1 Amendment (2026-06-17)

Amends `v0-4-inventory-catalogue-2026-06-16.md` (v1.0-draft, #711) per the three
reconciliation items flagged in the v1.0 team banner. **Doc-only**; substrate seal
clear. Resolves R-1 (D-numbering), R-2 (AppSec status), R-3 (missing agents).

All claims below are **verified against main `1991114`** (Layer 36 — not transcribed):
agent self-IDs read from each package's `pyproject.toml` description.

---

## R-1 — D-numbering (canonical scheme + the divergences it resolves)

The v1.0 catalogue used D.7 = Threat-Intel / D.8 = Compliance / D.9 = AppSec. The
**operator-canonical** scheme (this amendment) aligns to the code where the code is
already right, and **renumbers where main has collisions**:

| Canonical | Agent (package)                             | Main self-ID today                         | Action                                               |
| --------- | ------------------------------------------- | ------------------------------------------ | ---------------------------------------------------- |
| **D.7**   | Investigation (`investigation`)             | D.7 (#8) ✓                                 | none                                                 |
| **D.8**   | Threat-Intel (`threat-intel`)               | D.8 (#12) ✓                                | none                                                 |
| **D.9**   | Compliance (`compliance`)                   | **D.6 (#13)** ✗                            | **rename code D.6 → D.9** (follow-up)                |
| **D.14**  | AppSec (`appsec`)                           | D.14 (#14) ✓                               | none                                                 |
| **D.5**   | Data-security (`data-security`)             | D.5 (#11) ✓ (keeps D.5)                    | none                                                 |
| **(new)** | Multi-cloud-posture (`multi-cloud-posture`) | **D.5 (#8)** ✗ (collides w/ data-security) | **rename** (per #718-D2; team picks a free D-number) |
| **D.6**   | K8s-posture (`k8s-posture`)                 | D.6 (#9)                                   | keeps D.6 (compliance vacates it)                    |

⚠️ **Verify-against-main discrepancy surfaced (Layer 36):** main currently has **two
D.5** (data-security #11 + multi-cloud-posture #8) and **two D.6** (k8s-posture #9 +
compliance #13). The canonical scheme above resolves both, but achieving it requires
**package self-ID renames in code** (compliance D.6→D.9; multi-cloud-posture off D.5) —
those are **follow-up code PRs**, not part of this doc amendment. This amendment records
the canonical target; the renames track separately so the catalogue and code converge.

The catalogue body should be read with the canonical column above as authoritative;
the v1.0 D.7=Threat-Intel / D.8=Compliance / D.9=AppSec labels are superseded.

---

## R-2 — AppSec build status

v1.0 marked **"D.9 AppSec — Unbuilt."** Corrected:

> **D.14 AppSec — Built v0.1 (v0.3 B-1 cycle, PRs #690-707).** Checkov IaC + gitleaks
> secrets-in-code + Semgrep SAST scanners; GitHub / GitLab / Bitbucket SCM connectors;
> clone-for-scan; OCSF 2003 emission; `nexus_eval_runners` entry-point. v0.4 Stage 1.6
> added the code-side `kg_writer` (CODE_REPOSITORY + IAC_ARTIFACT + DEFINED_IN, #724).

(Number corrected D.9 → D.14 per R-1.)

---

## R-3 — agents missing from the v1.0 catalogue

v1.0 omitted five code agents. Verified against main:

**Write to the knowledge graph (need inventory specs in the catalogue):**

- **D.13 Synthesis (`synthesis`)** — has `kg_writer.py`; writes `synthesis_report` entities (LLM-narrated cross-agent synthesis). KG-writing LLM agent.
- **D.12 Curiosity (`curiosity`)** — has `kg_writer.py`; writes `hypothesis` / coverage-gap entities (generative). KG-writing LLM agent.

**Do NOT write inventory (acknowledge, no node ownership):**

- **D.7 Investigation (`investigation`)** — **no `kg_writer`** (verified); an LLM _consumer_ that reads the graph via `neighbors()` (`memory_walk.py`). Reader, not writer.
- **F.6 Audit (`audit`)** — orchestration/integrity agent (hash-chained audit); non-inventory-writing.
- **Agent #0 Supervisor (`supervisor`)** — declarative router/dispatcher; non-inventory-writing.

This makes the full kg-writing roster (verified): cloud-posture, compliance, threat-intel,
synthesis, curiosity, meta-harness (the 6 pre-v0.4) **+** the v0.4 Stage-1 additions
(D.3 runtime #722, D.14 appsec #724, D.5 data-security DynamoDB/RDS #725 findings — note
data-security's _graph_ `kg_writer` is still pending its Stage-1 writer PR).

---

## Status

R-1 / R-2 / R-3 reconciled at the doc level. **Follow-up code work (not this PR):** the
two package self-ID renames (compliance D.6→D.9; multi-cloud-posture off D.5) to make the
code match this canonical scheme — surfaced for operator scheduling. Catalogue v1.0 +
this v1.1 amendment together are the current authoritative inventory spec.
