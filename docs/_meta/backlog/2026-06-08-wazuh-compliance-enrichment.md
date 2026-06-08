# Backlog — Wazuh compliance enrichment (narrowed scope) — 2026-06-08

> **🛑 NOT EXECUTING NOW.** Parked. **Trigger is independent of the detection-maturity arc.**
> **Trigger:** a **design-partner sales conversation requires a compliance pitch.** When that happens, open this as a ~1-week extraction cycle. Until then it stays parked.

- **Source:** [PR #245 competitive benchmark §4](../competitive-benchmark-2026-06-08.md) (the Wazuh inventory was built **from scratch** there) · operator decisions **2026-06-07** + **2026-06-08**.
- **Estimated effort:** ~1 week of team work.

## Scope (narrowed — compliance only)

**In scope:**

- **Compliance mapping CSV extraction** for **PCI DSS**, **HIPAA**, **NIST 800-53**, **GDPR**.
- **ATT&CK tagging vocabulary** (MITRE technique IDs / taxonomy as an open standard).

**Explicitly NOT in scope:**

- ❌ Detection-logic patterns / rule bodies
- ❌ SCA (Software Composition Analysis)
- ❌ Active Response extraction

## Methodology (provenance discipline)

- **ADR-008 provenance discipline:** a **GPL-isolated workspace**, **extractor scripts**, and **fact tables only**.
- **Clean-room facts-vs-GPL rules:** extract **facts and open standards** (regulator/standards-body control catalogs, MITRE technique IDs, the _mapping_ of control→requirement) — **never** Wazuh's copyrightable GPL expression (rule/decoder XML, SCA YAML, scripts).

## Why parked (the honest history)

- On **2026-06-07**, "Wazuh extraction" was caught as a **wrong premise** — no extraction methodology pre-existed (the assumed "ADR-008 clean-room methodology / prior Wazuh extraction plan" did not exist; the benchmark built the Wazuh inventory from scratch). See PR #245 §4.
- On the **same 2026-06-08 conversation** the scope was **narrowed to compliance-only** (the four frameworks + ATT&CK vocabulary above), dropping detection/SCA/Active-Response.
- It **defers until agent-build progress justifies the engagement** — specifically, until a design partner's compliance pitch needs it. It is **not** gated on the Level-3 arc.

## On trigger — first steps (do NOT do now)

1. Confirm the design-partner compliance requirement (which frameworks they actually need).
2. Stand up the GPL-isolated extraction workspace + extractor scripts per ADR-008 provenance discipline.
3. Produce fact tables (control catalogs + cross-mappings + ATT&CK vocabulary); wire into the Compliance agent's framework coverage.

---

— recorded 2026-06-08 (parked; trigger = design-partner compliance pitch, independent of the detection arc).
