# v0.4 Stage 1.1 (A-5) — D.3 Runtime depth + runtime inventory — brainstorm

**Status:** brainstorm for operator review (per-PR review; the calibration template for Stage 1.2-1.6).
**Directive:** `docs/_meta/v0-4-directive-2026-06-16.md` §3 Stage 1.1 + Option X (fold inventory discovery into depth).
**Agent:** `packages/agents/runtime-threat` (the catalogue's "C.x Runtime"; package self-ID is the runtime-threat detection agent).
**Discipline:** depth-first; per-agent ownership; substrate seal EMPTY; live behind `NEXUS_LIVE_*` gates; offline byte-identical.

> ⚠️ Numbering note (R-1): the directive/this plan use "A-5 / D.3 Runtime"; the inventory catalogue (#711) labels this **C.x Runtime**. The v1.1 catalogue amendment reconciles numbering. The _package_ is unambiguous: `runtime-threat`.

---

## 1. Current state (recon-verified vs main `d55d8c7`)

| Capability                                    | State on main                                      | Evidence                                                                                                                                  |
| --------------------------------------------- | -------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| Falco rules                                   | **4 default rules** + hot-reload rule-pack manager | `falco/rule_packs.py` (`DEFAULT_RULE_PACK`: terminal-shell / read-sensitive-file / outbound-C2 / privileged-container; `RulePackManager`) |
| Tracee                                        | present (eBPF behavioral, realtime)                | `tools/tracee*.py`                                                                                                                        |
| osquery                                       | present, **single `.sql` pack** per run            | `tools/` osquery runner                                                                                                                   |
| Passive baseline                              | present (collect only; **no drift detection**)     | `baseline/observer.py` + `persistence.py`                                                                                                 |
| FIM                                           | **absent**                                         | no file-integrity module                                                                                                                  |
| `kg_writer.py`                                | **absent**                                         | runtime-threat does not write inventory to the SemanticStore                                                                              |
| eval_runner / live_lane / correlators / mitre | present                                            | `eval_runner.py`, `live_lane.py`, `correlators/`, `mitre/`                                                                                |

**So the net-new for Stage 1.1 is:** FIM · Falco rule-pack expansion · Tracee depth · osquery multi-query · **active** anomaly on the existing passive baseline · **runtime inventory discovery + `kg_writer.py`** (Option X).

---

## 2. Goal + scope boundary

- **Goal:** D.3 Runtime reaches full detection maturity AND populates its domain inventory (L5-runtime + L6 behavior) into the Postgres SemanticStore.
- **Covers:** FIM, expanded Falco/Tracee/osquery detection, heuristic active anomaly, runtime inventory (processes/files/containers/L5-runtime properties), kg_writer.
- **Does NOT cover (boundary):** ML baselining (v0.5, P-3 of directive); the cloud config of the host (D.3/F.3 AWS posture owns the EC2/VM node — Runtime _annotates_ it, per the catalogue ownership rule); image-at-rest vulns (D.1). Runtime **contributes** L5-runtime/L6 to existing host/pod nodes; it does not redefine them.

---

## 3. Approach — per component (options + recommendation)

### 3a. FIM (file integrity monitoring)

- **Options:** (i) Falco-rule-based file-write detection (reuse the existing Falco path); (ii) a dedicated FIM module with a watched-path set + baseline hash + change events; (iii) osquery `file_events`/FIM table.
- **Recommendation:** **(ii) dedicated FIM module** emitting `File integrity event (L6)` (the catalogue's node), seeded from a configurable watched-path set, with Falco file-write rules (3b) as the realtime trigger. osquery FIM as an alternate collector behind the sensor gate. Keeps FIM a first-class node, not buried in a Falco rule.
- **Open decision (operator):** default watched-path set (OS-critical paths only vs. configurable per-tenant) — low-risk default = OS-critical + opt-in extension.

### 3b. Falco rule-pack expansion

- From 4 default → a curated pack expansion via the existing `RulePackManager` (hot-reload already supports it). Add high-value MITRE-mapped rules (privilege-escalation, persistence, defense-evasion, lateral-movement file/exec/net). **No fabrication of rule semantics** — each rule maps to a real Falco rule + MITRE technique; cite source.
- **Self-merge** (per-agent; additive to the pack).

### 3c. Tracee depth

- Extend the existing Tracee behavioral signatures (TRC-\* set) with additional eBPF programs already in the existing normalizer shape (byte-identical offline). Scope to signatures that map to MITRE techniques not already covered by Falco (avoid duplicate detections → correlator dedup).

### 3d. osquery multi-query

- From single-pack → a multi-query pack set (the catalogue names IR + vuln-mgmt packs). Extend the runner to load N packs; offline fixture-driven.

### 3e. Active anomaly (heuristic, NOT ML)

- Build **on the existing passive baseline** (`observer.py`): compare live process/file/connection observations to the persisted baseline → emit a heuristic-anomaly finding on deviation (new binary / unexpected listening port / new outbound peer). **Heuristic only** (statistical/threshold), ML deferred to v0.5 (directive P-3).
- **Open decision (operator):** heuristic thresholds (conservative default to avoid FP storms) — recommend conservative + tunable.

### 3f. Runtime inventory discovery + `kg_writer.py` (Option X)

- New `kg_writer.py` (mirrors the 6 existing agents' pattern: injected `SemanticStore`, single-tenant opt-in, no-op when `None`).
- **Per the inventory catalogue (#711) C.x Runtime section:** owns Process/File-integrity/Container-lifecycle event nodes (L6) + **L5-runtime property sets** (filesystem state, running packages, open ports, OS users, SSH keys, sudoers) **attached to existing host/pod nodes** (contributes, not owns the host node). Edges: `EXECUTED_ON`, `MODIFIED`, `EXHIBITED_BEHAVIOR`, `OPENED_PORT`.
- **Sensor dependency (catalogue "Option D"):** L5-runtime/L6 require a workload sensor. v0.4 ships the kg_writer + node schema + the cloud-API-reachable subset; the full sensor pipeline (Falco/Tracee/osquery deployed to workloads over local TLS) is the catalogue's **v1.5** item — **flag: confirm whether v0.4 includes sensor deployment or only the schema + offline/gated path.** Recommend: schema + gated path in v0.4; sensor deployment stays v1.5 (scope discipline, Layer 34).

---

## 4. Sub-PR breakdown (team plan; self-merge cascade unless noted)

1. **PR1** — `kg_writer.py` + runtime inventory node schema (L6 events + L5-runtime property sets) + SemanticStore wiring (no-op when store None; offline byte-identical).
2. **PR2** — FIM module + `File integrity event (L6)` + Falco file-write rules.
3. **PR3** — Falco rule-pack expansion (MITRE-mapped; sourced).
4. **PR4** — Tracee depth (additional signatures; correlator dedup).
5. **PR5** — osquery multi-query pack loading.
6. **PR6** — heuristic active anomaly on the passive baseline.
7. **PR7** — cycle verification + coverage doc + `kg_writer` e2e (gated live lane).

---

## 5. Substrate, invariants, gates

- **Substrate seal EMPTY** — `kg_writer` writes via the existing charter `SemanticStore` (per-agent ownership; no shared-writer/schema change). New nodes are runtime-agent-local additive shapes. Trigger #29 (shared-writer contention) watched at the kg_writer interface.
- **Live behind `NEXUS_LIVE_RUNTIME_*`** gates (Falco/Tracee); offline default byte-identical; sensor deployment gated (Option D).
- **Per-PR vs self-merge:** per §10 of the directive — D.3 depth = **self-merge cascade**; any new shared kg interface touch → per-PR review.
- **Layer 27** before any review signal: rebase → CI green → THEN signal.

---

## 6. Coverage + honest limitations

- Coverage `[estimate]` (per E-1/E-2 discipline; not instrumented). D.3 depth contributes runtime detection breadth + the runtime slice of the fleet inventory graph.
- **Honest:** active anomaly is heuristic (ML → v0.5); FIM watched-path set is bounded; L5-runtime/L6 fullness depends on the sensor (Option D, v1.5) — without it, v0.4 realizes the cloud-API-reachable subset + the schema. The realized runtime-inventory lift lands when the sensor runs (operator-run, mirrors A-1 live-loop caveat).

---

## 7. Open decisions to surface (operator)

1. **Sensor scope in v0.4** — schema + gated path only (rec), or include sensor deployment (pulls v1.5 forward)?
2. **FIM watched-path default** — OS-critical only (rec) vs per-tenant configurable at launch.
3. **Anomaly thresholds** — conservative + tunable (rec).
4. (Carried) R-1 numbering — catalogue v1.1 reconciles C.x Runtime ↔ D.3.

---

## 8. Note on this as the template

This is the calibration template for Stage 1.2-1.6. If the operator wants a different depth/section-set for brainstorms, adjust here before the rest are written. The same shape (recon-verified current state → per-component options+rec → sub-PR breakdown → substrate/gates → honest coverage → open decisions) applies to 1.2 (D.5 data + DB inventory), 1.3 (D.6 K8s CIS v2.0 + inventory), 1.4 (D.4 Zeek-conn kg_writer + topology), 1.5 (D.2 per-role eval depth), 1.6 (Track B AppSec + SCM inventory). **HOLD: no execution PRs until brainstorms approved.**
