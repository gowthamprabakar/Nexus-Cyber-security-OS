# v0.3 / Phase D — Track A Workstream A-1 launch (live-loop wiring) — 2026-06-14

> **Status:** Workstream launch / scope-of-record. Track A discipline = self-merge cascade;
> substrate seal EMPTY throughout A-1. This doc opens A-1 per the v0.3 directive's
> acknowledgment protocol ("Open A-1 launch PR ... with operator decision on Q-A-1").

## 1. What A-1 is

The sequenced **foundation** of Track A: wire each detect agent's already-built live reader into
its production `run()` / CLI path so the OCSF emitter is driven by **live** data instead of
offline/stub/fixture data. Per the directive: **"No new capability — wires existing infrastructure
into run() loop."** Depth workstreams A-2…A-6 then build on an OPERATING fleet, not an
INFRASTRUCTURE one (mirror of Phase C SS1→SS2 sequencing).

## 2. Q-A-1 resolution (operator-decided 2026-06-14)

The directive estimated "~12 agents." A ground-truth sweep of every agent's `run()` path, live-reader
modules, and OCSF emitter (read-only, against main `9900c37`) found the **verified gap = 9
OCSF-detector agents**, not 12. The audit's "~12" is a looser superset that also counted the 6
continuous schedulers and the LLM agents; restricting to the precise definition — _a live reader is
built but `run()` still emits OCSF from offline data_ — yields 9.

One of the 9, **multi-cloud-posture**, has **no live Azure/GCP findings scanners at all** (only
scope-discovery helpers exist) — wiring it is **net-new capability**, which violates A-1's "no new
capability" rule.

**Operator decision (Q-A-1): "8 wiring + reclassify MCP."**

- **A-1 work-list = the 8 agents** whose live readers are built and only need run()-wiring.
- **multi-cloud-posture's net-new Azure/GCP findings scanners → reclassified to Track A-3**
  (CSPM rule breadth), where net-new scanner build belongs. A-1 does not touch it.

This keeps A-1 strictly a wiring workstream, faithful to the directive's definition. The audit's
"~12" vs verified "9 (→8 in A-1)" delta is **definitional, not a code error** (trigger #31 closed by
this record).

## 3. The A-1 work-list (8 agents)

Two FULL gaps (run() emits entirely from offline; built live readers wired to nothing) and six
PARTIAL gaps (one live source already wired in Phase C SS4 / v0.2; sibling readers built-but-unwired).

| #   | agent          | gap     | OCSF      | wire INTO run()/cli — built reader(s)                                                   | evidence (built-but-unwired)                                                     |
| --- | -------------- | ------- | --------- | --------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------- |
| 1   | data-security  | PARTIAL | 2003      | `azure_blob_inventory.py` + `gcs_inventory.py` (S3 already live)                        | `agent.py:88-89` "client-injected + ungoverned until SDKs land (v0.3)"           |
| 2   | network-threat | PARTIAL | 2004      | `suricata_realtime.py` + `zeek_realtime.py` (VPC-flow already live)                     | `agent.py:82-84` realtime subscribers NOT registered                             |
| 3   | k8s-posture    | PARTIAL | 2003      | `kube_bench_live.py` + `polaris_live.py` (workload reader already live)                 | live exec readers referenced by nothing                                          |
| 4   | identity       | PARTIAL | 2004      | `azure_ad.py` + `federation.py` / `live_lane_azure.py` (AWS IAM already live)           | only `normalizer.py:355` capability + tests reference them                       |
| 5   | synthesis      | PARTIAL | 2004      | `fleet_workspace_reader.py` + `fleet_enumeration.py` (3 pinned workspaces already live) | v0.2 fleet reader (source scope 3→12) not imported by agent/cli                  |
| 6   | vulnerability  | PARTIAL | 2002      | `registry_pipeline.py` enumerate→scan (Trivy on `--image` already live)                 | CI-proven `test_registry_pipeline_wired.py`; not reachable from `cli.py run_cmd` |
| 7   | runtime-threat | FULL    | 2004      | `falco_realtime.py` + `tracee_realtime.py` / `live_lane.py`                             | `agent.py:199,205` run() reads offline JSONL only                                |
| 8   | threat-intel   | FULL    | 2002/2004 | live `nvd_live.py` / `kev_live.py` / `mitre_live.py` (registered)                       | `agent.py:267-281` run() ingest calls offline snapshot readers only              |

## 4. Ambiguous-case resolutions (from the sweep §E)

- **vulnerability (#6):** the live-registry→OCSF pipeline is built + CI-proven but unreachable from
  `cli.py run_cmd` (which only takes `--image`). **A-1 = wire `registry_pipeline.*_scan_to_findings`
  into the production CLI/run() entrypoint** so live registry enumeration drives OCSF. Counts as
  wiring (existing infra), not net-new.
- **synthesis (#5):** `run()` already emits OCSF over real evidence (3 workspaces + LLM). **A-1 =
  wire the v0.2 `fleet_workspace_reader` / `fleet_enumeration` so the source scope broadens 3→12**
  (existing-infra wiring). curiosity is NOT in scope — its `read_sibling_state` is already
  source-agnostic / fleet-wide (no gap).
- **compliance:** **NOT in A-1.** It has no cloud/cluster live reader (it correlates sibling
  workspaces — its wired path). Its multi-cloud CIS breadth (`cis_{azure,gcp,k8s}_benchmark.py`,
  only AWS loaded at `agent.py:143`) is a **breadth** task for **Track A-3**, not a live-loop gap.

## 5. Ordering (prove the pattern on PARTIALs first)

Wire the six PARTIAL agents first — each already has one live source wired in-repo, so the new
wiring copies an existing, proven pattern (lowest risk). Then the two FULL gaps.

```
A-1.1 data-security    (S3 pattern → Azure Blob + GCS)
A-1.2 network-threat   (VPC pattern → Suricata + Zeek realtime)
A-1.3 k8s-posture      (workload pattern → kube-bench + Polaris live exec)
A-1.4 identity         (AWS IAM pattern → Azure AD + federation)
A-1.5 synthesis        (3-workspace pattern → fleet reader 3→12)
A-1.6 vulnerability    (Trivy pattern → registry pipeline into cli/run)
A-1.7 runtime-threat   (FULL → falco + tracee realtime)
A-1.8 threat-intel     (FULL → live NVD/KEV/MITRE ingest)
```

## 6. Per-PR contract (every A-1 wiring PR)

1. Wire the built live reader's output into the agent's `run()` / CLI OCSF path, behind the
   agent's existing `NEXUS_LIVE_*` gate (live calls cost money — never default-on in CI).
2. **Byte-identical OCSF guarantee:** the offline/stub path stays the default; with the live gate
   OFF, OCSF emission is byte-identical to pre-PR (regression-guarded).
3. Live path exercised only under `workflow_dispatch` / the agent's live lane (not default CI).
4. Agent eval suite green; repo suite green; substrate seal EMPTY (`git diff origin/main --
packages/shared packages/charter` empty).
5. Per-agent node-type declaration carried (Phase 0 design-awareness; lightweight checklist).

## 7. A-1 completion criteria

```
✅ 8 agents wired live→OCSF (gate-guarded; offline default byte-identical)
✅ Each agent's live lane exercised under workflow_dispatch
✅ multi-cloud-posture net-new scanners handed to Track A-3 (not built here)
✅ All 8 agents' eval suites green; repo suite green
✅ Substrate seal EMPTY throughout
✅ Per-agent node-type declarations complete (8 checklists)
✅ A-1 verification record + Wiz-weighted recompute (target +5–8pp realized)
```

## 8. References

- v0.3 / Phase D directive (operator, 2026-06-14) — Track A §A-1; trigger #31.
- Phase D readiness audit — `phase-d-readiness-audit-2026-06-14.md` §Dimension 2/4.
- Phase C completion — `phase-c-completion-2026-06-14.md` §SS1/SS4 (what was registered vs wired).
- A-1 ground-truth sweep (2026-06-14) — verified 9-gap enumeration this doc records.

---

## 9. Mid-cascade addendum (2026-06-14) — recon finding + 4 reclassifications

> **Why this addendum exists.** After §3's 8-agent work-list was set, a 6-agent
> parallel recon read each remaining agent's actual run()/reader/emitter wiring. It
> found the directive's "no new capability — wire existing infrastructure" premise
> holds for **only 2** of the agents. The operator's **"Split"** decision
> (2026-06-14) keeps A-1 as a wiring workstream and reclassifies the net-new work to
> the depth tracks — extending the §2 MCP→A-3 and data-sec→A-6 precedent. This
> addendum is the scope-of-record for that split.

### 9.1 Recon verdict per agent

| agent                   | verdict                    | why                                                                                                                                                                      |
| ----------------------- | -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| threat-intel            | ✅ pure wiring (DONE #653) | live readers return offline record shapes; `_ingest` live route                                                                                                          |
| vulnerability           | ✅ pure wiring (DONE #654) | registry pipeline converges on `trivy_to_findings`→2002                                                                                                                  |
| identity (federation)   | ✅ wiring (DONE #655)      | `federation_to_findings` 2nd emitter already exists; additive                                                                                                            |
| network-threat          | ⚠️ needs net-new           | Suricata/Zeek are infinite push streams → need a bounded-drain adapter; Zeek-conn needs a missing `ZeekConn→FlowRecord` adapter                                          |
| runtime-threat          | ⚠️ needs net-new           | falco/tracee infinite push streams → bounded-drain adapter; no production gRPC/pipe client exists                                                                        |
| k8s-posture             | ⚠️ net-new capability      | live kube-bench/Polaris readers are sync class APIs + **no production runner exists** (only test fakes)                                                                  |
| identity (Azure-AD ids) | ⚠️ net-new                 | `AzureAdListing` is shape-disjoint from `IdentityListing`, no emit path                                                                                                  |
| synthesis               | ⚠️ net-new + risk          | fleet reader terminates in a dict the narrator can't consume → needs `FleetFindings→ContextBundle` adapter + Q6 matched-text scrub for 9 agents (safety-regression risk) |

### 9.2 A-1 final scope (5 agents)

1. ✅ threat-intel (#653) · 2. ✅ vulnerability (#654) · 3. ✅ identity-federation (#655)
   · 4. network-threat (Suricata + Zeek-DNS, bounded-drain) · 5. runtime-threat (falco +
   tracee, bounded-drain). Agents 4–5 consume a shared **bounded-drain infrastructure**
   (operator-reviewed, abstraction-only) before their wiring PRs cascade.

### 9.3 The 4 reclassifications (Split decision)

| reclassified work                           | from | to                                 | reason                                              |
| ------------------------------------------- | ---- | ---------------------------------- | --------------------------------------------------- |
| k8s-posture live kube-bench/Polaris runners | A-1  | **A-3** (CSPM breadth)             | production runner is net-new capability, not wiring |
| synthesis fleet source 3→12 (+ Q6 scrub)    | A-1  | **dedicated depth PR**             | needs adapter + Q6 safety replication for 9 agents  |
| Azure-AD identity enumeration → findings    | A-1  | **A-4** (identity effective-perms) | shape-disjoint, net-new detection logic             |
| Zeek-conn → FlowRecord adapter              | A-1  | **follow-up**                      | adapter does not exist; Zeek-DNS handled in A-1.4   |

### 9.4 Bounded-drain infrastructure (the A-1.4/A-1.5 prerequisite)

Suricata/Zeek/falco/tracee subscribers consume infinite push streams and return
`StreamStats`, not records — a single-shot `run()` would hang. A shared, agent-agnostic
bounded-drain abstraction (operator-reviewed, no wiring) lands first; network-threat and
runtime-threat then wire to it. Existing per-sensor normalizers already produce
byte-identical offline shapes, so downstream stays source-agnostic. CI exercises injected
fake streams; real sockets stay gated behind the per-sensor `NEXUS_LIVE_*` lanes.
