# Attack-Path Roadmap to the North Star

**Living doc — the macro map. Created 2026-06-22.** Every piece of work should ladder to this.

## North Star (one sentence)

> A customer connects a cloud account and, within minutes, sees their top ~10 **real attack paths** — prioritized, explained, with a fix — at a **measured** detection coverage that credibly reads as "half of Wiz, on the things that matter."

## The strategy in one idea

**Organize by attack path, not by agent.** The north star is ~10 attack-path archetypes. Each is fed by a small, overlapping set of agents. So the same program (a) verifies the agents that matter, (b) builds the product, (c) escapes the limbo — all at once.

- **Phase 1 (now):** ~10 hardcoded toxic-combination _patterns_. Fast to value. Additive — no ceiling, no rewrite.
- **Phase 2 (Wiz-class):** a _generic_ path engine — the graph discovers arbitrary exposure→access→impact chains. The typed graph + `kg_query` 3-hop BFS already seeds this. Patterns → engine is an evolution.

## The Discipline (how we escape the limbo)

1. **Done = I watched it work.** An agent/path is **REAL** only when its detection runs against a realistic source (moto / LocalStack / kind / real LLM) in a **CI test that actually executes** — not docs, not fixtures, not hand-fakes, not operator-only-never-run.
2. **Three honest grades, always:** **REAL** (CI-verified against realistic reality) · **WIRED** (code exists, fake/gate-tested, real path never verified) · **CLAIMED** (doc says so, code/reality disagrees — e.g. the LTREE bug). Deferred agents get an honest **operator-verified** label — never a fake REAL.
3. **The anti-limbo rule:** when we hit a deeper problem, ask _"does this block the next attack path or the north star?"_ No → write it in the Parked ledger, keep moving. Yes → in scope.

## The ~10 Attack-Path Archetypes (ranked, with feeders + status)

> Status: ✅ REAL (CI-verified) · 🟡 feeders partly REAL · ⬜ not started. Feeders in **bold** are already REAL-verified.

| #   | Attack path                                                                          | Feeder agents                                                         | Status                                                                                                                                      |
| --- | ------------------------------------------------------------------------------------ | --------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | Public resource + sensitive data + over-permissioned identity                        | **data-security**, **identity**                                       | ✅ path + feeders REAL (moto, 2026-06-22)                                                                                                   |
| 2   | Internet-exposed workload + critical/exploitable vulnerability (KEV)                 | **vulnerability** (real trivy), **cloud-posture** (ECS exposure)      | ✅ REAL (2026-06-22) — `find_internet_exposed_vulnerable_workload` (mechanism-② bridge)                                                     |
| 3   | Public resource + exposed secret/credential                                          | **data-security** (secrets)                                           | ✅ REAL (moto-proven, 2026-06-22) — `find_public_secret_exposure`                                                                           |
| 4   | Over-permissioned identity → fine-grained access → sensitive resource                | **identity** (concrete policy Resources), **data-security**           | ✅ REAL (moto-CI, 2026-06-22) — `find_fine_grained_data_exposure`                                                                           |
| 5   | Internet-exposed + vulnerable + high-privilege + sensitive (the "crown jewel" 4-hop) | **vulnerability**, **identity**, **data-security**, **cloud-posture** | ✅ REAL (2026-06-22) — `find_crown_jewel_exposure` (assembles 2 + 4)                                                                        |
| 6   | Privileged K8s workload running a vulnerable image                                   | **k8s-posture**, **vulnerability**                                    | ✅ REAL (kind + trivy, 2026-06-26) — `find_privileged_vulnerable_workload`                                                                  |
| 7   | Public + unencrypted storage + sensitive data                                        | **data-security**                                                     | ✅ REAL (moto-CI, 2026-06-22) — `find_public_unencrypted_exposure`                                                                          |
| 8   | External/cross-account trust + over-permission → sensitive resource                  | **identity** (offline trust-policy), **data-security**                | ✅ REAL (moto-CI, 2026-06-22) — `find_external_trust_exposure`                                                                              |
| 9   | Vulnerable container image (registry) deployed to internet-facing workload           | vulnerability (registry), k8s-posture/network                         | ⤳ subsumed by path 2 (same `RUNS_IMAGE→VULNERABLE_TO→exposed` chain; registry-scan source is operator-verified — trivy can't scan moto-ECR) |
| 10  | Exposed AI/ML service + sensitive training data                                      | **aispm**, **data-security**                                          | ✅ REAL (moto, 2026-06-26) — `find_exposed_ai_with_sensitive_data`                                                                          |

**Core feeder set (covers ~all paths): data-security ✅, identity ✅ (basic / depth pending), vulnerability ✅ (real trivy, trivy-gated), cloud-posture ✅ (ECS exposure, moto), network-threat, k8s-posture, compliance, aispm — ~8 agents, heavy reuse. 4 of 8 now REAL-verified.**

**Mechanism-② bridge proven (ADR-023):** path 2 closed the first cross-agent join where the two agents do NOT share a canonical key — vulnerability keys images by ref, the spine keys workloads by ARN. `cloud-posture.record_workloads` writes `RUNS_IMAGE` onto the SAME image-ref node vulnerability writes CVEs onto, so a graph walk crosses the gap. This is the template for the remaining misfit joins (network IP→`OWNED_BY`, runtime host→`RUNS_ON`).

## Verification Order (value × feeder-reuse)

Prioritize paths that are high-value AND unlock the most reuse:

1. **Path 1 — DONE.** Template proven (data-security + identity REAL via moto).
2. **Path 2 — DONE.** vulnerability REAL (real `trivy fs`) + cloud-posture ECS exposure REAL (moto) + the **mechanism-② `RUNS_IMAGE` bridge** (ADR-023) joining vuln-images↔workloads. Unlocks 5, 9.
3. **Path 4 — DONE.** identity depth: `_fine_grained_grants` extracts concrete-Resource S3 access offline → fine-grained `HAS_ACCESS_TO` (the non-admin least-privilege violation path 1's admin-only seed misses). moto-REAL.
4. **Path 6** → stand up **kind**, verify **k8s-posture** REAL. Unlocks 6, 9.
5. **Paths 3, 7, 8 — DONE** (reuse verified feeders + one new pattern each). **Path 10** → aispm feeder.
6. **Path 5 — DONE.** The crown jewel: assembled paths 2 + 4 on one workload pivot (exposed + vulnerable + `ASSUMES` a role that reaches sensitive data). Added the workload→task-role `ASSUMES` bridge. **7 of 10 paths REAL (1,2,3,4,5,7,8).** Remaining: **9** (registry image→workload, reuses `RUNS_IMAGE`), **6** (kind + k8s-posture), **10** (aispm).

Each path = (verify its new feeder REAL in CI) + (wire the correlation pattern) + (ship it, demoable). ~1 shippable path/week after the first.

## The product surface — `AttackPathRanker` (the north star, in code)

`meta_harness.attack_paths.AttackPathRanker` is the deliverable: it runs all seven REAL
detectors over a tenant's graph and returns ONE worst-first ranked `AttackPath` list
(type + severity + human title + entities) — "connect an account → see your top attack
paths, prioritized." Severity is the triage judgment: crown_jewel 95 > public_secret 90 >
internet_exposed_vulnerable 80 > public_unencrypted 75 > external_trust 70 >
fine_grained_data 60. Pure aggregation over already-REAL detectors; hermetic. This is what a
demo/API renders. **9 of 10 archetypes REAL feed it (1,2,3,4,5,6,7,8,10); path 9 subsumed by
path 2 → all 10 covered.** Feeders REAL: data-security, identity, vulnerability, cloud-posture,
k8s-posture, aispm (6/8). Severity order: crown_jewel 95 > public_secret 90 >
internet_exposed_vulnerable 80 > privileged_vulnerable 78 > public_unencrypted 75 >
external_trust 70 > exposed_ai_sensitive_data 68 > fine_grained_data 60.

## Measurement (so "50-60% of Wiz" is a fact, not a feeling)

The L2 capability banks (`packages/integration/src/fleet_testkit/tests/banks/path{N}_*/`) score each
path's precision/recall against ground-truth fixtures, driven by `fleet_testkit.bank_runner`. **All 8
distinct detectors are banked** (path 1 subsumed by 4); the **fleet scorecard** (`test_fleet_scorecard.py`)
runs them all and prints one number. As of 2026-06-26: **8 paths, 29 cases, 23 TP / 0 FP / 0 FN →
fleet precision 1.000 / recall 1.000** (paths 2/5 trivy-gated, 6 kind+trivy-gated, run where the tools
exist). The score is the regression floor, not a coverage claim — it is 1.000 **on the bank**, which is
why the gaps below matter.

### Known detection gaps vs Wiz (the complete curated list — honest counter-evidence)

The banks measure what we catch; this is the curated ledger of what we MISS — so the scorecard's
1.000 is read in context (it is 1.000 _on the bank_). **`[test]`** = a characterization test in
`test_known_limitations.py` asserts the current miss (closing it fails the test on purpose, forcing
an update here); **`[code]`** = verified by reading the implementation; **`[config]`/`[scope]`** =
a tuning/coverage-boundary fact. 13 gaps across 5 categories, all verified 2026-06-26.

**A. Data exposure — what counts as "public" + what the classifier reads (data-security):**

1. ✅ **FIXED 2026-06-27** — **Bucket-policy public** `[test]` ⭐ — `kg_writer._bucket_is_public` now
   evaluates the (already-fetched) bucket policy for a wildcard-principal `Allow`, neutralized when
   Block-Public-Access blocks/restricts public policies. Was: ACL-only, so the dominant modern public
   path (AWS disables ACLs by default) was invisible. Test flipped to assert-detect + a PAB precision test.
2. ✅ **FIXED 2026-06-27** — **Object-level ACL public** `[test]` — `S3LiveObjectSampler` reads each
   object's ACL (`get_object_acl` → AllUsers/AuthenticatedUsers) → `ObjectSample.is_public`; the agent +
   harness thread the per-bucket public-object set into `kg_writer.record`, OR-ing it into `is_public`.
   Wired through the real agent path + a precision test (private object stays dark).
3. ✅ **FIXED 2026-06-27** — **Compressed / encoded blobs** `[test]` — `classify_bytes` decodes gzip +
   base64 before classifying (plain → gzip → base64, first specific match), wired into the real agent
   `_classify` + the harness. Precision held (specific patterns, no entropy → noise doesn't match). Was:
   decoded-UTF-8 only.
4. ✅ **FIXED 2026-06-27** — **AWS secret access keys** `[test]` — added `_AWS_SECRET_KEY_RE` (the
   `secret access key` label, any separator/camelCase, + 40-char base64), classified as `AWS_ACCESS_KEY`.
   Now catches `aws_secret_access_key = <40>` / `SecretAccessKey: <40>`; a bare 40-char string is still
   not flagged (label required). Was: only the AKIA _ID_ had a pattern; the secret key slipped through.

**B. Identity — what grants/trust we resolve (identity):**

5. ✅ **FIXED 2026-06-27** — **Group-inherited IAM access** `[test]` — `_fine_grained_grants` now follows
   a user's `group_memberships` and resolves the group's attached + inline policies, so a group-only user
   is caught (paths 4/8). Was: attached + inline on the principal only.
6. ✅ **FIXED 2026-06-27** — **Federated (OIDC/SAML) external trust** `[test]` — `_externally_trusted_arns`
   now also flags any `Allow` statement with `Principal.Federated` (external OIDC/SAML provider, e.g.
   GitHub Actions OIDC) alongside cross-account trust. Service principals stay ignored.
7. ✅ **FIXED 2026-06-27** — **Resource-based access grants** `[test]` — data-security records the
   bucket policy's named (non-wildcard) S3-read principals as a `policy_readers` property on its own
   bucket node (clean ownership — no IDENTITY/edge crossing), and `kg_query.find_resource_based_data_exposure`
   joins them to the bucket's sensitive data via `CONTAINS` (works for private-but-shared buckets, not
   just public). Wired into `AttackPathRanker` (sev 62) + a hermetic bank (3 cases) in the fleet
   scorecard. Was: IAM-listing-only, so policy-granted access was invisible.
8. ✅ **FIXED 2026-06-27 (permission boundary; SCP/Condition deferred)** `[test]` — the IAM reader fetches
   the boundary (`get_role`/`get_user` → `PermissionsBoundaryArn`) into `IamRole/IamUser`;
   `_synthesize_admin_grants` + `_fine_grained_grants` suppress a grant only when a **resolvable** boundary
   unambiguously disallows it. **Conservative — no boundary / unresolvable (AWS-managed) → keep the
   finding**, so the precision fix can't introduce false negatives (three guard tests). **SCPs (Organizations
   API) + statement Conditions remain a further phase.**

**C. Compute & exposure (cloud-posture):**

9. ✅ **FIXED 2026-06-27** — **EC2 / non-ECS compute not inventoried** `[test]` — new
   `cloud_posture.tools.aws_ec2.read_ec2_workloads(ec2, iam)`: `describe_instances` → public IP **and** a
   `0.0.0.0/0` SG → `is_public`; resolves the instance-profile → IAM role (the EC2 ASSUMES bridge).
   `record_ec2_workloads` writes `CLOUD_RESOURCE{kind=ec2-instance,is_public}` + `ASSUMES` → role.
   **Honest limit: EC2 runs an AMI/packages, not a container image — the `RUNS_IMAGE`→CVE join needs a
   separate host-vuln model (trivy `rootfs`/`vm`); exposure is inventoried, the vuln join is its own slice.**
10. ✅ **FIXED 2026-06-27** — **Load-balancer / no-public-IP exposure** `[test]` — new
    `cloud_posture.tools.aws_elbv2.internet_facing_target_groups(elbv2)` walks internet-facing LBs →
    listeners → target groups; `read_ecs_workloads(..., lb_exposed_target_groups=)` flags a service whose
    `loadBalancers` reference an internet-facing target group as `is_public=True` (OR-ed with the SG
    check). Walks LB→listeners forward (moto leaves `TG.LoadBalancerArns` empty). Precision held.

**D. Vulnerability (vulnerability):**

11. ✅ **RESOLVED 2026-06-27 (deliberate tunable, not a defect)** — **Severity floor** `[config]` — trivy
    scans **HIGH + CRITICAL** by default (`DEFAULT_SEVERITY`), but `trivy_fs_scan`/`trivy_image_scan`
    already accept a `severity` list — including MEDIUM/LOW is a per-scan opt-in. The default is a
    deliberate noise-control choice (flooding every scan with MEDIUM CVEs hurts signal); it is tunable,
    not missing. No code change — documented as a knob.
12. ✅ **FIXED 2026-06-27** — **KEV as a first-class signal** `[test]` — `record_scan_results` takes an
    injectable `kev_cve_ids` set and flags matching CVE nodes `kev=True` (a prioritization signal). The
    catalog is injected (the live CISA `kev.py` feed is the agent's online path; tests/banks pass a known
    set → hermetic). Firing stays severity-based (the deliberate recall floor, #11); KEV is now surfaced
    for ranking rather than ignored.

**E. Multi-cloud (scope):**

13. **Azure / GCP attack-path coverage — STORAGE PARITY NOW CI-REAL** `[scope]` — _was:_ every bank
    drove AWS moto only and ARN-keyed joins wouldn't resolve non-AWS keys. **DONE (slice 1, commit
    b5894dd):** (1) canonical-key scheme extended — `charter.canonical.azure_blob_uri` / `gcs_uri`
    (ADR-023); (2) `kg_writer.record_data_sources` writes the SAME `CLOUD_RESOURCE{is_public}` +
    `EXPOSES_DATA` vocabulary for any `DataSource`, so the cloud-agnostic `kg_query` detectors fire
    unchanged; (3) CI-REAL substrate via the readers' own injectable Protocols (`fleet_testkit.azure_blob`
    / `gcs_blob` — no `moto` needed) driving the REAL readers + classifier + writer; **6 e2e tests prove
    path-3 (public-secret) + path-7 (public-unencrypted) light up on Azure Blob AND GCS, private-is-dark.**
    **DONE (slice 2 — access leg, commit 96a0363):** cross-cloud identity for **path 4**. `record_access`
    was already cloud-agnostic; only grant _resolution_ was AWS-only. New `identity.tools.azure_rbac`
    (`blob_read_grants` — container-scoped Storage-Blob-Data-\* assignments → `(principal, azure_blob_uri)`;
    broad account/sub scopes + control-plane roles skipped = fine-grained by design) +
    `identity.tools.gcp_iam` (`storage_read_grants` — object-read bindings → `(member, gcs_uri)`; public
    members dropped). `fleet_testkit.identity_access` drives the REAL resolvers + REAL `record_access` via
    injectable clients. **4 e2e (Azure/GCP path-4 fires + scoped-elsewhere dark) + 8 resolver units.**
    **DONE (slice 3 — external trust, commit 797f001):** cross-cloud identity for **path 8**.
    `azure_ad.AzureAdUser` gained `user_type`/`is_guest` (Graph select fetches `userType` — REAL B2B
    guest signal); `azure_rbac.external_trust_grants` keeps blob-read grants held by guest principals;
    `gcp_iam.external_trust_grants` keeps object-read grants held by foreign members (outside
    `org_domain`) or `allAuthenticatedUsers` (allUsers/project-SA excluded). Drivers call
    `record_external_trust` + `record_access`. **4 e2e (Azure guest / GCP foreign fire, member/internal
    dark) + 3 resolver units + guest-parse test.** Cross-cloud identity (paths 4 + 8) COMPLETE.
    **REMAINING (own days, the last #13 sub-item):** non-storage Azure/GCP resource types — compute
    (Azure VM / GCP GCE for paths 2/5/6 exposure+workload legs) and AI (Azure OpenAI / Vertex for path
    10). Each needs a net-new posture reader + the `RUNS_IMAGE`/`ASSUMES`/`EXPOSES_MODEL` bridges built
    for AWS. Storage + identity legs already prove the engine is genuinely multi-cloud; compute/AI extend
    breadth, not the core mechanism.

_Add gaps here as probing finds them — this is the live coverage-limit ledger._

## Detection-gap fix status (2026-06-27)

**Fixed (12 of 13):** #1 bucket-policy-public, #2 object-ACL, #3 gzip/base64 decode, #4 AWS-secret-key,
#5 group-inherited access, #6 federated trust, #7 resource-based access, #8 permission-boundary cap
(SCP/Condition deferred), #9 EC2 inventory (host-vuln join its own slice), #10 ELBv2/load-balancer
exposure, #11 severity-floor (tunable), #12 KEV flag. **#13 multi-cloud (in progress):** storage parity
slice DONE (commit b5894dd) — Azure Blob + GCS public+sensitive light up paths 3/7 CI-REAL, 6 e2e tests;
remaining sub-slices = cross-cloud identity (Azure AD / GCP IAM) for access-leg paths 4/8, non-storage
resource types. Every AWS fix flipped its characterization test assert-miss → assert-detect with a
precision guard; full repo 7784 pass (+6 multi-cloud e2e).

## Parked (does NOT block the north star — honest debt, deferred)

- DB-level tenant RLS hardening (store-layer GUC + FORCE RLS) — app-level isolation holds; revisit before real customer data. [see truth-audit doc]
- Azure/GCP-only detection paths — likely **operator-verified**, not CI-REAL (mocks too weak). Labeled honestly.
- Auto-driven continuous loop; supervisor `del semantic_store` placeholder; pgvector ANN; effective-perms simulator (live-AWS only).
- Access-Analyzer external-access (online API, not moto-drivable) — **operator-verified only**. Path 8 ships the **offline trust-policy** variant (`_externally_trusted_arns`, CI-REAL); the Access-Analyzer cross-resource findings are a superset that needs live AWS to verify.

## Honest ceiling

~10 patterns ≈ pitchable demo (~6–10 wks). More patterns = additive, indefinite. Generic path engine = the true Wiz-class match (longer arc) — but the architecture supports it with no rewrite. Slow and steady, no ceiling that forces starting over.
