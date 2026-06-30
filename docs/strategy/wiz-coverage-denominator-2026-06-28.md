# Detection Coverage vs Wiz — the denominator (making "~55%" a real number)

**Date:** 2026-06-28 (multi-cloud correction 2026-06-29).

> ⚠️ **The "~91%" headline is AWS. It is NOT a blanket CNAPP number — that framing was misleading.**
> The fleet is heavily AWS-skewed (cloud-posture: 8 AWS readers vs 1 Azure / 1 GCP; data-security:
> 7/1/1). The recent 73→91% jump was ~76% AWS-only work. Honest triple-track:
>
> | Cloud     | Attack-path category coverage | Note                                                                                                                                                 |
> | --------- | ----------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
> | **AWS**   | **~91%**                      | the number below; deep + recently expanded                                                                                                           |
> | **Azure** | **~55%**                      | only the cross-cloud-verified paths (storage 3/7, compute 2/5/6, AI 10, identity 4/8); KMS/RDS/privesc/lateral/host-vuln/secret-in-code are AWS-only |
> | **GCP**   | **~50%**                      | same as Azure, minus the Azure AD identity depth                                                                                                     |
>
> 12 of 20 detectors are AWS-only; 8 have multi-cloud e2e. The per-edge build rule (graph-model
> scope map) now requires every new edge to declare its per-cloud scope explicitly, so this gap
> stops widening. The table below is the **AWS** denominator.

**Turns the _felt_ "~50-60% of Wiz" into an explicit, defensible fraction.**

## Two different numbers (we were conflating them)

- **Quality** = precision/recall on our own bank cases. The fleet scorecard measures this (1.000). "Do our detectors correctly classify what they claim to?" — yes.
- **Coverage** = fraction of the real cloud-attack-path space we detect at all. **This is the "% of Wiz" number, and we never had it** — P/R against our own banks says nothing about what we _don't_ detect.

This doc defines the coverage denominator. Honest caveat: the denominator is the **public CNAPP attack-path category set** (what Wiz/Orca/Prisma market), **not** Wiz's internal rule count. It's a breadth proxy, stated as such.

## The denominator — cloud attack-path categories

| #   | Category                                                          | Covered? | By                                          |
| --- | ----------------------------------------------------------------- | -------- | ------------------------------------------- |
| 1   | Public storage + sensitive data                                   | ✅       | public_unencrypted (7)                      |
| 2   | Public resource + exposed secret/credential                       | ✅       | public_secret (3)                           |
| 3   | Internet-exposed workload + vulnerability                         | ✅       | internet_exposed_vulnerable (2)             |
| 4   | Privileged K8s workload + vulnerability                           | ✅       | privileged_vulnerable (6)                   |
| 5   | Over-permissioned identity → sensitive data                       | ✅       | fine_grained_data (4)                       |
| 6   | External / cross-account trust → data                             | ✅       | external_trust (8)                          |
| 7   | Resource-policy (bucket-policy) data exposure                     | ✅       | resource_based_data (#7)                    |
| 8   | Exposed AI/ML service + sensitive training data                   | ✅       | exposed_ai_sensitive_data (10)              |
| 9   | Crown jewel (exposed+vuln+privilege+data, composite)              | ✅       | crown_jewel (5)                             |
| 10  | Active C2 / communication with known-malicious IP                 | ✅       | malicious_destination                       |
| 11  | Active runtime exploit on a vulnerable workload                   | ✅       | runtime_exploit_vulnerable                  |
| 12  | Code-to-cloud: IaC misconfig deployed                             | ✅       | iac_misconfig_deployed                      |
| 13  | Identity privilege-escalation chain (assume a role to reach data) | ✅       | privilege_escalation (C1)                   |
| 14  | Network lateral movement (observed flow → vuln host)              | ✅       | lateral_movement (#14, observed flows)      |
| 15  | Host/OS vulnerability (VM/AMI, not container)                     | ✅       | internet_exposed_host_vulnerable (#15)      |
| 16  | Registry / supply-chain image vulnerability                       | 🟡       | subsumed by 3; registry scan operator-only  |
| 17  | Secret-in-code → live cloud credential                            | ✅       | leaked_credential (#17, access-key-id join) |
| 18  | SaaS over-scoped OAuth / SSO → cloud identity                     | ❌       | sspm not wired (A4, operator-only)          |
| 19  | Exposed managed database (RDS publicly accessible)                | ✅       | exposed_database (#19)                      |
| 20  | K8s RBAC privilege escalation                                     | ✅       | rbac_privilege_escalation (#20)             |
| 21  | KMS key / encryption exposure                                     | ✅       | exposed_kms_key (#21)                       |
| 22  | Compliance/posture drift as a risk                                | 🟡       | compliance not a path feeder                |

**Covered: 19 full + 2 partial of 22 = ~91%** (20/22 = 0.909). **Exceeds the ~50-60% North-Star band — with an explicit list, not a feel. C1 (privilege_escalation) #13; #20 RBAC privesc via cluster-admin-bound SA; #15 host/OS vuln via real `trivy` host scan keyed onto the public EC2 node; #14 lateral movement via OBSERVED flow (foothold→internal vuln host), NOT derived CAN_REACH reachability (Stage 3).**

## What the gaps tell us (the breadth backlog, ranked)

Highest-value uncovered (each ~1 named-archetype slice):

1. ~~#13 privilege-escalation chain~~ — ✅ DONE (C1, privilege_escalation archetype).
2. **#17 secret-in-code → cloud cred** — appsec + identity; the code-to-cloud differentiator's other half.
3. **#19 exposed managed database** — data-security DB sources (RDS/DynamoDB/BigQuery).
4. **#14 network lateral movement** — CAN_REACH reachability (needs the network reachability edge).
5. **#18 SaaS SSO** — operator-only (federation), defer.

Promote ~3 of these → ~68%; the rest are depth/operator work.

## Line items (the full plan this measures against)

- **A. Measurement (this doc + scorecard):** A1 expand banks 5→20-30 cases · A2 this denominator ✅ · A3 scorecard prints coverage N/22.
- **B. Live loop:** B1 one scan→correlate→rank command · B2 LocalStack full-loop e2e, timed · B3 continuous schedule (operator).
- **C. Breadth:** C1 promote candidates (#13) · C2 KMS/secret sinks (#21) · C3 SaaS/compliance (#18/#22) · C4 agent depth (#19, effective-perms).

**Verdict:** detection is **~91% coverage / 1.000 quality on what it covers**. "Complete per North Star" needs **B (live loop)** + a few **C** slices to push coverage toward 60-65%. The number is now real.
