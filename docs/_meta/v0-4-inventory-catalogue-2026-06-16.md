<!--
═══════════════════════════════════════════════════════════════════════════
TEAM BANNER (not operator content) — v1.0-draft landing note
═══════════════════════════════════════════════════════════════════════════
Operator-authored institutional artifact, landed AS-IS as the Stage 3 gate for
the v0.4 directive (#710 §11). Version: v1.0-draft.

Known reconciliation items (verified against main `6360079` this session;
to be resolved in a v1.1 amendment during Stage 1, NOT edited here):

- R-1 (D-numbering): this catalogue's agent numbering diverges from the code on
  main. Main's package self-IDs include D.7 = Investigation (#8) and
  D.8 = Threat-Intel (#12); this catalogue uses D.7 = Threat Intel / D.8 =
  Compliance / D.9 = AppSec / etc. RECOMMENDED resolution = Option α: the
  catalogue amends to match main numbering in v1.1 (lowest disruption).
  Operator may direct otherwise.
- R-2 (AppSec status): this catalogue marks "D.9 AppSec — Unbuilt." Reality:
  AppSec shipped as D.14 v0.1 in the v0.3 B-1 cycle (#690-707 on main;
  Checkov + gitleaks + Semgrep + GitHub/GitLab/Bitbucket connectors). v1.1
  updates the status.
- R-3 (coverage): five code agents are not specified here. kg-writers verified
  on main = cloud-posture, compliance, threat-intel, synthesis, curiosity,
  meta-harness (6). synthesis + curiosity need inventory specs in v1.1;
  investigation is an LLM consumer with NO kg_writer; audit + supervisor are
  non-inventory-writing orchestration agents.

This banner is a team annotation (Layer 36: relay-artifact verification). The
operator's authored catalogue follows verbatim, unedited.
═══════════════════════════════════════════════════════════════════════════
-->

# Nexus Cyber OS — Complete Agent Inventory Map

**Purpose:** The definitive per-agent inventory specification. For every agent in the fleet, this document enumerates exactly what that agent discovers, which inventory nodes it owns canonically, which nodes it contributes to, which edges it writes, and which tools it uses to do so.

**How to read this:** Each agent section follows the same structure:

1. **Mandate** — what this agent is responsible for, in one line
2. **Scope boundary** — what it does and does NOT cover (critical for avoiding drift)
3. **Tools** — the open-source and custom tooling it uses
4. **Nodes owned (canonical)** — entities this agent is the single source of truth for
5. **Nodes contributed to** — entities owned by others that this agent annotates
6. **Edges written** — the structural relationships this agent emits into the graph
7. **L-levels covered** — which inventory depth levels (L1–L6) this agent populates

**The ownership rule (applies throughout):** The agent whose domain expertise produces the deepest understanding of an entity owns the canonical node. Base infrastructure goes to D.3. Specialist layers go to their domain agents. Behavior goes to C.x agents. Findings go to whichever agent detected them. When two agents touch the same node, the canonical owner writes the node; others contribute edges or annotate properties.

---

# QUADRANT MAP

```
DETECT quadrant (D):     D.1–D.11  — the discovery fleet
CLOUD/CROSS quadrant (C): C.x      — network, kubernetes, runtime
AUDIT quadrant:          D.8 Compliance, A.4 Meta-Harness
CURE quadrant (A):       A.1–A.3 Remediation
```

---

# D.1 — VULNERABILITY AGENT

## Mandate

Discover every known vulnerability across every scannable artifact — container images, OS packages, language dependencies, Lambda packages, Kubernetes workloads — and attach them to the resources that carry them.

## Scope boundary

- **Covers:** CVE detection, package vulnerability matching, SBOM generation, exploit-availability correlation, vulnerability severity scoring.
- **Does NOT cover:** the cloud configuration of the resource hosting the vulnerable artifact (that's D.3), the identity attached to it (D.2), or remediation (A.1–A.3). D.1 finds the vulnerability; it does not fix it or assess its blast radius.

## Tools

- **Trivy** — container image, filesystem, repository, Kubernetes, SBOM scanning
- **Grype** — alternative vulnerability scanner with native EPSS + KEV integration for cross-validation
- **OSV-scanner** — open-source dependency vulnerabilities across 20+ ecosystems
- **NVD** — the canonical CVE database
- **EPSS** — Exploit Prediction Scoring System (likelihood scoring)
- **CISA KEV** — Known Exploited Vulnerabilities catalog (actively-exploited prioritization)

## Nodes owned (canonical)

- **CVE Finding node** — `{cve_id, cvss_score, cvss_vector, epss_score, kev_listed, severity, affected_package, affected_version, fixed_version, discovery_timestamp, source_database}`
- **SBOM package node** — `{package_name, version, ecosystem, license, source_layer, purl}`
- **Vulnerability scan record node** — `{scan_id, target, scanner, scanner_version, timestamp, total_findings}`

## Nodes contributed to

- **Container Image node** (owned by D.1 for the image artifact itself, but image-to-source edges contributed by D.9) — D.1 annotates with `vulnerability_count`, `critical_count`, `last_scanned`
- **EC2 / VM nodes** (owned by D.3) — D.1 annotates with discovered package vulnerabilities when L5-runtime data is available via sensor
- **Lambda function nodes** (owned by D.3) — D.1 annotates with package vulnerabilities in deployment package
- **Kubernetes pod nodes** (owned by D.6) — D.1 annotates with image vulnerabilities

## Edges written

- `VULNERABLE_TO`: Resource → CVE Finding (the core vulnerability edge)
- `CONTAINS_PACKAGE`: Container Image → SBOM package
- `CONTAINS_PACKAGE`: Lambda function → SBOM package
- `FIXED_IN`: CVE Finding → version (remediation target)
- `AFFECTS`: CVE Finding → Resource (the resource carrying the vulnerable artifact)

## L-levels covered

- **L2:** SBOM package nodes, CVE Finding nodes
- **L5-image:** package manifests extracted from container images, Lambda packages, AMIs
- **L5-runtime:** package manifests from running filesystems (when C.x Runtime sensor present)

---

# D.2 — IDENTITY AGENT (CIEM)

## Mandate

Discover every identity, every permission, every trust relationship across all cloud providers, and map the effective access each identity has to every resource. This is the agent that answers "who can do what to what."

## Scope boundary

- **Covers:** IAM users, roles, policies, permission boundaries, SCPs, Azure RBAC, GCP IAM, federated identity, group memberships, effective-access computation, privilege escalation path analysis.
- **Does NOT cover:** the cloud resources identities have access to (D.3 owns those nodes; D.2 writes the access edges), runtime authentication events at the OS level (C.x Runtime), or SaaS-side identity unless federated (D.10).

## Tools

- Custom IAM/CIEM analysis engine
- Reference patterns: CloudMapper, IAMSpy, Parliament (policy linting), AWS Access Analyzer concepts
- Policy JSON parsers (walk inside policy documents to extract principals, actions, resources, conditions)

## Nodes owned (canonical)

- **IAM user node** — `{arn, name, creation_date, last_activity, mfa_enabled, access_keys[], console_access, tags}`
- **IAM role node** — `{arn, name, trust_policy, max_session_duration, last_used, path, managed_vs_custom, permission_boundary}`
- **IAM policy node** — `{arn, name, policy_document, version, attachment_count, aws_managed_vs_customer}`
- **Permission boundary node** — `{arn, document}`
- **SCP node** — `{id, document, target_ous[], target_accounts[]}`
- **Azure RBAC role assignment node** — `{id, role_definition, principal, scope}`
- **Azure custom role node** — `{id, permissions[], assignable_scopes[]}`
- **GCP IAM binding node** — `{role, members[], resource, condition}`
- **GCP custom role node** — `{id, permissions[], stage}`
- **Service account node** — `{email/arn, keys[], creation_date, last_used}`
- **Identity group node** — `{id, name, members[], attached_policies[]}`
- **Federated identity provider node** — `{type (SAML/OIDC), issuer, trust_config}`
- **Authentication event node (L6)** — `{identity, timestamp, source_ip, mfa_status, success, geolocation}`

## Nodes contributed to

- **All cloud resource nodes** (owned by D.3) — D.2 writes the `HAS_ACCESS_TO` edges describing which identities can act on them
- **KMS key nodes** (owned by D.3) — D.2 analyzes key policies for access
- **Account nodes** (owned by D.3) — D.2 writes cross-account `TRUSTS` edges

## Edges written

- `ASSUMES`: Compute → IAM role, ServiceAccount → IAM role (via IRSA), Identity → IAM role
- `HAS_ACCESS_TO`: Identity/Role → Resource (with permission set in edge properties: actions[], effect, conditions)
- `MEMBER_OF`: Identity → Group
- `ATTACHED_TO`: Policy → Identity/Role/Group
- `TRUSTS`: Account → Account (cross-account), Identity Provider → Account
- `ASSUMABLE_BY`: Role → Service/Principal (derived from trust policy)
- `CAN_ESCALATE_TO`: Identity → Identity (privilege escalation path — computed)
- `BOUNDED_BY`: Identity → Permission boundary

## L-levels covered

- **L2:** all identity nodes
- **L3:** policy documents, trust policies, permission boundaries as node properties
- **L4:** the entire access-edge layer (`HAS_ACCESS_TO`, `ASSUMES`, `CAN_ESCALATE_TO`)
- **L6:** authentication events

---

# D.3 — CLOUD POSTURE AGENT (CSPM) — AWS

## Mandate

Discover every AWS cloud resource and its complete security configuration. This is the foundational discovery agent — the largest single owner of inventory nodes. The bulk of L2 and L3 lives here.

## Scope boundary

- **Covers:** AWS CSPM only (per locked architectural scope). Every AWS resource: compute, storage, database, networking, secrets, encryption, messaging, observability. Their full L3 configurations. Misconfiguration findings.
- **Does NOT cover:** Azure or GCP (that's D.5), Kubernetes cluster-internals (D.6 — though D.3 owns the EKS cluster node itself), identity access edges (D.2 writes those onto D.3's nodes), data classification (D.4), or vulnerabilities (D.1). **F.3 Cloud Posture = AWS CSPM ONLY.** Never add multi-cloud framing in this agent's deliverables.

## Tools

- **Prowler** — ~600 AWS checks (the primary CSPM rule engine)
- **boto3** — AWS SDK for resource enumeration

## Nodes owned (canonical)

### Compute

- EC2 instance, EC2 Spot Fleet, EC2 Auto Scaling Group, Lambda function, Lambda Layer, Lambda Function URL, ECS task, ECS service, ECS cluster, Fargate task, AWS App Runner service, Lightsail instance, AWS Batch (queue, definition, compute environment), AWS Dedicated Host, EC2 Bare Metal, AWS WorkSpaces, AppStream, Lambda@Edge, CloudFront Function, AWS Wavelength, AWS Outposts
- **EKS cluster, EKS node group, EKS Fargate profile, EKS managed addon** (D.3 owns the cluster control-plane node; D.6 owns what runs inside)

### Storage

- S3 bucket, S3 access point, S3 multi-region access point, S3 Object Lambda access point, EBS volume, EBS snapshot, EFS file system, EFS access point, FSx (Lustre/Windows/NetApp/OpenZFS), AWS Backup (vault, plan, recovery point), S3 Glacier vault

### Database

- RDS DB instance, RDS DB cluster, Aurora cluster, Aurora Serverless, RDS Proxy, DynamoDB table, DynamoDB global table, DynamoDB stream, ElastiCache (Redis, Memcached), MemoryDB cluster, OpenSearch domain, OpenSearch Serverless collection, Neptune cluster, Timestream (database, table), Redshift cluster, Redshift Serverless (workgroup, namespace), DocumentDB cluster, QLDB ledger

### Networking

- VPC, subnet, route table, route, VPC peering connection, VPC endpoint, VPC endpoint service, transit gateway, transit gateway attachment, security group, NACL, internet gateway, NAT gateway, NAT instance, egress-only IGW, ALB, NLB, CLB, Gateway Load Balancer, ELB target group, Route 53 hosted zone, Route 53 record, Route 53 resolver, Site-to-site VPN, Client VPN endpoint, Direct Connect, CloudFront distribution, CloudFront origin, AWS Global Accelerator, App Mesh, AWS Cloud Map, AWS WAF web ACL, WAF rule group, AWS Shield

### Secrets and encryption

- AWS Secrets Manager secret, SSM Parameter Store SecureString, KMS key, KMS alias, KMS grant, ACM certificate, ACM Private CA

### Messaging and eventing

- SQS queue (standard, FIFO), SNS topic, SNS subscription, Kinesis Data Stream, Kinesis Firehose, Kinesis Data Analytics, MSK cluster, MSK Connect, MSK Serverless, EventBridge bus, EventBridge rule, EventBridge pipe, EventBridge scheduler, Step Functions state machine, Step Functions activity, AWS SWF domain, MWAA (Airflow)

### Observability

- CloudWatch log group, CloudWatch log stream, CloudWatch metric alarm, CloudTrail trail, CloudTrail Lake event data store, AWS Config recorder, AWS Config delivery channel, AWS Config rule, AWS Config conformance pack, X-Ray service map

### Image artifacts

- AMI, container image (by digest — but D.1 owns the vulnerability annotations), ECR repository, ECR Public, ECR Pull Through Cache, CodeArtifact (domain, repository)

### Findings

- **AWS Misconfiguration Finding node** — `{rule_id, severity, resource, description, remediation, source (Prowler check), compliance_mappings[]}`

## Nodes contributed to

- **Container Image nodes** (canonical D.1) — D.3 references images in compute deployments
- **IaC artifact nodes** (canonical D.9) — D.3 cross-references which resources came from which stacks

## Edges written

- `OWNS`: Account → Resource
- `CONTAINS`: Account → Resource, VPC → Subnet
- `IN_SUBNET`: Compute → Subnet
- `IN_VPC`: Subnet → VPC, Compute → VPC
- `ATTACHED_TO`: SecurityGroup → Resource
- `ENCRYPTED_BY`: Resource → KMS key
- `STORES_SECRET`: SecretStore → SecretRef
- `RUNS_IMAGE`: Compute → Container Image
- `ROUTES_TO`: RouteTable → Gateway
- `PEERED_WITH`: VPC → VPC
- `LOGS_TO`: Resource → LogGroup
- `EXPOSED_TO`: Resource → Internet (when public IP or public security group rule — derived from L3)

## L-levels covered

- **L1:** AWS accounts, OUs (shared with org-level discovery)
- **L2:** the bulk of all AWS resource nodes
- **L3:** the complete configuration of every AWS resource (the deepest static layer)
- **L4:** structural edges derived from L3 (`IN_SUBNET`, `ATTACHED_TO`, `ENCRYPTED_BY`, `EXPOSED_TO`)

---

# D.4 — DATA SECURITY AGENT (DSPM) — AWS / primary

## Mandate

Discover what data exists inside storage resources and classify its sensitivity. This is the agent that answers "where is the sensitive data, and is it exposed."

## Scope boundary

- **Covers:** content classification of storage (S3, RDS, Redshift, DynamoDB, EFS), detection of PII/PCI/PHI/secrets/training-data, data-exposure correlation.
- **Does NOT cover:** the storage resource's cloud configuration (D.3 owns the bucket node; D.4 writes the classification edge), multi-cloud data stores (D.5 for Azure/GCP), or the identities that can reach the data (D.2).

## Tools

- Custom content classification pipeline
- Open-source DLP libraries (regex + ML classifiers for PII/PCI/PHI detection)
- Macie-equivalent classification logic

## Nodes owned (canonical)

- **Data classification node** — `{type, subtype, confidence, sample_location, scan_timestamp}` where:
  - **PII subtypes:** SSN, full name, email, postal address, phone, date of birth, government ID, biometric, financial account, medical record
  - **Compliance-scoped:** PCI cardholder data, PHI, GDPR personal data, CCPA personal information, SOX financial data
  - **Authentication material:** API keys (by provider), private keys, passwords, session tokens, OAuth tokens, JWT signing keys, DB connection strings
  - **Source material:** source code, IP, trade secrets
  - **AI-specific:** training data, model weights, prompt logs, sensitive embeddings
  - **Customer-specific:** customer data, uploaded files, communication logs
- **Data scan record node** — `{scan_id, target, classifier_version, records_scanned, sensitive_found}`

## Nodes contributed to

- **S3 bucket, RDS, Redshift, DynamoDB, EFS nodes** (owned by D.3) — D.4 writes `CONTAINS` edges to classification nodes
- **Secret nodes** (owned by D.3) — D.4 adds usage-pattern analysis

## Edges written

- `CONTAINS`: Storage resource → Data classification (the core DSPM edge)
- `CLASSIFIED_AS`: Resource → sensitivity tag
- `EXPOSES_DATA`: Resource → Data classification (when exposure + sensitivity intersect)

## L-levels covered

- **L2:** data classification nodes
- **L5:** content scanning inside storage (the data-content layer)

---

# D.5 — MULTI-CLOUD POSTURE AGENT — Azure + GCP

## Mandate

The Azure and GCP analog to D.3. Discover every Azure and GCP resource and its security configuration. Currently in fixture mode — the discovery logic exists but live connectors are not yet wired.

## Scope boundary

- **Covers:** Azure + GCP CSPM. Azure resources (VMs, Blob, SQL, AKS, Key Vault, NSGs, etc.) and GCP resources (Compute Engine, GCS, Cloud SQL, GKE, KMS, firewall rules, etc.) and their L3 configurations.
- **Does NOT cover:** AWS (that's D.3), Kubernetes cluster-internals (D.6), identity edges (D.2). **D.5 Multi-Cloud Posture = Azure + GCP only.**

## Tools

- **Prowler** — 167 Azure checks + 102 GCP checks
- Azure SDK for Python
- GCP client libraries

## Nodes owned (canonical)

### Azure

- Azure VM, Azure VM Scale Set, Azure Functions, Azure Container Instance, Azure Container Apps, AKS cluster, AKS node pool, Azure Blob container, Azure Data Lake Storage Gen2, Azure Storage Account, Azure Managed Disk, Azure Files, Azure SQL Database, Azure SQL Managed Instance, Azure PostgreSQL/MySQL Flexible Server, Azure Cosmos DB (all APIs), Azure Cache for Redis, Azure AI Search, Azure VNet, Azure subnet, Azure NSG, Azure ASG, Azure Application Gateway, Azure Load Balancer, Azure Front Door, Azure DNS zone, Azure Private DNS zone, Azure VPN Gateway, Azure ExpressRoute, Azure Key Vault (secret, key, certificate), Azure Service Bus, Azure Event Hubs, Azure Event Grid, Azure Logic Apps, Azure Monitor, Log Analytics workspace, Application Insights
- **Azure Misconfiguration Finding node**

### GCP

- GCP Compute Engine, GCP Managed Instance Group, GCP Cloud Functions (Gen 1, Gen 2), GCP Cloud Run, GKE cluster, GKE node pool, GKE Autopilot, GCS bucket, GCP Persistent Disk, GCP Filestore, GCP Cloud SQL, GCP AlloyDB, GCP Spanner, GCP Firestore, GCP Bigtable, GCP BigQuery (dataset, table), GCP Memorystore, GCP VPC, GCP subnet, GCP firewall rule, GCP firewall policy, GCP Cloud Armor, GCP Load Balancer, GCP Cloud DNS, GCP Cloud VPN, GCP Cloud Interconnect, GCP KMS (key ring, key, version), GCP Secret Manager, GCP Pub/Sub (topic, subscription), GCP Eventarc, GCP Workflows, GCP Cloud Logging, GCP Cloud Monitoring
- **GCP Misconfiguration Finding node**

## Nodes contributed to

- Azure/GCP identity nodes (D.2 owns identity analysis; D.5 surfaces the raw RBAC/IAM data)

## Edges written

- Same edge typology as D.3 but for Azure/GCP resources: `OWNS`, `CONTAINS`, `IN_SUBNET`, `IN_VPC`, `ATTACHED_TO`, `ENCRYPTED_BY`, `EXPOSED_TO`, `ROUTES_TO`, `PEERED_WITH`, `LOGS_TO`

## L-levels covered

- **L1:** Azure subscriptions/management groups, GCP projects/folders/orgs
- **L2:** all Azure and GCP resource nodes
- **L3:** Azure and GCP resource configurations
- **L4:** structural edges for Azure/GCP

## Current state note

Fixture mode. Activating D.5 = wiring live Azure/GCP connectors. The detection logic (Prowler's Azure/GCP checks) already exists. This is integration work, not detection-logic work.

---

# D.6 — KUBERNETES POSTURE AGENT (KSPM) — cloud-agnostic

## Mandate

Discover everything inside Kubernetes clusters — every workload, every RBAC binding, every network policy, every admission webhook — across any cloud or on-prem cluster. Cloud-agnostic by design.

## Scope boundary

- **Covers:** cluster-internal resources (pods, deployments, services, RBAC, network policies, admission controllers, CRDs), pod security configuration, cluster configuration (audit logging, PodSecurityStandards), CIS Kubernetes Benchmark compliance.
- **Does NOT cover:** the cloud control-plane node of the cluster (D.3 owns EKS cluster, D.5 owns AKS/GKE cluster nodes), container image vulnerabilities (D.1), or runtime process behavior inside pods (C.x Runtime).

## Tools

- **kube-bench** — full CIS Kubernetes Benchmark (hundreds of checks across control plane, worker, etcd, policies; EKS/GKE/AKS/OpenShift/k3s/RKE2 variants)
- **Polaris** — ~40 workload best-practice checks (24 security, 12 reliability, 4 efficiency)

## Nodes owned (canonical)

- Namespace, deployment, statefulset, daemonset, replicaset, pod, job, cronjob, service, endpoint, endpointslice, ingress, ingressclass, networkpolicy, poddisruptionbudget, horizontalpodautoscaler, verticalpodautoscaler, configmap, secret (K8s secret object), persistentvolume, persistentvolumeclaim, storageclass, serviceaccount (K8s), role, rolebinding, clusterrole, clusterrolebinding, mutatingwebhookconfiguration, validatingwebhookconfiguration, customresourcedefinition
- **Kubernetes Misconfiguration Finding node** — `{rule_id, severity, resource, namespace, description, source (kube-bench/Polaris)}`

## Nodes contributed to

- **EKS/AKS/GKE cluster nodes** (owned by D.3/D.5) — D.6 annotates with cluster-internal posture summary
- **Container image nodes** (owned by D.1) — D.6 references images run by pods
- **IAM role nodes** (owned by D.2) — D.6 writes IRSA mapping edges from K8s service accounts to IAM roles

## Edges written

- `RUNS_ON`: Pod → Node
- `USES_SERVICE_ACCOUNT`: Pod → K8s ServiceAccount
- `IRSA_MAPPING`: K8s ServiceAccount → IAM role (the cluster-to-cloud identity bridge)
- `RUNS_IMAGE`: Pod → Container image
- `SELECTS`: Service → Pod (label-based)
- `INGRESS_TO`: Ingress → Service
- `MOUNTS`: Pod → Volume (secret/configmap/hostPath/PVC)
- `OWNED_BY`: Pod → Deployment/StatefulSet/DaemonSet
- `GRANTS`: RoleBinding → Role, ClusterRoleBinding → ClusterRole
- `BINDS`: RoleBinding → ServiceAccount/User/Group

## L-levels covered

- **L2:** all cluster-internal nodes
- **L3:** pod security contexts, RBAC documents, network policy specs
- **L4:** cluster-internal edges + the IRSA cloud bridge

---

# D.7 — THREAT INTELLIGENCE AGENT

## Mandate

Enrich the inventory with external threat context — which vulnerabilities have known exploits, which IPs/domains are known-bad, which indicators of compromise are currently active.

## Scope boundary

- **Covers:** exploit availability for CVEs, known-bad IP/domain reputation, IOC correlation, threat-actor attribution context, recent CVE weaponization signals.
- **Does NOT cover:** the discovery of the CVEs themselves (D.1 owns CVE nodes; D.7 enriches them), live network detection (C.x Network), or remediation.

## Tools

- **Exploit-DB feeds** — public exploit availability
- **CISA KEV** — actively-exploited catalog (1,484 entries end of 2025)
- **MISP** — threat intelligence aggregation and IOC correlation
- **OpenCTI** — threat intelligence platform for structured threat data

## Nodes owned (canonical)

- **Exploit availability node** — `{cve_id, exploit_source, exploit_maturity, weaponized, public_poc_available}`
- **Threat indicator node** — `{indicator_type (ip/domain/hash), value, source, confidence, first_seen, last_seen, threat_category}`
- **Threat actor context node** — `{actor_name, ttps[], associated_indicators[]}`

## Nodes contributed to

- **CVE Finding nodes** (owned by D.1) — D.7 writes `EXPLOIT_EXISTS_FOR` edges, adding the exploitability dimension that elevates a CVE from theoretical to critical
- **L6 behavior event nodes** (owned by C.x) — D.7 matches observed IPs/domains against threat indicators

## Edges written

- `EXPLOIT_EXISTS_FOR`: Exploit availability → CVE Finding
- `MATCHES_INDICATOR`: L6 network event → Threat indicator
- `ATTRIBUTED_TO`: Threat indicator → Threat actor

## L-levels covered

- **L2:** exploit availability, threat indicator nodes
- **Cross-cutting:** enriches L2 CVE nodes and L6 behavior nodes

---

# D.8 — COMPLIANCE AGENT

## Mandate

Map every finding across the fleet to the compliance frameworks the customer cares about, and produce framework-level posture reporting.

## Scope boundary

- **Covers:** mapping findings to PCI-DSS, HIPAA, SOC 2, ISO 27001, NIST 800-53, NIST CSF, CIS, GDPR, FedRAMP, and others; compliance heatmaps; framework gap analysis.
- **Does NOT cover:** the generation of the findings themselves (every detection agent produces those), only their mapping to requirements.

## Tools

- OSCAL (Open Security Controls Assessment Language) definitions
- Prowler's framework mappings (~41 frameworks already mapped)
- Regulators' published control mappings

## Nodes owned (canonical)

- **Compliance requirement node** — `{framework, requirement_id, requirement_text, category}`
- **Compliance framework node** — `{framework_name, version, total_requirements}`
- **Compliance assessment record node** — `{framework, timestamp, pass_count, fail_count, score}`

## Nodes contributed to

- **All Finding nodes** (owned by detection agents) — D.8 writes `MAPS_TO_REQUIREMENT` edges connecting findings to the requirements they satisfy or violate

## Edges written

- `MAPS_TO_REQUIREMENT`: Finding → Compliance requirement
- `SATISFIES`: Resource configuration → Compliance requirement
- `VIOLATES`: Finding → Compliance requirement
- `PART_OF`: Compliance requirement → Compliance framework

## L-levels covered

- **L2:** compliance requirement and framework nodes
- **Cross-cutting:** maps all findings across all agents

---

# D.9 — APPSEC AGENT (UNBUILT)

## Mandate

Discover the code side of the world — repositories, commits, builds, pipelines, IaC — and connect deployed cloud resources back to the source code and developer that produced them. This is the agent that makes code-to-cloud tracing possible.

## Scope boundary

- **Covers:** source repositories, commits, branches, pull requests, CI/CD pipelines, build artifacts, IaC artifacts, SAST findings, IaC misconfiguration findings, secrets in code.
- **Does NOT cover:** the deployed cloud resources themselves (D.3/D.5 own those; D.9 writes the `BUILT_FROM` edges back to them), runtime behavior, or the vulnerability database matching (D.1 — though D.9 surfaces dependency files for D.1 to scan).

## Tools

- **Semgrep** — SAST (2,000+ community rules / 20,000+ Pro rules)
- **Checkov** — IaC scanning (1,000+ policies across Terraform, CloudFormation, Kubernetes, ARM, Bicep, Helm, Ansible, OpenTofu)
- **Trufflehog** — secrets detection (800+ secret detectors with live verification)
- **Gitleaks** — secrets detection (100+ regex rules)
- GitHub API, GitLab API, Bitbucket API

## Nodes owned (canonical)

- **Repository node** — `{url, visibility, default_branch, branch_protection, collaborators[], webhooks[], code_scanning_enabled, secret_scanning_enabled, dependabot_enabled, last_push, topics, languages}`
- **Commit node** — `{sha, author, committer, timestamp, signed, message, files_changed[]}`
- **Branch node** — `{name, protected, protection_rules}`
- **Pull request node** — `{id, author, status, source_branch, target_branch, checks[]}`
- **CI/CD pipeline node** — `{type, repository, triggers[], runners[]}`
- **Build node** — `{id, pipeline, status, artifacts[], timestamp, commit}`
- **IaC artifact node** — `{type (terraform/cloudformation/bicep/helm), location, resources_declared[], state_backend}`
- **Developer node** — `{username, email, commits[], repos[]}`
- **SAST finding node** — `{rule_id, severity, file, line, source (Semgrep)}`
- **IaC misconfiguration finding node** — `{rule_id, severity, resource_block, file, source (Checkov)}`
- **Secret-in-code finding node** — `{secret_type, file, line, verified, source (Trufflehog/Gitleaks)}`

## Nodes contributed to

- **Container image nodes** (owned by D.1) — D.9 writes `BUILT_FROM` edges connecting images to source commits
- **Cloud resource nodes** (owned by D.3/D.5) — D.9 writes `DEPLOYED_VIA` edges connecting resources to IaC artifacts

## Edges written

- `BUILT_FROM`: Container image → Repository, Container image → Commit
- `COMMITTED_BY`: Commit → Developer
- `DEPLOYED_VIA`: Cloud resource → IaC artifact
- `DEFINED_IN`: IaC artifact → Repository
- `TRIGGERED_BY`: Build → Commit
- `PRODUCES`: Build → Container image / artifact
- `INTRODUCED_IN`: Finding → Commit (which commit introduced the vulnerability/misconfig)

## L-levels covered

- **L2:** all code-side nodes
- **L3:** repository configurations, branch protection, pipeline configs
- **L4:** the entire code-to-cloud edge bridge (`BUILT_FROM`, `DEPLOYED_VIA`, `COMMITTED_BY`)
- **L5:** code contents (SAST, secrets scanning)

---

# D.10 — SSPM AGENT (UNBUILT)

## Mandate

Discover SaaS application posture — the configurations, identities, integrations, and data-sharing settings of the SaaS tools the organization uses — and connect them into the same graph as cloud resources.

## Scope boundary

- **Covers:** SaaS tenant configurations (Okta, GitHub-as-SaaS, M365, Google Workspace, Slack, Salesforce, etc.), OAuth apps and grants, third-party integrations, admin permissions, MFA enforcement, data-sharing settings.
- **Does NOT cover:** the cloud resources SaaS tools integrate with (D.3/D.5), code repositories as code (D.9 — though D.10 covers GitHub's SaaS-level org settings), or federated identity computation (D.2 — though D.10 surfaces the federation config).

## Tools

- Custom SSPM connectors (SSPM open source is sparse)
- Reference patterns: Disco, SaaSAlerts
- SaaS provider APIs (Okta API, Microsoft Graph API, Google Workspace Admin API, Slack API, Salesforce API)

## Nodes owned (canonical)

- **SaaS tenant node** — `{provider, tenant_id, name, admin_count, mfa_enforcement, data_sharing_config}`
- **OAuth application node** — `{app_id, name, scopes[], authorized_by, tenant}`
- **SaaS integration node** — `{source_saas, target_saas, integration_type, permissions[]}`
- **SaaS user node** — `{provider, user_id, roles[], mfa_status, last_login}`
- **SaaS misconfiguration finding node** — `{rule_id, severity, tenant, description}`

Per-provider sub-coverage:

- **Productivity:** Google Workspace, Microsoft 365, Slack, Zoom, Atlassian (Jira, Confluence), Notion, Asana
- **Engineering SaaS:** GitHub (org/marketplace/OAuth level), GitLab.com, CircleCI, Datadog, PagerDuty, Sentry, Snyk
- **CRM/business:** Salesforce, HubSpot, Workday, NetSuite
- **Identity SaaS:** Okta, Auth0, OneLogin, JumpCloud, Ping
- **Security SaaS:** 1Password, LastPass, CrowdStrike, SentinelOne
- **File sharing:** Dropbox Business, Box

## Nodes contributed to

- **Cloud account nodes** (owned by D.3/D.5) — D.10 writes `INTEGRATED_WITH` edges
- **Federated identity nodes** (owned by D.2) — D.10 surfaces the IdP-to-cloud federation config

## Edges written

- `INTEGRATED_WITH`: SaaS tenant → Cloud account
- `FEDERATED_FROM`: Identity provider → Account
- `AUTHORIZED`: OAuth app → SaaS tenant (with scope)
- `SSO_INTO`: SaaS user → Cloud account (the cross-domain identity path)

## L-levels covered

- **L1:** SaaS tenants as containers
- **L2:** SaaS users, OAuth apps, integrations
- **L3:** SaaS configurations
- **L4:** SaaS-to-cloud integration edges

---

# D.11 — AI-SPM AGENT (UNBUILT)

## Mandate

Discover the AI/ML footprint — services, models, frameworks, training data — and identify AI-specific risks like model exposure, training-data poisoning paths, and AI-provider key leakage.

## Scope boundary

- **Covers:** AI service inventory (Bedrock, SageMaker, Vertex AI, Azure OpenAI), AI frameworks (MLflow, Hugging Face, LangChain, LlamaIndex), AI infrastructure (Ray, KubeFlow, Triton), AI-specific risks (exposed endpoints, training data exposure, prompt injection vectors, shadow AI), AI-provider key detection.
- **Does NOT cover:** the underlying compute/storage hosting AI services (D.3/D.5 own the EC2/bucket; D.11 adds the AI-classification layer), training-data content classification (D.4 classifies; D.11 connects it to AI lineage), or general vulnerabilities (D.1).

## Tools

- Custom AI service discovery connectors
- **Garak** — LLM vulnerability probes (150+ attacks / 3,000+ prompts / 50+ probe modules)
- **NeMo Guardrails** — programmable LLM guardrails
- AI-provider key signature detection (OpenAI sk-_, Hugging Face hf\__, Anthropic sk-ant-\*)

## Nodes owned (canonical)

### AWS AI

- SageMaker domain, SageMaker notebook instance, SageMaker training job, SageMaker model, SageMaker endpoint, SageMaker pipeline, SageMaker feature group, Bedrock agent, Bedrock knowledge base, Bedrock guardrail, Bedrock custom model, Amazon Q app

### Azure AI

- Azure ML workspace, Azure ML compute, Azure ML endpoint, Azure ML model, Azure OpenAI deployment, Azure AI Search index, Azure Cognitive Services account, Azure AI Foundry hub

### GCP AI

- Vertex AI dataset, Vertex AI training pipeline, Vertex AI model, Vertex AI endpoint, Vertex AI Workbench notebook, Vertex AI feature store, GCP AutoML model, Gemini API binding

### Frameworks / OSS

- MLflow tracking server, MLflow model registry, Hugging Face model (in code or storage), LangChain pipeline, LlamaIndex pipeline, Chroma vector store, Pinecone index, Weaviate cluster, Qdrant cluster, FAISS index

### AI infrastructure

- Triton Inference Server, Ray cluster, KubeFlow pipeline, JupyterHub

### AI agents / MCP

- Deployed agent endpoint, MCP server registration, agent task queue, AI tool registry

### Findings

- **AI-SPM finding node** — `{rule_id, severity, ai_resource, risk_type (exposed_endpoint/data_poisoning/key_leak/shadow_ai), description}`

## Nodes contributed to

- **Compute/storage nodes** (owned by D.3/D.5) — D.11 writes AI-classification edges identifying which infrastructure hosts AI workloads
- **Data classification nodes** (owned by D.4) — D.11 writes `TRAINED_ON` edges connecting models to training datasets

## Edges written

- `TRAINED_ON`: Model → Dataset
- `SERVES_MODEL`: Endpoint → Model
- `INFERENCES_LOGGED_TO`: Endpoint → data capture bucket
- `INVOKED_BY`: Agent → Compute
- `HOSTS_AI`: Compute → AI service (the infra-to-AI classification edge)
- `EXPOSES_MODEL`: Endpoint → Internet (when public)

## L-levels covered

- **L2:** all AI-specific nodes
- **L3:** AI service configurations (network isolation, encryption, public access)
- **L4:** AI lineage edges (`TRAINED_ON`, `SERVES_MODEL`)
- **L5:** AI-provider key detection in code/storage

---

# C.x — NETWORK AGENT

## Mandate

Discover network reachability — what can reach what — and emit the network-path edges that make lateral-movement and internet-exposure analysis possible. Also capture network behavior at runtime.

## Scope boundary

- **Covers:** VPC/VNet reachability computation, security group + NACL + route table traversal, internet exposure paths, lateral movement paths, cross-VPC reachability, network flow events (L6).
- **Does NOT cover:** the network resource configurations themselves (D.3/D.5 own security group, route table, VPC nodes; C.x Network reads them and derives reachability edges), or in-host process behavior (C.x Runtime).

## Tools

- Custom reachability traversal engine (over security group + NACL + route table data)
- **Suricata** — network IDS/IPS (~21,000+ ET Open rules)
- VPC Flow Logs analysis
- DNS query log analysis

## Nodes owned (canonical)

- **Network path node** — `{source, destination, protocol, ports[], path_hops[]}`
- **Network flow event node (L6)** — `{source_ip, dest_ip, source_port, dest_port, protocol, bytes, packets, duration, timestamp}`
- **Network detection finding node** — `{rule_id, severity, source (Suricata), signature}`

## Nodes contributed to

- **All compute/network resource nodes** (owned by D.3/D.5) — C.x Network writes the `CAN_REACH` and `EXPOSED_TO` edges

## Edges written

- `CAN_REACH`: Resource → Resource (with port/protocol — the core reachability edge)
- `EXPOSED_TO`: Internet → Resource (computed internet exposure)
- `LATERAL_PATH`: Resource → Resource (computed lateral movement)
- `COMMUNICATES_WITH`: Resource → Resource (observed from flow logs)

## L-levels covered

- **L4:** the entire network reachability edge layer (`CAN_REACH`, `EXPOSED_TO`)
- **L6:** network flow events

---

# C.x — KUBERNETES NETWORK (overlaps with D.6)

## Mandate

Discover cluster-internal network paths — service mesh routes, ingress paths, pod-to-pod reachability via network policies.

## Scope boundary

- **Covers:** cluster-internal traffic patterns, service mesh routes, ingress paths, network policy reachability.
- **Does NOT cover:** cluster-external network (C.x Network), or the K8s resource configs (D.6).

## Tools

- Network policy traversal engine
- Service mesh config readers (Istio, Linkerd)

## Edges written

- `ROUTES_TO`: Service mesh route
- `INGRESS_TO`: Ingress → Service
- `POD_CAN_REACH`: Pod → Pod (via network policy)

## L-levels covered

- **L4:** cluster-internal network edges

---

# C.x — RUNTIME AGENT

## Mandate

Discover what's actually happening on running workloads — live processes, file changes, syscalls, in-host authentication — via sensors deployed to the workloads. This is the agent that populates L5-runtime and L6 behavior.

## Scope boundary

- **Covers:** live process execution, syscall events, file integrity changes, container runtime events, in-VM authentication, L5-runtime filesystem state.
- **Does NOT cover:** static resource config (D.3/D.5), image vulnerabilities at rest (D.1 — though C.x Runtime feeds runtime filesystem to D.1 for scanning), or network reachability computation (C.x Network).

## Tools

- **Falco** — eBPF runtime detection (93 managed rules, 25 stable bundled by default)
- **Tracee** — eBPF behavioral signatures (TRC-1…TRC-15+, MITRE ATT&CK mapped)
- **OSQuery** — host state as SQL (incident-response and vuln-management query packs)

## Nodes owned (canonical)

- **Process event node (L6)** — `{binary, args, user, parent_process, host, exit_code, duration, timestamp}`
- **File integrity event node (L6)** — `{file_path, change_type, process, host, timestamp}`
- **Container lifecycle event node (L6)** — `{event (start/stop/exec/kill), image, user, host, timestamp}`
- **Runtime detection finding node** — `{rule_id, severity, source (Falco/Tracee), mitre_technique, host}`
- **L5-runtime property sets** — filesystem state, running packages, open ports, OS users, SSH keys, sudoers config (attached to existing resource nodes)

## Nodes contributed to

- **EC2 / VM nodes** (owned by D.3/D.5) — C.x Runtime adds L5-runtime properties and L6 behavior events
- **Kubernetes pod nodes** (owned by D.6) — C.x Runtime adds runtime behavior
- **Authentication event nodes** (owned by D.2) — C.x Runtime contributes OS-level auth events

## Edges written

- `EXECUTED_ON`: Process event → Host resource
- `MODIFIED`: Process → File
- `EXHIBITED_BEHAVIOR`: Resource → Runtime finding
- `OPENED_PORT`: Resource → port (actual listening state vs. SG-allowed)

## L-levels covered

- **L5-runtime:** live filesystem, packages, ports, users (via sensor)
- **L6:** process, file, container lifecycle events

## Sensor deployment note (Option D)

The L5-runtime and L6 data require a sensor on the workload. v1 ships without it (cloud-API L5-image only). v1.5 adds opt-in Falco/Tracee/OSQuery deployment via Helm/Ansible/systemd, reporting back to the edge runtime over local TLS — data stays in the customer environment.

---

# A.1 / A.2 / A.3 — REMEDIATION AGENTS

## Mandate

Act on findings using inventory and trace context. Three tiers of increasing autonomy. These agents consume the inventory graph rather than populating it — but they read heavily from it.

## Scope boundary

- **Covers:** fix recommendation (A.1), fix-as-code generation without applying (A.2), and authorized fix execution (A.3).
- **Does NOT cover:** detection (the D and C agents) or correlation (the diagnostician). Remediation acts on what others found.

## Tools

- **DeepSeek** — LLM for natural-language remediation step generation (Ask AI)
- SCM write clients (Octokit for GitHub, GitLab client)
- Fix template library (per CVE class, per misconfiguration class)

## Nodes owned (canonical)

- **Remediation action node** — `{finding, tier (recommend/dry_run/execute), status, generated_fix, timestamp}`
- **Fix template node** — `{finding_class, template, target_format (cli/console/terraform)}`
- **Pre-authorization node** — `{tenant, finding_class, environment, auto_fix_approved}`

## Nodes consumed (read-heavy)

- All Finding nodes (what to fix)
- Code-to-cloud trace edges from D.9 (where the fix lands)
- Inventory context (which repo, which resource, which owner)

## Edges written

- `REMEDIATES`: Remediation action → Finding
- `TARGETS`: Remediation action → Resource/Repository
- `AUTHORIZED_BY`: Remediation action → Pre-authorization

## L-levels covered

- Consumes all levels; populates remediation action records

---

# A.4 — META-HARNESS (the orchestration / diagnostician layer)

## Mandate

The cross-agent intelligence layer. Reads the populated inventory graph from all agents and runs the correlation queries — toxic combinations, attack paths, blast radius. This is the agent that turns 17 agents' worth of isolated findings into connected attack-path intelligence.

## Scope boundary

- **Covers:** cross-agent correlation, toxic-combination detection, attack-path traversal, blast-radius computation, orchestration validation.
- **Does NOT cover:** detection (it consumes what the D/C agents discover) or remediation (A.1–A.3). The Meta-Harness reasons over the graph; it doesn't populate the base inventory.

## Tools

- Graph traversal engine (Postgres recursive CTEs now, Neo4j Cypher when scale demands)
- Pattern library (named toxic-combination queries)

## Nodes owned (canonical)

- **Toxic combination node** — `{pattern_name, severity, instances[], involved_nodes[], evidence[]}`
- **Attack path node** — `{source, target, hops[], evidence_per_hop[], exploitability_score}`
- **Blast radius record node** — `{seed_finding, reachable_nodes[], sensitivity_reached[]}`

## Nodes consumed (read-only across the entire graph)

- Every node and edge written by every other agent. The Meta-Harness is the universal consumer.

## Edges written

- `PART_OF_PATH`: Node → Attack path
- `CONTRIBUTES_TO`: Finding → Toxic combination
- `IN_BLAST_RADIUS`: Node → Blast radius record

## L-levels covered

- Consumes all L1–L6; produces the correlation layer that sits above all of them

---

# CONSOLIDATED OWNERSHIP MATRIX

| Node category                                                           | Canonical owner  | Key contributors                                 |
| ----------------------------------------------------------------------- | ---------------- | ------------------------------------------------ |
| AWS accounts, OUs                                                       | D.3              | all read                                         |
| Azure subscriptions, GCP projects                                       | D.5              | all read                                         |
| AWS cloud resources (compute, storage, db, network, secrets, messaging) | D.3              | D.1 (vulns), D.2 (access), D.4 (data), D.11 (AI) |
| Azure + GCP cloud resources                                             | D.5              | D.1, D.2, D.4, D.11                              |
| EKS/AKS/GKE cluster control plane                                       | D.3 / D.5        | D.6 (internals)                                  |
| Kubernetes cluster-internal objects                                     | D.6              | D.1 (image vulns), C.x Runtime (behavior)        |
| IAM/identity nodes (all clouds)                                         | D.2              | D.5/D.3 (raw data), D.10 (federation)            |
| Data classification nodes                                               | D.4              | D.5 (multi-cloud), D.11 (AI training data)       |
| CVE Finding nodes, SBOM packages                                        | D.1              | D.7 (exploit availability)                       |
| Container image nodes                                                   | D.1              | D.9 (build source), D.3 (deployment)             |
| Exploit availability, threat indicators                                 | D.7              | C.x Network (IOC matching)                       |
| Compliance requirements, frameworks                                     | D.8              | all detection agents (finding mappings)          |
| Code-side nodes (repo, commit, build, IaC)                              | D.9              | D.3/D.5 (deployment cross-ref)                   |
| SaaS tenant nodes                                                       | D.10             | D.2 (federation edges)                           |
| AI service nodes                                                        | D.11             | D.3/D.5 (underlying infra), D.4 (training data)  |
| Network path nodes, reachability edges                                  | C.x Network      | D.3/D.5 (network config source)                  |
| Network flow events (L6)                                                | C.x Network      | C.x Runtime (sensor-emitted)                     |
| Process / file / container events (L6)                                  | C.x Runtime      | —                                                |
| Authentication events (L6)                                              | D.2              | C.x Runtime (OS-level auth)                      |
| L5-runtime properties                                                   | C.x Runtime      | —                                                |
| Misconfiguration findings (AWS)                                         | D.3              | —                                                |
| Misconfiguration findings (Azure/GCP)                                   | D.5              | —                                                |
| Misconfiguration findings (K8s)                                         | D.6              | —                                                |
| SAST / IaC / secrets findings                                           | D.9              | —                                                |
| Remediation actions                                                     | A.1/A.2/A.3      | —                                                |
| Toxic combinations, attack paths, blast radius                          | A.4 Meta-Harness | consumes all                                     |

---

# THE CORE RULE, RESTATED

**Base infrastructure → D.3 (AWS) / D.5 (Azure, GCP).**
**Specialist layers → their domain agents** (D.2 identity, D.4 data, D.6 Kubernetes, D.9 code, D.10 SaaS, D.11 AI).
**Behavior → C.x agents** (network, runtime).
**Findings → whichever agent detected them.**
**Correlation → A.4 Meta-Harness.**
**Remediation → A.1/A.2/A.3.**

When two agents touch the same node, the canonical owner writes the node; the other contributes edges or annotates properties. No agent redefines a node it does not own.

---

# BUILD-STATUS LEGEND

| Agent                   | Status                               |
| ----------------------- | ------------------------------------ |
| D.1 Vulnerability       | Built v0.1                           |
| D.2 Identity            | Built v0.1                           |
| D.3 Cloud Posture (AWS) | Active, mid-cycle                    |
| D.4 Data Security       | Built v0.1                           |
| D.5 Multi-cloud Posture | Fixture mode (needs live connectors) |
| D.6 Kubernetes Posture  | Built v0.1                           |
| D.7 Threat Intelligence | Built v0.1                           |
| D.8 Compliance          | Built v0.1                           |
| D.9 AppSec              | **Unbuilt**                          |
| D.10 SSPM               | **Unbuilt**                          |
| D.11 AI-SPM             | **Unbuilt**                          |
| C.x Network             | Built v0.1                           |
| C.x Runtime             | Built v0.1 (sensor pipeline is v1.5) |
| A.1/A.2/A.3 Remediation | Partial (tiers incomplete)           |
| A.4 Meta-Harness        | Early (the diagnostician vision)     |
