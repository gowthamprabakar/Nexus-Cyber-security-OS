# `nexus-cloud-posture`

Cloud Posture Agent — agent **#1 of 18** for Nexus Cyber OS, and the **reference NLAH** that defines the pattern the other 17 follow ([ADR-007](../../../docs/_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md)).

## What it does

Scans AWS accounts for cloud-configuration issues that increase risk, using **Prowler 5.x** for breadth + **boto3-driven IAM enrichment** for primary-source evidence. Emits OCSF v1.3 Compliance Findings (`class_uid 2003`) wrapped with a `NexusEnvelope` (correlation_id, tenant_id, agent_id, model_pin, charter_invocation_id), a markdown summary, and an append-only hash-chained audit log. Optionally upserts assets + findings into the customer's Neo4j knowledge graph.

Every action runs through the [runtime charter](../../charter/) — execution contract, per-dimension budget envelope, tool whitelist, audit chain — so the agent cannot exceed its sanctioned scope.

## Quick start

```bash
# 1. Run the local eval suite (10/10 should pass)
uv run cloud-posture eval packages/agents/cloud-posture/eval/cases

# 2. Validate an ExecutionContract YAML
uv run charter validate path/to/contract.yaml

# 3. Run against a real AWS account (see runbooks/aws_dev_account_smoke.md)
uv run cloud-posture run \
    --contract path/to/contract.yaml \
    --aws-account-id 111122223333 \
    --aws-region us-east-1
```

## Inputs

A signed `ExecutionContract` (YAML) — schema defined by [`nexus-charter`](../../charter/). Required: budget envelope, permitted-tools whitelist, workspace + persistent_root paths, completion_condition, ULID `delegation_id`.

## Outputs

Three files in the charter-managed workspace:

| File            | Shape                                                                                                                                    | Purpose                                               |
| --------------- | ---------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------- |
| `findings.json` | `FindingsReport` ([schemas.py](src/cloud_posture/schemas.py)) — list of OCSF v1.3 Compliance Finding dicts wrapped with `nexus_envelope` | Wire format on the future `findings.>` fabric subject |
| `summary.md`    | Markdown digest grouped by severity (Critical → High → Medium → Low → Info)                                                              | Human-readable for SREs / auditors                    |
| `audit.jsonl`   | Append-only hash chain of every charter event                                                                                            | Verified by `uv run charter audit verify`             |

## Architecture

```
ExecutionContract (YAML)
    │
    ▼
┌──────────────────────────────────────────────────────────────┐
│ Charter context manager                                      │
│   - workspace setup                                          │
│   - per-dimension budget envelope (llm_calls / tokens /      │
│     wall_clock_sec / cloud_api_calls / mb_written)           │
│   - tool registry (whitelist + version-pinned)               │
│   - hash-chained audit log                                   │
│   - current_charter() contextvar (LLM providers attach here) │
└─────────────────────────────┬────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────┐
│ async run(contract, *, llm_provider=None, neo4j_driver=None) │
│                                                              │
│  1.  await ctx.call_tool("prowler_scan", ...)                │
│  2.  asyncio.TaskGroup:                                      │
│         await ctx.call_tool("aws_iam_list_users_without_mfa")│
│         await ctx.call_tool("aws_iam_list_admin_policies")   │
│  3.  build_finding(...)  →  CloudPostureFinding (OCSF 2003)  │
│         each wrapped with a fresh NexusEnvelope              │
│  4.  (optional) UNWIND-batched KG upsert                     │
│  5.  ctx.write_output("findings.json", ...)                  │
│      ctx.write_output("summary.md", render_summary(report))  │
│  6.  ctx.assert_complete()                                   │
└──────────────────────────────────────────────────────────────┘
```

### Tools

| Tool                                      | Source                                                                                                         | Cost (cloud-API calls) |
| ----------------------------------------- | -------------------------------------------------------------------------------------------------------------- | ---------------------- |
| `prowler_scan`                            | [`tools/prowler.py`](src/cloud_posture/tools/prowler.py) — async subprocess wrapper around the Prowler 5.x CLI | 200                    |
| `aws_s3_list_buckets` / `aws_s3_describe` | [`tools/aws_s3.py`](src/cloud_posture/tools/aws_s3.py) — async via `asyncio.to_thread(boto3.client(...))`      | 1 / 6                  |
| `aws_iam_list_users_without_mfa`          | [`tools/aws_iam.py`](src/cloud_posture/tools/aws_iam.py)                                                       | 10                     |
| `aws_iam_list_admin_policies`             | detects `Action="*"` `Resource="*"` on customer-managed policies                                               | 10                     |
| `kg_upsert_asset` / `kg_upsert_finding`   | [`tools/neo4j_kg.py`](src/cloud_posture/tools/neo4j_kg.py) — customer-scoped, UNWIND-batched                   | 0                      |

All tools are async by default per [ADR-005](../../../docs/_meta/decisions/ADR-005-async-tool-wrapper-convention.md).

### LLM provider plumbing

The driver accepts an optional `LLMProvider` argument so the same call signature serves Investigation / Synthesis agents that _do_ drive their loops via LLM. The v0.1 Cloud Posture flow is **deterministic** — Prowler + IAM + OCSF emission, no model in the loop, per the NLAH out-of-scope clause.

When the LLM is wired (Investigation / Synthesis / Meta-Harness), it goes through [`charter.llm.LLMProvider`](../../charter/src/charter/llm.py) — supports Anthropic, OpenAI, vLLM-local, Ollama, and any OpenAI-compatible endpoint per [ADR-006](../../../docs/_meta/decisions/ADR-006-openai-compatible-provider.md). Configure via `NEXUS_LLM_*` env vars; see [`cloud_posture.llm`](src/cloud_posture/llm.py) for the adapter.

## NLAH (the agent's domain brain)

The natural-language harness lives at [`src/cloud_posture/nlah/`](src/cloud_posture/nlah/) and ships with the wheel:

- [`README.md`](src/cloud_posture/nlah/README.md) — mission, severity rubric, reasoning style, failure modes, self-evolution boundary
- [`tools.md`](src/cloud_posture/nlah/tools.md) — tool index for the LLM, with cost / when / failure notes
- [`examples/`](src/cloud_posture/nlah/examples/) — two OCSF-shaped few-shot examples (public S3 bucket, over-privileged IAM policy)

Loaded via `cloud_posture.nlah_loader.load_system_prompt()`.

## Eval suite

Local placeholder until [F.2 eval-framework](../../../docs/superpowers/plans/2026-05-08-build-roadmap.md) ships:

```bash
uv run cloud-posture eval packages/agents/cloud-posture/eval/cases
# → 10/10 passed
```

Ten representative cases cover four critical / four high / two medium severities across six OCSF resource types (S3 / RDS / EC2 / CloudTrail / KMS / IAM). See [`eval/README.md`](eval/README.md) for the case schema, the rationale for each case, and the Phase-1 trajectory toward ≥ 100 cases.

## Tests

```bash
# Unit tests (mocked external services)
uv run pytest packages/agents/cloud-posture/

# LocalStack integration tests (opt in)
docker compose -f docker/docker-compose.dev.yml up -d localstack
NEXUS_LIVE_LOCALSTACK=1 uv run pytest \
    packages/agents/cloud-posture/tests/integration/

# Live LLM (charter-side; opt in)
NEXUS_LIVE_OLLAMA=1 uv run pytest \
    packages/charter/tests/integration/
```

## Runbooks

- [`runbooks/aws_dev_account_smoke.md`](runbooks/aws_dev_account_smoke.md) — manual smoke against a real AWS dev account before any customer-facing release.

## License

Business Source License 1.1. Production use requires a commercial license. The runtime charter ([`packages/charter/`](../../charter/)) and the eval-framework ([`packages/eval-framework/`](../../eval-framework/)) are Apache 2.0.

## See also

- [F.3 build plan with execution status](../../../docs/superpowers/plans/2026-05-08-f-3-cloud-posture-reference-nlah.md)
- [ADR-007 — Cloud Posture as the reference NLAH](../../../docs/_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md)
- [ADR-004 — fabric layer (OCSF wire format)](../../../docs/_meta/decisions/ADR-004-fabric-layer.md)
- [ADR-005 — async tool wrapper convention](../../../docs/_meta/decisions/ADR-005-async-tool-wrapper-convention.md)
- [Runtime charter](../../charter/)
- [Build roadmap (master plan-of-plans)](../../../docs/superpowers/plans/2026-05-08-build-roadmap.md)
- [System readiness snapshot](../../../docs/_meta/system-readiness.md)
