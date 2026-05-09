# Version history

| Date       | Doc / package  | Version | Change                                                                                                             | Author    |
| ---------- | -------------- | ------- | ------------------------------------------------------------------------------------------------------------------ | --------- |
| 2026-05-08 | repo           | 0.1.0   | initial bootstrap (P0.1)                                                                                           | bootstrap |
| 2026-05-08 | charter        | 0.1.0   | scaffold                                                                                                           | bootstrap |
| 2026-05-08 | eval-framework | 0.1.0   | scaffold                                                                                                           | bootstrap |
| 2026-05-08 | docs/agents    | —       | PART1/3 archived; harness doc canonical                                                                            | bootstrap |
| 2026-05-08 | charter        | 0.1.0   | F.1 ships: contracts, budget, tools, workspace, audit chain, verifier, context manager, CLI, hello-world reference | F.1       |
| 2026-05-09 | cloud-posture  | 0.1.0   | F.3 Tasks 1–3: deps + Pydantic schemas + Prowler subprocess wrapper                                                | F.3       |
| 2026-05-09 | cloud-posture  | 0.1.0   | F.3 Task 4: AWS S3 describe tools (list_buckets, describe_bucket) with moto coverage                               | F.3       |
| 2026-05-09 | docs/decisions | —       | ADR-003 LLM provider strategy (tiered + abstracted + sovereign-capable)                                            | F.3       |
| 2026-05-09 | docs/decisions | —       | ADR-004 fabric layer (NATS JetStream, five buses, OCSF on the wire)                                                | F.3       |
| 2026-05-09 | docs/decisions | —       | ADR-005 async-by-default tool wrapper convention                                                                   | F.3       |
| 2026-05-09 | cloud-posture  | 0.1.0   | F.3 Task 4.5: async refactor of Prowler + S3 wrappers (per ADR-005)                                                | F.3       |
| 2026-05-09 | cloud-posture  | 0.1.0   | F.3 Task 5: AWS IAM analyzer (list_users_without_mfa, list_admin_policies)                                         | F.3       |
| 2026-05-09 | docs/plans     | —       | F.3 plan amended: status header + Tasks 4.5/5.5/6.5/8.5 inserted; Task 9 delta added (consume `charter.llm`)       | F.3       |
| 2026-05-09 | shared         | 0.1.0   | F.3 Task 5.5: fabric scaffolding (subjects, envelope, correlation_id) per ADR-004                                  | F.3       |
| 2026-05-09 | cloud-posture  | 0.1.0   | F.3 Task 6: customer-scoped Neo4j async knowledge-graph writer (UNWIND-batched relations)                          | F.3       |
| 2026-05-09 | cloud-posture  | 0.1.0   | F.3 Task 6.5: schemas.py refactored to OCSF v1.3 Compliance Finding (class_uid 2003) typing layer per ADR-004      | F.3       |
| 2026-05-09 | shared         | 0.1.0   | py.typed marker so mypy strict resolves cross-package types                                                        | F.3       |
