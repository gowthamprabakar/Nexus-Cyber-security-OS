# Version history

| Date       | Doc / package  | Version | Change                                                                                                               | Author    |
| ---------- | -------------- | ------- | -------------------------------------------------------------------------------------------------------------------- | --------- |
| 2026-05-08 | repo           | 0.1.0   | initial bootstrap (P0.1)                                                                                             | bootstrap |
| 2026-05-08 | charter        | 0.1.0   | scaffold                                                                                                             | bootstrap |
| 2026-05-08 | eval-framework | 0.1.0   | scaffold                                                                                                             | bootstrap |
| 2026-05-08 | docs/agents    | —       | PART1/3 archived; harness doc canonical                                                                              | bootstrap |
| 2026-05-08 | charter        | 0.1.0   | F.1 ships: contracts, budget, tools, workspace, audit chain, verifier, context manager, CLI, hello-world reference   | F.1       |
| 2026-05-09 | cloud-posture  | 0.1.0   | F.3 Tasks 1–3: deps + Pydantic schemas + Prowler subprocess wrapper                                                  | F.3       |
| 2026-05-09 | cloud-posture  | 0.1.0   | F.3 Task 4: AWS S3 describe tools (list_buckets, describe_bucket) with moto coverage                                 | F.3       |
| 2026-05-09 | docs/decisions | —       | ADR-003 LLM provider strategy (tiered + abstracted + sovereign-capable)                                              | F.3       |
| 2026-05-09 | docs/decisions | —       | ADR-004 fabric layer (NATS JetStream, five buses, OCSF on the wire)                                                  | F.3       |
| 2026-05-09 | docs/decisions | —       | ADR-005 async-by-default tool wrapper convention                                                                     | F.3       |
| 2026-05-09 | cloud-posture  | 0.1.0   | F.3 Task 4.5: async refactor of Prowler + S3 wrappers (per ADR-005)                                                  | F.3       |
| 2026-05-09 | cloud-posture  | 0.1.0   | F.3 Task 5: AWS IAM analyzer (list_users_without_mfa, list_admin_policies)                                           | F.3       |
| 2026-05-09 | docs/plans     | —       | F.3 plan amended: status header + Tasks 4.5/5.5/6.5/8.5 inserted; Task 9 delta added (consume `charter.llm`)         | F.3       |
| 2026-05-09 | shared         | 0.1.0   | F.3 Task 5.5: fabric scaffolding (subjects, envelope, correlation_id) per ADR-004                                    | F.3       |
| 2026-05-09 | cloud-posture  | 0.1.0   | F.3 Task 6: customer-scoped Neo4j async knowledge-graph writer (UNWIND-batched relations)                            | F.3       |
| 2026-05-09 | cloud-posture  | 0.1.0   | F.3 Task 6.5: schemas.py refactored to OCSF v1.3 Compliance Finding (class_uid 2003) typing layer per ADR-004        | F.3       |
| 2026-05-09 | shared         | 0.1.0   | py.typed marker so mypy strict resolves cross-package types                                                          | F.3       |
| 2026-05-09 | docs/\_meta    | —       | system-readiness.md — Phase 1a Week 2 snapshot: 110 tests, 9/16 F.3 tasks shipped, weighted Wiz coverage ~1.25%      | F.3       |
| 2026-05-09 | cloud-posture  | 0.1.0   | F.3 Task 7: findings → markdown summarizer (consumes OCSF via CloudPostureFinding wrapper)                           | F.3       |
| 2026-05-09 | cloud-posture  | 0.1.0   | F.3 Task 8: NLAH (domain brain) + tools reference + 2 OCSF-shaped few-shot examples + loader                         | F.3       |
| 2026-05-09 | charter        | 0.1.0   | F.3 Task 8.5: LLMProvider Protocol + AnthropicProvider per ADR-003; current_charter() contextvar                     | F.3       |
| 2026-05-09 | docs/decisions | —       | ADR-006 — one OpenAICompatibleProvider subsumes vLLM, Ollama, OpenAI, OpenRouter, Together, Fireworks, Groq, etc.    | F.3       |
| 2026-05-09 | charter        | 0.1.0   | charter.llm_openai_compat: OpenAICompatibleProvider with for_vllm_local() / for_ollama() convenience constructors    | F.3       |
| 2026-05-09 | cloud-posture  | 0.1.0   | F.3 Task 9: LLM adapter — LLMConfig + make*provider + config_from_env (5 providers, NEXUS_LLM*\* env vars)           | F.3       |
| 2026-05-09 | charter        | 0.1.0   | py.typed marker so cross-package imports resolve under mypy strict                                                   | F.3       |
| 2026-05-09 | charter        | 0.1.0   | live integration tests against Ollama qwen3:4b (skipped by default; opt in with NEXUS_LIVE_OLLAMA=1)                 | F.3       |
| 2026-05-09 | cloud-posture  | 0.1.0   | F.3 Task 10: agent driver — async run() wires charter + tools + OCSF schemas + summarizer + optional Neo4j KG        | F.3       |
| 2026-05-10 | cloud-posture  | 0.1.0   | F.3 Task 11: LocalStack-backed integration tests for IAM no-MFA + admin policy + clean account                       | F.3       |
| 2026-05-10 | cloud-posture  | 0.1.0   | F.3 Task 12: minimal local eval runner + 10 representative cases (10/10 passing); F.2 placeholder                    | F.3       |
| 2026-05-10 | cloud-posture  | 0.1.0   | F.3 Task 13: CLI — `cloud-posture eval CASES_DIR` + `cloud-posture run --contract path.yaml`                         | F.3       |
| 2026-05-10 | cloud-posture  | 0.1.0   | F.3 Task 14: AWS dev-account smoke runbook (`runbooks/aws_dev_account_smoke.md`); gates live-tested                  | F.3       |
| 2026-05-10 | cloud-posture  | 0.1.0   | F.3 Task 15: package README + ADR-007 (Cloud Posture as the reference NLAH for the other 17 agents)                  | F.3       |
| 2026-05-10 | docs/decisions | —       | ADR-007 — Cloud Posture canonical for charter context / async tools / OCSF / NLAH layout / LLM plumbing / eval shape | F.3       |
| 2026-05-10 | cloud-posture  | 0.1.0   | F.3 Task 16: final verification — 4/6 gates green (94 tests, 96.09% cov, ruff/mypy clean, audit valid)               | F.3       |
| 2026-05-10 | docs/\_meta    | —       | f3-verification-2026-05-10.md — F.3 accepted as code-complete; gate-by-gate record                                   | F.3       |
| 2026-05-10 | docs/\_meta    | —       | system-readiness re-issued (2026-05-10): 203 tests, 96% cov, 7 ADRs, weighted Wiz ~6.7% (CSPM at 30% of weight)      | F.3       |
| 2026-05-10 | docs/plans     | —       | F.2 Eval Framework v0.1 plan written (16 tasks; runner Protocol + suite + gates + comparison + CLI)                  | F.2       |
| 2026-05-10 | docs/plans     | —       | build-roadmap updated to link the F.2 plan and mark F.3 ✅ code-complete                                             | F.2       |
| 2026-05-10 | eval-framework | 0.1.0   | F.2 Task 1: bootstrap apache-2.0 package skeleton (pyproject, py.typed, cli stub)                                    | F.2       |
| 2026-05-10 | eval-framework | 0.1.0   | F.2 Task 2: typed pydantic models — EvalCase / EvalResult / SuiteResult / EvalTrace; 19 tests                        | F.2       |
| 2026-05-10 | eval-framework | 0.1.0   | F.2 Task 3: YAML loader — `load_case_file` + `load_cases`; loads cloud-posture suite unchanged; 11 new tests         | F.2       |
| 2026-05-10 | eval-framework | 0.1.0   | F.2 Task 4: EvalRunner Protocol (@runtime_checkable) + FakeRunner test double; 8 tests                               | F.2       |
| 2026-05-10 | eval-framework | 0.1.0   | F.2 Task 5: async `run_suite()` — per-case workspace + per-case timeout + ULID suite_id; 18 new tests                | F.2       |
