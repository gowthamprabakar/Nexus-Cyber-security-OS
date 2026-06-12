# Runbook — The Six Code-Level Invariants (investigation v0.2)

D.7 enforces **six** code-level invariants — three inherited from the D.13 LLM-agent template,
three NEW to the Orchestrator-Workers pattern (D.7 establishes them for D.12 / A.1 to inherit).
Each is a hard guard: a violation **raises**, never works around.

## Inherited from D.13 (the LLM-agent template)

| Invariant                 | Module                         | Raises when                                                                                          |
| ------------------------- | ------------------------------ | ---------------------------------------------------------------------------------------------------- |
| `assert_categorical_only` | `privacy/categorical.py`       | a narrative/hypothesis/plan carries plaintext PII/PAN/secret (WI-I8) — discuss by LABEL, never value |
| `assert_bounded_retry`    | `retry/bounded.py`             | LLM retry count exceeds 2 (WI-I10) — then the deterministic draft wins                               |
| `assert_findings_cited`   | `validation/evidence_cited.py` | a hypothesis cites a finding absent from the collected set                                           |

## NEW — the Orchestrator-Workers institutional set

| Invariant               | Module                         | Raises when                                                                                                     |
| ----------------------- | ------------------------------ | --------------------------------------------------------------------------------------------------------------- |
| `assert_worker_bounded` | `orchestrator_bounds.py`       | sub-investigation `depth > 3` or `parallel > 5` (H5 / WI-I11)                                                   |
| `assert_evidence_chain` | `validation/evidence_chain.py` | an `evidence_ref` is malformed (`<kind>:<id>`, kind ∈ audit_event/finding/entity) **or** dangling (H2 / WI-I12) |
| `assert_no_speculation` | `validation/no_speculation.py` | a hypothesis has **zero** evidence_refs — pure speculation (H1 / WI-I13)                                        |

## Layering (no-speculation → evidence-chain → findings-cited)

- `assert_no_speculation` is the **floor**: at least one citation must exist.
- `assert_evidence_chain` is **quality**: present links are well-formed and resolve.
- `assert_findings_cited` is the inherited **resolution** check against the collected set.

The live e2e gate (`test_investigation_live_e2e.py`) runs all six against real LLM output.
