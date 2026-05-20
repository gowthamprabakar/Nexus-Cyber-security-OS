"""ControlEntity / FrameworkEntity models for the D.6 Compliance SemanticStore writer.

Per Q3/Q5 of the D.6 v0.1 plan, the agent ships two pydantic entity
models that mirror the framework + control structure of the bundled
YAML:

- ``FrameworkEntity`` — entity_type=``"framework"``; one per
  framework loaded (v0.1: just ``cis_aws_v3``). Properties carry the
  framework version + display name.
- ``ControlEntity`` — entity_type=``"control"``; one per CIS control
  in the library. Properties carry control id / name / level /
  applicability / required / paraphrased description / per-source-
  agent rule-id mappings.

These are **logical-layer** models — used by the ``kg_writer`` to
serialise into the ``SemanticStore.entities`` substrate. The
substrate's three-column composite key is
``(tenant_id, entity_type, external_id)`` per the F.3 KG-loop pattern;
``external_id`` is computed per-model below.

Q6 reminder: this module carries no PII and no verbatim CIS Benchmark
text. The ``description`` field is the paraphrased operator-summary
that ships in ``control_libraries/cis_aws_v3.yaml`` (Task 4).
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from compliance.schemas import ComplianceFramework, ControlLevel, ControlMapping


class FrameworkEntity(BaseModel):
    """One framework loaded by the agent (entity_type=``"framework"``).

    v0.1 ships a single framework per run (CIS_AWS_V3). v0.2 lifts
    this to multi-framework dispatch.
    """

    framework: ComplianceFramework
    version: str = Field(min_length=1)
    name: str = Field(min_length=1)

    @property
    def external_id(self) -> str:
        """Framework value is its own external_id (one entity per framework)."""
        return self.framework.value

    def properties(self) -> dict[str, Any]:
        """Serialise to the SemanticStore properties dict."""
        return {
            "framework": self.framework.value,
            "version": self.version,
            "name": self.name,
        }


class ControlEntity(BaseModel):
    """One CIS control in the active library (entity_type=``"control"``).

    The external_id is ``<framework>:<control_id>`` so v0.2's multi-
    framework dispatch can keep each framework's control namespace
    independent (e.g., CIS 1.1 vs SOC2 1.1).
    """

    framework: ComplianceFramework
    control_id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    level: ControlLevel
    required: bool = True
    applicability: list[str] = Field(default_factory=list)
    description: str = ""
    source_mappings: list[ControlMapping] = Field(default_factory=list)

    @property
    def external_id(self) -> str:
        return f"{self.framework.value}:{self.control_id}"

    def properties(self) -> dict[str, Any]:
        """Serialise to the SemanticStore properties dict.

        ``source_mappings`` is flattened to a list of
        ``{source_agent, source_rule_id, level, required}`` dicts so
        the SemanticStore JSON column carries something readable.
        """
        return {
            "framework": self.framework.value,
            "control_id": self.control_id,
            "name": self.name,
            "level": self.level.value,
            "required": self.required,
            "applicability": list(self.applicability),
            "description": self.description,
            "source_mappings": [
                {
                    "source_agent": m.source_agent,
                    "source_rule_id": m.source_rule_id,
                    "level": m.level.value,
                    "required": m.required,
                }
                for m in self.source_mappings
            ],
        }


__all__ = ["ControlEntity", "FrameworkEntity"]
