"""Knowledge graph writer (Neo4j async). Every node is customer-scoped.

Per ADR-005 the writer is async-by-default and consumes the neo4j async driver
(`neo4j.AsyncDriver`). Per the per-tenant isolation requirement (ADR-004,
platform_architecture §4.3), every MERGE constrains by customer_id so cross-
tenant data never co-mingles in a single Cypher round-trip.
"""

from __future__ import annotations

from typing import Any

# neo4j ships type stubs but the async driver shape varies across minor
# versions; treating the driver as Any keeps the writer decoupled from
# upstream type churn while the protocol below documents the contract.

_UPSERT_ASSET_CYPHER = (
    "MERGE (a:Asset {customer_id: $customer_id, kind: $kind, "
    "external_id: $external_id}) "
    "SET a += $properties"
)

_UPSERT_FINDING_CYPHER = (
    "MERGE (f:Finding {customer_id: $customer_id, finding_id: $finding_id}) "
    "SET f.rule_id = $rule_id, f.severity = $severity"
)

_RELATE_FINDING_CYPHER = (
    "MATCH (f:Finding {customer_id: $customer_id, finding_id: $finding_id}) "
    "UNWIND $arns AS arn "
    "MERGE (a:Asset {customer_id: $customer_id, external_id: arn}) "
    "MERGE (f)-[:AFFECTS]->(a)"
)


class KnowledgeGraphWriter:
    """Customer-scoped Neo4j writer for assets + findings + relations.

    Caller owns the driver lifecycle (connect/close); the writer just runs
    Cypher inside short-lived sessions.
    """

    def __init__(self, driver: Any, customer_id: str) -> None:
        self._driver = driver
        self._customer_id = customer_id

    async def upsert_asset(self, kind: str, external_id: str, properties: dict[str, Any]) -> None:
        async with self._driver.session() as s:
            await s.run(
                _UPSERT_ASSET_CYPHER,
                customer_id=self._customer_id,
                kind=kind,
                external_id=external_id,
                properties=properties,
            )

    async def upsert_finding(
        self,
        finding_id: str,
        rule_id: str,
        severity: str,
        affected_arns: list[str],
    ) -> None:
        async with self._driver.session() as s:
            await s.run(
                _UPSERT_FINDING_CYPHER,
                customer_id=self._customer_id,
                finding_id=finding_id,
                rule_id=rule_id,
                severity=severity,
            )
            if not affected_arns:
                return
            await s.run(
                _RELATE_FINDING_CYPHER,
                customer_id=self._customer_id,
                finding_id=finding_id,
                arns=affected_arns,
            )
