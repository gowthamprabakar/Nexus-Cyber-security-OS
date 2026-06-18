"""Tests for the AWS AI-discovery connector parse (D.11 PR2)."""

from __future__ import annotations

from typing import Any

from aispm.tools.aws_ai import inventory_from_reader


class _FakeAwsAiReader:
    def __init__(
        self,
        *,
        endpoints: list[dict[str, Any]] | None = None,
        notebooks: list[dict[str, Any]] | None = None,
        bedrock_logging: bool | None = True,
        guardrails: int = 1,
    ) -> None:
        self._e = endpoints or []
        self._n = notebooks or []
        self._log = bedrock_logging
        self._g = guardrails

    def sagemaker_endpoints(self) -> list[dict[str, Any]]:
        return self._e

    def sagemaker_notebooks(self) -> list[dict[str, Any]]:
        return self._n

    def bedrock_logging_enabled(self) -> bool | None:
        return self._log

    def bedrock_guardrail_count(self) -> int:
        return self._g


def test_parses_endpoints_notebooks_and_bedrock() -> None:
    reader = _FakeAwsAiReader(
        endpoints=[
            {
                "name": "prod",
                "data_capture_enabled": False,
                "kms_encrypted": False,
                "network_isolated": False,
                "model_name": "m1",
            },
            {"name": ""},  # skipped (no name)
        ],
        notebooks=[{"name": "nb1", "direct_internet_access": True}],
        bedrock_logging=False,
        guardrails=0,
    )
    inv = inventory_from_reader(reader, account_id="111122223333", region="us-east-1")

    assert inv.account_id == "111122223333"
    assert [e.name for e in inv.sagemaker_endpoints] == ["prod"]
    assert inv.sagemaker_endpoints[0].data_capture_enabled is False
    assert inv.sagemaker_endpoints[0].model_name == "m1"
    assert [n.name for n in inv.sagemaker_notebooks] == ["nb1"]
    assert inv.sagemaker_notebooks[0].direct_internet_access is True
    assert inv.bedrock_logging_enabled is False
    assert inv.bedrock_guardrail_count == 0


def test_tristate_unknowns_preserved() -> None:
    reader = _FakeAwsAiReader(
        endpoints=[{"name": "x"}],  # all posture fields absent → None
        bedrock_logging=None,  # unreadable
    )
    inv = inventory_from_reader(reader, account_id="111122223333", region="us-east-1")
    ep = inv.sagemaker_endpoints[0]
    assert ep.data_capture_enabled is None
    assert ep.kms_encrypted is None
    assert ep.network_isolated is None
    assert inv.bedrock_logging_enabled is None
