"""AWS AI-service discovery connector (D.11 AI-SPM PR2, operator Q1 cloud #1).

Reads an account's AI deployments — SageMaker endpoints / notebooks + Bedrock invocation
logging / guardrails — into a typed ``AwsAiInventory``. Posture *rules* over this inventory
live in :mod:`aispm.posture.aws`; this module only fetches + types.

Live reads sit behind a thin :class:`AwsAiReader` protocol (returning already-extracted
dicts); :func:`inventory_from_reader` is the pure parse, exercised with a fake reader
(canned data) in tests. The live ``_BotoAwsAiReader`` (real boto3) is the gated live path —
the kube/moto analogue: real parse logic, a stand-in for AWS. boto3 auth follows the charter
CredentialResolver contract (profile/region are source identifiers; no secret material).
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any, Protocol


class AwsAiReader(Protocol):
    """Source of already-extracted AWS-AI dicts — real boto3 client or fake."""

    def sagemaker_endpoints(self) -> list[dict[str, Any]]: ...
    def sagemaker_notebooks(self) -> list[dict[str, Any]]: ...
    def bedrock_logging_enabled(self) -> bool | None: ...
    def bedrock_guardrail_count(self) -> int: ...


@dataclass(frozen=True, slots=True)
class SageMakerEndpoint:
    name: str
    data_capture_enabled: bool | None  # inference logging
    kms_encrypted: bool | None
    network_isolated: bool | None
    model_name: str


@dataclass(frozen=True, slots=True)
class SageMakerNotebook:
    name: str
    direct_internet_access: bool | None


@dataclass(frozen=True, slots=True)
class AwsAiInventory:
    account_id: str
    region: str
    sagemaker_endpoints: tuple[SageMakerEndpoint, ...] = field(default_factory=tuple)
    sagemaker_notebooks: tuple[SageMakerNotebook, ...] = field(default_factory=tuple)
    bedrock_logging_enabled: bool | None = None
    bedrock_guardrail_count: int = 0
    degraded: tuple[dict[str, str], ...] = field(default_factory=tuple)


def inventory_from_reader(reader: AwsAiReader, *, account_id: str, region: str) -> AwsAiInventory:
    """Pure: build a typed :class:`AwsAiInventory` from a reader's extracted dicts."""
    endpoints = tuple(
        SageMakerEndpoint(
            name=str(e.get("name", "")),
            data_capture_enabled=e.get("data_capture_enabled"),
            kms_encrypted=e.get("kms_encrypted"),
            network_isolated=e.get("network_isolated"),
            model_name=str(e.get("model_name", "")),
        )
        for e in reader.sagemaker_endpoints()
        if e.get("name")
    )
    notebooks = tuple(
        SageMakerNotebook(
            name=str(n.get("name", "")), direct_internet_access=n.get("direct_internet_access")
        )
        for n in reader.sagemaker_notebooks()
        if n.get("name")
    )
    return AwsAiInventory(
        account_id=account_id,
        region=region,
        sagemaker_endpoints=endpoints,
        sagemaker_notebooks=notebooks,
        bedrock_logging_enabled=reader.bedrock_logging_enabled(),
        bedrock_guardrail_count=reader.bedrock_guardrail_count(),
    )


class _BotoAwsAiReader:
    """Live boto3-backed AwsAiReader (gated live path; NOT exercised in CI)."""

    def __init__(self, *, profile: str | None, region: str) -> None:
        import boto3

        session = boto3.Session(profile_name=profile, region_name=region)
        self._sm = session.client("sagemaker")
        self._br = session.client("bedrock")

    def sagemaker_endpoints(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for ep in self._sm.list_endpoints().get("Endpoints", []):
            name = ep.get("EndpointName", "")
            cfg_name = self._sm.describe_endpoint(EndpointName=name).get("EndpointConfigName", "")
            cfg = self._sm.describe_endpoint_config(EndpointConfigName=cfg_name) if cfg_name else {}
            data_capture = cfg.get("DataCaptureConfig") or {}
            variants = cfg.get("ProductionVariants") or []
            model_name = variants[0].get("ModelName", "") if variants else ""
            network_isolated: bool | None = None
            if model_name:
                model = self._sm.describe_model(ModelName=model_name)
                network_isolated = bool(model.get("EnableNetworkIsolation", False))
            out.append(
                {
                    "name": name,
                    "data_capture_enabled": bool(data_capture.get("EnableCapture", False)),
                    "kms_encrypted": bool(cfg.get("KmsKeyId")),
                    "network_isolated": network_isolated,
                    "model_name": model_name,
                }
            )
        return out

    def sagemaker_notebooks(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for nb in self._sm.list_notebook_instances().get("NotebookInstances", []):
            name = nb.get("NotebookInstanceName", "")
            detail = self._sm.describe_notebook_instance(NotebookInstanceName=name)
            dia = detail.get("DirectInternetAccess")  # "Enabled" | "Disabled"
            out.append(
                {"name": name, "direct_internet_access": (dia == "Enabled") if dia else None}
            )
        return out

    def bedrock_logging_enabled(self) -> bool | None:
        cfg = self._br.get_model_invocation_logging_configuration()
        logging_config = cfg.get("loggingConfig")
        return bool(logging_config) if logging_config is not None else False

    def bedrock_guardrail_count(self) -> int:
        return len(self._br.list_guardrails().get("guardrails", []))


async def read_aws_ai(
    *,
    account_id: str,
    region: str = "us-east-1",
    profile: str | None = None,
    reader: AwsAiReader | None = None,
) -> AwsAiInventory:
    """Read an account's AI deployments into a typed inventory. boto3 in a worker thread."""
    if reader is not None:
        return inventory_from_reader(reader, account_id=account_id, region=region)
    return await asyncio.to_thread(
        lambda: inventory_from_reader(
            _BotoAwsAiReader(profile=profile, region=region),
            account_id=account_id,
            region=region,
        )
    )


__all__ = [
    "AwsAiInventory",
    "AwsAiReader",
    "SageMakerEndpoint",
    "SageMakerNotebook",
    "inventory_from_reader",
    "read_aws_ai",
]
