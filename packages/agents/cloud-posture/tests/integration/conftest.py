"""Fixtures for LocalStack-backed integration tests.

The integration tests in this directory only run when both:

1. The `NEXUS_LIVE_LOCALSTACK=1` env var is set.
2. LocalStack is reachable at `localhost:4566` (override with
   `NEXUS_LOCALSTACK_URL`).

Otherwise they skip with a clear instruction so a clean `pytest` run does
not depend on Docker.

To bring LocalStack up:

    docker compose -f docker/docker-compose.dev.yml up -d localstack
    NEXUS_LIVE_LOCALSTACK=1 uv run pytest \\
        packages/agents/cloud-posture/tests/integration/ -v
"""

from __future__ import annotations

import os
import socket
from collections.abc import Iterator

import pytest

_LOCALSTACK_URL = os.environ.get("NEXUS_LOCALSTACK_URL", "http://localhost:4566").rstrip("/")


def _live_enabled() -> bool:
    return os.environ.get("NEXUS_LIVE_LOCALSTACK") == "1"


def _localstack_reachable() -> bool:
    host_port = _LOCALSTACK_URL.removeprefix("http://").removeprefix("https://")
    host, _, port_str = host_port.partition(":")
    try:
        with socket.create_connection((host, int(port_str or "4566")), timeout=1):
            return True
    except (OSError, ValueError):
        return False


@pytest.fixture(scope="session")
def localstack_endpoint() -> str:
    if not _live_enabled():
        pytest.skip(
            "set NEXUS_LIVE_LOCALSTACK=1 to enable; "
            "bring infra up with `docker compose -f docker/docker-compose.dev.yml "
            "up -d localstack`"
        )
    if not _localstack_reachable():
        pytest.skip(
            f"NEXUS_LIVE_LOCALSTACK=1 set but LocalStack at {_LOCALSTACK_URL} "
            "is unreachable (run `docker compose -f docker/docker-compose.dev.yml "
            "up -d localstack`)"
        )
    return _LOCALSTACK_URL


@pytest.fixture
def aws_env(monkeypatch: pytest.MonkeyPatch, localstack_endpoint: str) -> Iterator[None]:
    """Point boto3 at LocalStack with throwaway credentials."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.setenv("AWS_ENDPOINT_URL", localstack_endpoint)
    yield
