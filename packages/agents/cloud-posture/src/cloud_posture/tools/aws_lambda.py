"""Lambda function inventory + internet-exposure reader (Cycle 6 — serverless Lambda exposure).

Reads Lambda functions, flags ``is_public`` when the function has a public URL
(``AuthType=NONE``) or a resource policy with a wildcard-principal Allow, and resolves
the execution role ARN. The join key into the identity graph is the execution role ARN
— the Lambda analogue of an ECS task role.

Two ``is_public`` signals:
1. **Function URL** — ``get_function_url_config`` returns ``AuthType == "NONE"``. If the
   function has no URL (ResourceNotFoundException), falls back to the policy check.
2. **Resource policy** — ``get_policy`` JSON contains a Statement with ``Effect=Allow``
   and ``Principal`` == ``"*"`` or ``{"AWS": "*"}``. If no policy exists
   (ResourceNotFoundException), the function is not policy-public.

Plain boto3 reader: inject ``lam`` + ``iam`` clients so the reader runs against real
AWS or in-process moto identically.

Honest limit: Lambda is NOT a scanned container image in this slice — ``RUNS_IMAGE``
join does not apply here.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class LambdaWorkload:
    """A Lambda function resolved to its ARN, internet-exposure flag, and execution role."""

    function_arn: str
    is_public: bool
    role_arn: str = ""


def _is_wildcard_principal(principal: Any) -> bool:
    """True if principal is ``"*"`` or ``{"AWS": "*"}``."""
    if principal == "*":
        return True
    if isinstance(principal, dict):
        aws = principal.get("AWS")
        if aws == "*":
            return True
        # list form: e.g. {"AWS": ["*"]}
        if isinstance(aws, list) and "*" in aws:
            return True
    return False


def _policy_is_public(policy_json: str) -> bool:
    """True if any Statement has Effect=Allow and a wildcard principal."""
    try:
        doc = json.loads(policy_json)
    except (ValueError, TypeError):
        return False
    for stmt in doc.get("Statement", []):
        if stmt.get("Effect") != "Allow":
            continue
        principal = stmt.get("Principal")
        if _is_wildcard_principal(principal):
            return True
    return False


def _function_is_public(lam: object, function_name: str) -> bool:
    """Return True if the function has a public URL (AuthType=NONE) or a wildcard resource policy."""
    # Signal 1: Function URL with AuthType=NONE
    try:
        url_cfg = lam.get_function_url_config(FunctionName=function_name)  # type: ignore[attr-defined]
        if url_cfg.get("AuthType") == "NONE":
            return True
        # URL exists but uses IAM auth — not public via URL; fall through to policy check
    except Exception as exc:
        exc_name = type(exc).__name__
        if "ResourceNotFoundException" not in exc_name and "ResourceNotFound" not in exc_name:
            # Unexpected error — treat as not public (safe default)
            pass
        # No URL configured; fall through to policy check

    # Signal 2: Resource policy with wildcard Allow
    try:
        policy_resp = lam.get_policy(FunctionName=function_name)  # type: ignore[attr-defined]
        policy_json = policy_resp.get("Policy", "")
        if policy_json and _policy_is_public(policy_json):
            return True
    except Exception as exc:
        exc_name = type(exc).__name__
        if "ResourceNotFoundException" not in exc_name and "ResourceNotFound" not in exc_name:
            pass
        # No policy — not policy-public

    return False


def read_lambda_workloads(lam: object, iam: object) -> list[LambdaWorkload]:
    """Enumerate Lambda functions as ``LambdaWorkload`` rows (exposure + execution role).

    Calls ``list_functions()`` and for each function determines:
    - ``is_public`` via :func:`_function_is_public` (URL AuthType=NONE OR wildcard policy)
    - ``role_arn`` from the function's ``Role`` field (the execution role ARN)
    """
    workloads: list[LambdaWorkload] = []
    resp: dict[str, Any] = lam.list_functions()  # type: ignore[attr-defined]
    functions: list[dict[str, Any]] = resp.get("Functions", [])
    for fn in functions:
        function_name: str = fn.get("FunctionName", "")
        function_arn: str = fn.get("FunctionArn", "")
        role_arn: str = fn.get("Role", "")
        if not function_arn:
            continue
        is_public = _function_is_public(lam, function_name)
        workloads.append(
            LambdaWorkload(
                function_arn=function_arn,
                is_public=is_public,
                role_arn=role_arn,
            )
        )
    return workloads


__all__ = ["LambdaWorkload", "read_lambda_workloads"]
