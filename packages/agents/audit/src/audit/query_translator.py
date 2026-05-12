"""NL → typed `AuditStore.query` parameters via `charter.llm_adapter`.

F.6 Task 11. The only LLM-using surface in the Audit Agent. Operators
ask the CLI in natural language ("show me every entity upsert for
tenant X in the last 24 hours"); this module converts that into a
typed `AuditQueryArgs` shape the driver feeds into `AuditStore.query`.

ADR-007 v1.1 conformance: no per-agent `llm.py`. The translator calls
the `LLMProvider` protocol directly (which agents construct via
`charter.llm_adapter.make_provider`).

Three safety properties:

1. **Tenant pivot is impossible.** `AuditQueryArgs.tenant_id` is stamped
   from the caller, NOT from the LLM's JSON output. Defence in depth
   on top of Postgres RLS.
2. **Malformed LLM output is non-fatal.** A non-JSON response, a
   refusal ("I'm sorry, I can't…"), or invalid field types degrade to
   the everything-for-tenant query rather than raising. NL phrasing is
   a UX nicety; the structured-flag-only path always works.
3. **LLM unavailable is non-fatal.** Passing `provider=None` skips the
   LLM call entirely and returns the everything-for-tenant query. This
   is how the CLI's `--no-llm` flag is plumbed through.

The LLM is prompted via the NLAH bundle (`audit.nlah_loader.load_system_prompt`)
which lists the four canonical action names and the expected JSON shape.
"""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime
from typing import Any

from charter.llm import LLMProvider
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from audit.nlah_loader import load_system_prompt

_LOG = logging.getLogger(__name__)

# Match an optional ```json ... ``` fence or a bare JSON object. We're
# permissive on the open fence — LLMs sometimes write ```json or ``` JSON
# or just ```.
_FENCE_RE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL | re.IGNORECASE)

# Default model_pin for v0.1 — small enough to be fast on Anthropic / OpenAI;
# the deployment's `LLMConfig.model_pin` overrides for production.
_DEFAULT_MODEL_PIN = "claude-haiku-4-5-20251001"

_MAX_TOKENS = 256


class AuditQueryArgs(BaseModel):
    """Typed parameters extracted from a natural-language query.

    Mirrors the kwargs of `AuditStore.query` so the agent driver can
    `**args.model_dump(exclude_none=True)` straight through.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    tenant_id: str = Field(min_length=26, max_length=26)
    since: datetime | None = None
    until: datetime | None = None
    action: str | None = None
    agent_id: str | None = None
    correlation_id: str | None = None


async def translate_nl_query(
    *,
    nl: str,
    tenant_id: str,
    provider: LLMProvider | None,
) -> AuditQueryArgs:
    """Parse a natural-language audit query into typed `AuditStore.query` args.

    Returns the everything-for-tenant query when `provider is None` or
    when the LLM's response cannot be parsed.
    """
    if provider is None:
        return AuditQueryArgs(tenant_id=tenant_id)

    try:
        response = await provider.complete(
            prompt=_build_prompt(nl=nl, tenant_id=tenant_id),
            system=load_system_prompt(),
            model_pin=_DEFAULT_MODEL_PIN,
            max_tokens=_MAX_TOKENS,
            temperature=0.0,
        )
    except Exception as exc:
        _LOG.warning("LLM call failed; falling back to tenant-only query: %s", exc)
        return AuditQueryArgs(tenant_id=tenant_id)

    parsed = _parse_response(response.text)
    if parsed is None:
        return AuditQueryArgs(tenant_id=tenant_id)

    # Force the caller-supplied tenant — the LLM cannot pivot across tenants.
    parsed["tenant_id"] = tenant_id

    return _build_args(parsed, tenant_id=tenant_id)


def _build_prompt(*, nl: str, tenant_id: str) -> str:
    return (
        "Translate the operator's natural-language audit query into a JSON "
        "object whose keys are a subset of: action, agent_id, "
        "correlation_id, since, until.\n"
        "- `since` and `until` are ISO-8601 datetimes in UTC.\n"
        "- `action` is one of: episode_appended, playbook_published, "
        "entity_upserted, relationship_added (or any other action the "
        "operator names verbatim).\n"
        "- `agent_id` is the agent that emitted the action.\n"
        "- Omit fields that the operator did not constrain.\n"
        "- Do not include `tenant_id` — that is stamped by the system.\n"
        "Respond with the JSON object only, no prose.\n\n"
        f"Tenant context: {tenant_id}\n"
        f"Operator query: {nl}\n"
    )


def _parse_response(text: str) -> dict[str, Any] | None:
    """Return the parsed JSON object or None if the response can't be parsed."""
    stripped = text.strip()
    if not stripped:
        return None

    # 1. Try fence extraction.
    match = _FENCE_RE.search(stripped)
    candidate = match.group(1) if match else stripped

    try:
        parsed = json.loads(candidate)
    except json.JSONDecodeError:
        return None

    if not isinstance(parsed, dict):
        return None
    return parsed


def _build_args(parsed: dict[str, Any], *, tenant_id: str) -> AuditQueryArgs:
    """Build `AuditQueryArgs`, dropping fields that fail validation.

    Per the production contract, a single bad field doesn't poison the
    rest. We drop offending fields and retry until either the model
    validates or only `tenant_id` remains.
    """
    candidate: dict[str, Any] = {"tenant_id": tenant_id}
    for key in ("action", "agent_id", "correlation_id", "since", "until"):
        if key not in parsed or parsed[key] is None:
            continue
        candidate[key] = parsed[key]
        try:
            AuditQueryArgs(**candidate)
        except ValidationError:
            candidate.pop(key)

    return AuditQueryArgs(**candidate)


__all__ = ["AuditQueryArgs", "translate_nl_query"]
