"""LLM-driven skill compositor — Task 7 of A.4 v0.2.

A.4 Meta-Harness's **first LLM consumer**. Composes a candidate
``SKILL.md`` from a ``SkillTrigger`` (Task 6 output) via
``charter.llm.LLMProvider``, parses the response with
``skill_format.parse_skill_md_content`` (Task 3), normalises trust-
boundary frontmatter fields, and writes the result to the shadow path
``<workspace>/.nexus/candidate-skills/<agent>/<category>/<skill>/SKILL.md``
(Q1 of the v0.2 plan).

Trust boundary: **frontmatter fields the LLM is NOT trusted to set are
overridden post-parse:**

* ``target_agent`` — comes from the trigger, not the LLM (prevents the
  LLM from misrouting candidates to a different agent).
* ``created_by`` — pinned to ``meta_harness@v0.2.0``.
* ``deployment_status`` — forced to ``CANDIDATE`` (eval-gate hasn't
  run yet).
* ``eval_gate_status`` — forced to ``NOT_RUN``.
* ``provenance`` — derived from the trigger's ``audit_entry_hashes``
  paired with the audit-log path supplied by the driver.

The LLM is trusted for: ``name``, ``description``, ``version``,
``platforms``, ``category``, ``body``. Validation happens at parse
time via ``skill_format.parse_skill_md_content``; validation failures
raise ``SkillWriterError``.

**Stub-LLM byte-equal probe (WI-3).** Identical ``SkillTrigger`` +
identical ``FakeLLMProvider`` response → identical SKILL.md bytes on
disk. Required for Task 15's stub-response fixtures and the Task 16
verification record.
"""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from charter.llm import LLMProvider

from meta_harness.schemas import (
    SkillCandidate,
    SkillDeploymentStatus,
    SkillEvalGateStatus,
)
from meta_harness.skill_candidate_store import write_candidate_meta
from meta_harness.skill_format import (
    SkillFormatError,
    parse_skill_md_content,
    write_skill_md,
)
from meta_harness.skill_triggers import SkillTrigger

#: Default model_pin for skill composition. Workhorse tier — composition
#: is well-shaped and doesn't need frontier capability.
DEFAULT_SKILL_WRITER_MODEL_PIN = "claude-sonnet-4-6"

#: Default max_tokens for the composition call. Generous since SKILL.md
#: bodies can run a few KB.
DEFAULT_SKILL_WRITER_MAX_TOKENS = 4_000

#: Pinned `created_by` for v0.2 — every skill A.4 v0.2 emits carries
#: this exact value so the verification record can assert provenance.
_CREATED_BY = "meta_harness@v0.2.0"

#: Path-component validation: skill_id components must be slug-safe.
_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9_-]*$")

_SYSTEM_PROMPT = """You compose Nexus skills from successful agent traces.

Output a single SKILL.md file in the agentskills.io format — YAML
frontmatter between '---' fences, then a markdown body capturing the
reusable procedural pattern.

Required frontmatter keys: name, description, version, platforms,
target_agent, category, created_by. Optional: provenance.

Output the raw SKILL.md content only — no preamble, no explanation,
no code fences around the YAML."""


class SkillWriterError(RuntimeError):
    """Raised when the LLM-produced SKILL.md cannot be promoted to a
    ``SkillCandidate`` — malformed frontmatter, slug-unsafe identifiers,
    or trust-boundary violations the parser detects."""


def compose_skill_prompt(trigger: SkillTrigger) -> tuple[str, str]:
    """Build the (system, user) prompt pair for a skill-composition call.

    The output is deterministic for a given trigger — same trigger,
    same prompt bytes. That determinism is load-bearing for the stub-
    LLM byte-equal probe (WI-3).
    """
    tool_listing = "\n".join(f"- {name}" for name in trigger.tool_names)
    user_prompt = (
        f"Agent: {trigger.agent_id}\n"
        f"Run: {trigger.run_id}\n"
        f"Tool-sequence hash: {trigger.tool_sequence_hash}\n"
        f"Tool calls ({len(trigger.tool_names)} in order):\n"
        f"{tool_listing}\n\n"
        f"Compose a SKILL.md capturing this pattern as a reusable skill "
        f"for the {trigger.agent_id} agent. The target_agent field MUST "
        f"be exactly '{trigger.agent_id}'."
    )
    return _SYSTEM_PROMPT, user_prompt


def parse_llm_skill_response(
    response_text: str,
    *,
    trigger: SkillTrigger,
    audit_log_path: str,
    workspace_root: Path | str,
    emitted_at: datetime,
) -> SkillCandidate:
    """Parse the LLM-produced SKILL.md text and build a ``SkillCandidate``.

    Trust-boundary fields are overridden post-parse. ``provenance`` is
    derived by pairing the trigger's ``audit_entry_hashes`` with the
    caller-supplied ``audit_log_path`` (one ``(path, hash)`` tuple per
    entry). The ``shadow_path`` is computed from
    ``compute_candidate_shadow_path(workspace_root, agent_id, skill_id)``
    once the LLM-supplied ``category`` + ``name`` are validated slug-safe.

    Raises:
        SkillWriterError: when the response can't be parsed as a SKILL.md
        or the resulting category / name violate slug-safety.
    """
    try:
        llm_skill = parse_skill_md_content(response_text, source="<llm:skill_writer>")
    except SkillFormatError as exc:
        raise SkillWriterError(f"LLM produced malformed SKILL.md: {exc}") from exc

    if not _SLUG_RE.match(llm_skill.category):
        raise SkillWriterError(
            f"LLM-produced category is not slug-safe: {llm_skill.category!r} "
            f"(must match {_SLUG_RE.pattern})"
        )
    if not _SLUG_RE.match(llm_skill.name):
        raise SkillWriterError(
            f"LLM-produced name is not slug-safe: {llm_skill.name!r} "
            f"(must match {_SLUG_RE.pattern})"
        )

    provenance: tuple[tuple[str, str], ...] = tuple(
        (audit_log_path, entry_hash) for entry_hash in trigger.audit_entry_hashes
    )
    skill = llm_skill.model_copy(
        update={
            "target_agent": trigger.agent_id,
            "created_by": _CREATED_BY,
            "deployment_status": SkillDeploymentStatus.CANDIDATE,
            "eval_gate_status": SkillEvalGateStatus.NOT_RUN,
            "provenance": provenance,
        }
    )
    skill_id = f"{skill.category}/{skill.name}"
    shadow_path = compute_candidate_shadow_path(
        workspace_root=workspace_root,
        agent_id=trigger.agent_id,
        skill_id=skill_id,
    )
    return SkillCandidate(
        skill_id=skill_id,
        skill=skill,
        shadow_path=str(shadow_path),
        tool_sequence_hash=trigger.tool_sequence_hash,
        emitted_at=emitted_at,
    )


def compute_candidate_shadow_path(
    *,
    workspace_root: Path | str,
    agent_id: str,
    skill_id: str,
) -> Path:
    """Per Q1 of the v0.2 plan:
    ``<workspace>/.nexus/candidate-skills/<agent_id>/<skill_id>/SKILL.md``.

    ``skill_id`` is ``<category>/<skill-name>`` (matches the bundled
    in-repo layout under ``nlah/skills/``).
    """
    return Path(workspace_root) / ".nexus" / "candidate-skills" / agent_id / skill_id / "SKILL.md"


async def write_skill_candidate(
    *,
    trigger: SkillTrigger,
    audit_log_path: str,
    workspace_root: Path | str,
    llm_provider: LLMProvider,
    model_pin: str = DEFAULT_SKILL_WRITER_MODEL_PIN,
    max_tokens: int = DEFAULT_SKILL_WRITER_MAX_TOKENS,
    emitted_at: datetime | None = None,
) -> SkillCandidate:
    """End-to-end skill-composition flow: prompt → LLM → parse → write.

    1. Compose the deterministic prompt pair from the trigger.
    2. Call ``llm_provider.complete(...)``.
    3. Parse the response with trust-boundary overrides applied.
    4. Compute the shadow path; write SKILL.md via
       ``skill_format.write_skill_md`` (which creates parent dirs).
    5. Return the populated ``SkillCandidate`` (with ``shadow_path``
       resolved).

    The caller supplies the ``audit_log_path`` because Task 6 stays
    decoupled from filesystem layout — only Task 13's driver knows
    where the active run's audit log lives.
    """
    when = emitted_at if emitted_at is not None else datetime.now()
    system, user_prompt = compose_skill_prompt(trigger)
    response = await llm_provider.complete(
        prompt=user_prompt,
        model_pin=model_pin,
        max_tokens=max_tokens,
        system=system,
        temperature=0.0,
    )
    candidate = parse_llm_skill_response(
        response.text,
        trigger=trigger,
        audit_log_path=audit_log_path,
        workspace_root=workspace_root,
        emitted_at=when,
    )
    write_skill_md(candidate.skill, Path(candidate.shadow_path))
    write_candidate_meta(candidate, workspace_root=workspace_root)
    return candidate


__all__ = [
    "DEFAULT_SKILL_WRITER_MAX_TOKENS",
    "DEFAULT_SKILL_WRITER_MODEL_PIN",
    "SkillWriterError",
    "compose_skill_prompt",
    "compute_candidate_shadow_path",
    "parse_llm_skill_response",
    "write_skill_candidate",
]
