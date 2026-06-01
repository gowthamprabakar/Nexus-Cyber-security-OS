"""DSPy compilation thin wrapper for charter — v0.2.5 Task 2 (SAFETY-CRITICAL).

The substrate seam that binds DSPy's compilation/optimization API to
``charter.llm_adapter`` (per ADR-006 / ADR-003). Every v0.2.5 downstream
task (the GEPA metric adapter, the Stage-7 parallel composer, the
compilation cadence) calls through this module, so it is kept deliberately
**thin** and **provider-agnostic**: it works with any
``charter.llm.LLMProvider`` (Anthropic, OpenAI-compatible, DeepSeek, vLLM,
Ollama) — no provider-specific logic, no agent-specific logic ("dumb
charter").

**Optional-dependency contract (Task 1).** DSPy + GEPA install via the
``meta-harness[dspy]`` optional group; charter itself declares NO hard
dependency on ``dspy``. This module therefore performs **no top-level
``import dspy``** — every DSPy import is gated inside the function that
needs it (``_require_dspy``), so ``import charter.dspy_compiler`` succeeds
whether or not the extra is installed. Constructing or compiling without
the extra raises a clear, actionable error.

**Scope of this task.** This module provides the seam only. Actual GEPA
compilation against a live provider, the effectiveness ``metric=`` adapter,
and the Stage-7 composer arrive in later v0.2.5 tasks.

GEPA defaults honor v0.2.5 brainstorm Q2: ``auto="medium"`` with an
optional explicit ``max_metric_calls`` budget cap (GEPA requires exactly
one budget mode, so the two are mutually exclusive). A ``seed`` is threaded
through for reproducible compilation in tests (WI-3).
"""

from __future__ import annotations

import asyncio
import concurrent.futures
from typing import TYPE_CHECKING, Any

from charter.llm import LLMProvider

if TYPE_CHECKING:  # import only for type-checkers; never at runtime
    import dspy  # type: ignore[import-untyped]

# GEPA defaults per v0.2.5 brainstorm Q2.
DEFAULT_GEPA_AUTO = "medium"
DEFAULT_MAX_TOKENS = 4096
SUPPORTED_OPTIMIZERS = ("gepa",)

_DSPY_MISSING_MSG = (
    "DSPy is not installed. The v0.2.5 skill-optimization layer is an optional "
    "dependency — install it with:\n"
    "    uv pip install -e packages/agents/meta-harness[dspy]\n"
    "(charter declares no hard dependency on dspy; it is provided by the "
    "meta-harness[dspy] extra)."
)


def _require_dspy() -> Any:
    """Import and return the ``dspy`` module, or raise a clear error.

    Gated here (not at module top level) so charter imports cleanly without
    the optional ``[dspy]`` extra installed.
    """
    try:
        import dspy
    except ImportError as exc:  # pragma: no cover - exercised via monkeypatch
        raise ImportError(_DSPY_MISSING_MSG) from exc
    return dspy


def _run_sync(coro: Any) -> Any:
    """Run an awaitable to completion from synchronous code.

    DSPy's LM interface is synchronous; charter providers are async. When no
    event loop is running we use ``asyncio.run``; when one is already running
    (compilation invoked from async code) we run the coroutine on a private
    loop in a worker thread to avoid "loop already running" errors.
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(lambda: asyncio.run(coro)).result()


def _messages_to_prompt(
    prompt: str | None,
    messages: list[dict[str, Any]] | None,
) -> tuple[str | None, str]:
    """Normalize DSPy's (prompt | messages) call shape into (system, prompt).

    DSPy calls an LM with either a bare ``prompt`` string or OpenAI-style
    ``messages``. charter's ``complete`` takes a single prompt plus an
    optional system string, so we split a leading system message out and
    join the remaining turns.
    """
    if prompt is not None:
        return None, prompt
    if not messages:
        return None, ""
    system: str | None = None
    parts: list[str] = []
    for msg in messages:
        role = msg.get("role", "user")
        content = msg.get("content", "")
        if role == "system" and system is None:
            system = content
        else:
            parts.append(f"{role}: {content}" if role != "user" else content)
    return system, "\n\n".join(parts)


def _build_charter_lm(
    provider: LLMProvider,
    *,
    model_pin: str,
    max_tokens: int,
    temperature: float,
) -> dspy.BaseLM:
    """Build a DSPy ``BaseLM`` that delegates to a charter ``LLMProvider``.

    Defined inside a function (not at module scope) so the ``dspy.BaseLM``
    base class is only referenced when the optional extra is present.
    """
    dspy = _require_dspy()
    from litellm.types.utils import Choices, Message, ModelResponse, Usage

    class _CharterDSPyLM(dspy.BaseLM):  # type: ignore[misc, name-defined]
        """Provider-agnostic DSPy LM backed by ``charter.llm_adapter``."""

        def __init__(self) -> None:
            super().__init__(
                model=f"charter/{provider.provider_id}/{model_pin}",
                model_type="chat",
                temperature=temperature,
                max_tokens=max_tokens,
                cache=False,
            )
            self._provider = provider
            self._model_pin = model_pin

        def forward(
            self,
            prompt: str | None = None,
            messages: list[dict[str, Any]] | None = None,
            **kwargs: Any,
        ) -> Any:
            system, prompt_text = _messages_to_prompt(prompt, messages)
            resp = _run_sync(
                self._provider.complete(
                    prompt=prompt_text,
                    model_pin=self._model_pin,
                    max_tokens=int(kwargs.get("max_tokens", max_tokens)),
                    system=system,
                    temperature=float(kwargs.get("temperature", temperature)),
                )
            )
            usage = getattr(resp, "usage", None)
            total = getattr(usage, "total_tokens", 0) if usage is not None else 0
            return ModelResponse(
                choices=[
                    Choices(
                        index=0,
                        message=Message(role="assistant", content=resp.text),
                        finish_reason=resp.stop_reason or "stop",
                    )
                ],
                model=self._model_pin,
                usage=Usage(prompt_tokens=0, completion_tokens=total, total_tokens=total),
            )

    return _CharterDSPyLM()


class DSPyCompiler:
    """Thin, provider-agnostic wrapper around DSPy compilation.

    Construct with any ``charter.llm.LLMProvider`` plus the ``model_pin`` the
    provider should use. ``compile`` optimizes a ``dspy.Module`` with GEPA
    (the only optimizer supported in v0.2.5) against a metric that satisfies
    GEPA's ``metric=`` contract.
    """

    def __init__(
        self,
        provider: LLMProvider,
        *,
        model_pin: str,
        max_tokens: int = DEFAULT_MAX_TOKENS,
        temperature: float = 0.0,
        seed: int | None = None,
    ) -> None:
        if not isinstance(provider, LLMProvider):
            raise TypeError(
                f"provider must implement charter.llm.LLMProvider (got {type(provider).__name__})"
            )
        if not model_pin or not model_pin.strip():
            raise ValueError("model_pin must be a non-empty string")
        self._provider = provider
        self._model_pin = model_pin
        self._max_tokens = max_tokens
        self._temperature = temperature
        self._seed = seed
        self._lm: dspy.BaseLM | None = None

    @property
    def provider(self) -> LLMProvider:
        return self._provider

    @property
    def seed(self) -> int | None:
        return self._seed

    @property
    def lm(self) -> dspy.BaseLM:
        """The charter-backed DSPy LM (built lazily, cached)."""
        if self._lm is None:
            self._lm = _build_charter_lm(
                self._provider,
                model_pin=self._model_pin,
                max_tokens=self._max_tokens,
                temperature=self._temperature,
            )
        return self._lm

    def make_optimizer(
        self,
        *,
        metric: Any,
        optimizer: str = "gepa",
        auto: str | None = DEFAULT_GEPA_AUTO,
        max_metric_calls: int | None = None,
        reflection_lm: Any | None = None,
        **kwargs: Any,
    ) -> Any:
        """Construct (but do not run) the configured DSPy optimizer.

        Factored out so callers/tests can inspect the optimizer config
        without running a compilation. GEPA requires exactly one budget
        mode, so ``auto`` and ``max_metric_calls`` are mutually exclusive —
        passing ``max_metric_calls`` (e.g. the Q2 50-trial cap) switches to
        explicit-budget mode and drops ``auto``.
        """
        if optimizer not in SUPPORTED_OPTIMIZERS:
            raise ValueError(
                f"unsupported optimizer: {optimizer!r} "
                f"(v0.2.5 supports: {', '.join(SUPPORTED_OPTIMIZERS)})"
            )
        if not callable(metric):
            raise TypeError("metric must be callable (GEPA metric= contract)")
        dspy = _require_dspy()
        budget: dict[str, Any]
        if max_metric_calls is not None:
            budget = {"max_metric_calls": max_metric_calls}
        else:
            budget = {"auto": auto}
        return dspy.GEPA(
            metric=metric,
            reflection_lm=reflection_lm if reflection_lm is not None else self.lm,
            seed=self._seed,
            **budget,
            **kwargs,
        )

    def compile(
        self,
        program: Any,
        *,
        trainset: Any,
        metric: Any,
        optimizer: str = "gepa",
        auto: str | None = DEFAULT_GEPA_AUTO,
        max_metric_calls: int | None = None,
        reflection_lm: Any | None = None,
        **kwargs: Any,
    ) -> Any:
        """Compile ``program`` with the given metric/optimizer; returns the
        compiled ``dspy.Module``.

        The charter-backed LM is configured for the duration of compilation
        via ``dspy.context`` so the program and GEPA's reflection both call
        through ``charter.llm_adapter``.
        """
        dspy = _require_dspy()
        if not isinstance(program, dspy.Module):
            raise TypeError(f"program must be a dspy.Module (got {type(program).__name__})")
        if trainset is None:
            raise ValueError("trainset must be provided")
        opt = self.make_optimizer(
            metric=metric,
            optimizer=optimizer,
            auto=auto,
            max_metric_calls=max_metric_calls,
            reflection_lm=reflection_lm,
            **kwargs,
        )
        with dspy.context(lm=self.lm):
            return opt.compile(program, trainset=trainset)


__all__ = [
    "DEFAULT_GEPA_AUTO",
    "DEFAULT_MAX_TOKENS",
    "SUPPORTED_OPTIMIZERS",
    "DSPyCompiler",
]
