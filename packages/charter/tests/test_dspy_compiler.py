"""Tests — ``charter.dspy_compiler`` (v0.2.5 Task 2, SAFETY-CRITICAL substrate).

Verifies the DSPy compilation seam: provider-agnostic LM binding to
``charter.llm_adapter``, GEPA optimizer construction (auto="medium" default,
mutually-exclusive max_metric_calls budget), error handling, the optional-
dependency gating contract, and seeded reproducibility (WI-3).

No real GEPA compilation is run (Task 4+); the optimizer is inspected /
stubbed so the suite is deterministic and offline.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from charter.llm import FakeLLMProvider, LLMResponse, TokenUsage

# DSPy is the optional [dspy] extra (installed in CI via uv sync --all-extras).
# Skip the dspy-requiring tests gracefully in dev envs without the extra.
dspy = pytest.importorskip("dspy")

from charter import dspy_compiler  # noqa: E402
from charter.dspy_compiler import (  # noqa: E402
    DEFAULT_GEPA_AUTO,
    DSPyCompiler,
)

_MODULE_SRC = Path(dspy_compiler.__file__).read_text(encoding="utf-8")


def _resp(text: str) -> LLMResponse:
    return LLMResponse(
        text=text,
        stop_reason="stop",
        usage=TokenUsage(input_tokens=1, output_tokens=2),
        model_pin="test-model",
        provider_id="fake",
    )


def _provider(*texts: str, provider_id: str = "fake") -> FakeLLMProvider:
    return FakeLLMProvider([_resp(t) for t in texts], provider_id=provider_id)


def _metric(gold: Any, pred: Any, trace: Any = None, *a: Any, **k: Any) -> float:
    return 1.0


# ---------------------------------------------------------------------------
# Optional-dependency contract
# ---------------------------------------------------------------------------


def test_no_top_level_dspy_or_litellm_import() -> None:
    """The module must NOT import dspy/litellm at top level — the [dspy]
    extra is optional and ``import charter.dspy_compiler`` must always work."""
    for line in _MODULE_SRC.splitlines():
        # Module-level = not indented. In-function / TYPE_CHECKING-guarded
        # imports are indented and allowed (the gating contract).
        module_level = bool(line) and not line[0].isspace()
        s = line.strip()
        flagged = s in ("import dspy", "import litellm") or s.startswith(
            ("import dspy ", "import litellm ")
        )
        assert not (module_level and flagged), f"top-level optional import found: {s!r}"


def test_dspy_missing_raises_actionable_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """When dspy can't be imported, the seam raises a clear install hint."""

    def _boom() -> Any:
        raise ImportError(dspy_compiler._DSPY_MISSING_MSG)

    monkeypatch.setattr(dspy_compiler, "_require_dspy", _boom)
    compiler = DSPyCompiler(_provider("x"), model_pin="m")
    with pytest.raises(ImportError, match=r"meta-harness\[dspy\]"):
        _ = compiler.lm


# ---------------------------------------------------------------------------
# Construction / validation
# ---------------------------------------------------------------------------


def test_init_with_fake_provider() -> None:
    compiler = DSPyCompiler(_provider("a"), model_pin="deepseek-chat", seed=7)
    assert compiler.provider.provider_id == "fake"
    assert compiler.seed == 7


def test_init_rejects_non_provider() -> None:
    with pytest.raises(TypeError, match="LLMProvider"):
        DSPyCompiler(object(), model_pin="m")  # type: ignore[arg-type]


def test_init_rejects_empty_model_pin() -> None:
    with pytest.raises(ValueError, match="model_pin"):
        DSPyCompiler(_provider("a"), model_pin="  ")


# ---------------------------------------------------------------------------
# Provider-agnostic LM binding (ADR-006)
# ---------------------------------------------------------------------------


def test_lm_built_lazily_and_cached() -> None:
    compiler = DSPyCompiler(_provider("a"), model_pin="m")
    lm1 = compiler.lm
    lm2 = compiler.lm
    assert isinstance(lm1, dspy.BaseLM)
    assert lm1 is lm2  # cached


def test_lm_delegates_to_charter_provider() -> None:
    """Calling the bound LM routes through the charter provider's complete()."""
    provider = _provider("compiled-answer")
    compiler = DSPyCompiler(provider, model_pin="m")
    out = compiler.lm("what is 2+2?")
    assert out == ["compiled-answer"]
    assert len(provider.calls) == 1
    assert provider.calls[0]["prompt"] == "what is 2+2?"


def test_lm_delegates_with_messages_splits_system() -> None:
    provider = _provider("ok")
    compiler = DSPyCompiler(provider, model_pin="m")
    out = compiler.lm(
        messages=[
            {"role": "system", "content": "you are terse"},
            {"role": "user", "content": "hello"},
        ]
    )
    assert out == ["ok"]
    call = provider.calls[0]
    assert call["system"] == "you are terse"
    assert "hello" in call["prompt"]


def test_provider_agnostic_model_string_reflects_provider() -> None:
    """The bound LM's model id encodes the provider — works for any provider."""
    a = DSPyCompiler(_provider("x", provider_id="anthropic"), model_pin="claude-x")
    b = DSPyCompiler(_provider("x", provider_id="deepseek"), model_pin="deepseek-chat")
    assert "anthropic" in a.lm.model and "claude-x" in a.lm.model
    assert "deepseek" in b.lm.model and "deepseek-chat" in b.lm.model


# ---------------------------------------------------------------------------
# Optimizer construction (GEPA)
# ---------------------------------------------------------------------------


def test_make_optimizer_default_is_gepa_auto_medium() -> None:
    compiler = DSPyCompiler(_provider("x"), model_pin="m", seed=11)
    opt = compiler.make_optimizer(metric=_metric)
    assert isinstance(opt, dspy.GEPA)
    assert DEFAULT_GEPA_AUTO == "medium"


def test_make_optimizer_max_metric_calls_overrides_auto() -> None:
    """Passing the Q2 budget cap must not collide with auto (GEPA requires
    exactly one budget mode)."""
    compiler = DSPyCompiler(_provider("x"), model_pin="m")
    opt = compiler.make_optimizer(metric=_metric, max_metric_calls=50)
    assert isinstance(opt, dspy.GEPA)  # constructed without the "both budgets" error


def test_make_optimizer_rejects_unknown_optimizer() -> None:
    compiler = DSPyCompiler(_provider("x"), model_pin="m")
    with pytest.raises(ValueError, match="unsupported optimizer"):
        compiler.make_optimizer(metric=_metric, optimizer="random-search")


def test_make_optimizer_rejects_non_callable_metric() -> None:
    compiler = DSPyCompiler(_provider("x"), model_pin="m")
    with pytest.raises(TypeError, match="metric must be callable"):
        compiler.make_optimizer(metric=123)  # type: ignore[arg-type]


def test_seed_threaded_into_optimizer(monkeypatch: pytest.MonkeyPatch) -> None:
    """WI-3 — the seed is threaded into the GEPA optimizer for reproducibility."""
    captured: dict[str, Any] = {}

    class _FakeGEPA:
        def __init__(self, metric: Any, **kwargs: Any) -> None:
            captured.update(kwargs)
            captured["metric"] = metric

    monkeypatch.setattr(dspy, "GEPA", _FakeGEPA)
    compiler = DSPyCompiler(_provider("x"), model_pin="m", seed=1234)
    compiler.make_optimizer(metric=_metric)
    assert captured["seed"] == 1234
    assert captured["auto"] == "medium"


# ---------------------------------------------------------------------------
# compile() — validation + happy path (optimizer stubbed; no real GEPA run)
# ---------------------------------------------------------------------------


class _StubProgram(dspy.Module):  # type: ignore[misc, name-defined]
    def forward(self, **kwargs: Any) -> Any:  # pragma: no cover - not executed
        return None


def test_compile_rejects_non_module() -> None:
    compiler = DSPyCompiler(_provider("x"), model_pin="m")
    with pytest.raises(TypeError, match=r"dspy\.Module"):
        compiler.compile(object(), trainset=[], metric=_metric)


def test_compile_rejects_none_trainset() -> None:
    compiler = DSPyCompiler(_provider("x"), model_pin="m")
    with pytest.raises(ValueError, match="trainset"):
        compiler.compile(_StubProgram(), trainset=None, metric=_metric)


def test_compile_happy_path_stubbed_optimizer(monkeypatch: pytest.MonkeyPatch) -> None:
    """compile() builds the optimizer, runs its .compile under the charter LM
    context, and binds the LM to the returned program before returning. Optimizer
    stubbed so no live compilation occurs."""
    seen: dict[str, Any] = {}

    class _CompiledProgram:
        def set_lm(self, lm: Any) -> None:
            seen["bound_lm"] = lm

    compiled_program = _CompiledProgram()

    class _FakeOptimizer:
        def compile(self, program: Any, *, trainset: Any) -> Any:
            seen["program"] = program
            seen["trainset"] = trainset
            return compiled_program

    compiler = DSPyCompiler(_provider("x"), model_pin="m")
    monkeypatch.setattr(compiler, "make_optimizer", lambda **k: _FakeOptimizer())
    program = _StubProgram()
    result = compiler.compile(program, trainset=["ex"], metric=_metric)
    assert result is compiled_program
    assert seen["program"] is program
    assert seen["trainset"] == ["ex"]
    # The compiled program must have the charter LM bound (drift #3 fix).
    assert seen["bound_lm"] is compiler.lm


def test_compiled_program_is_invocable_without_external_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """drift #3 — a compiled program returned by compile() must be invocable
    directly, without re-establishing ``dspy.context(lm=...)``. compile() binds
    the charter LM via ``set_lm`` so a later ``compiled(...)`` does not raise
    ``ValueError: No LM is loaded``."""

    class _Sig(dspy.Signature):  # type: ignore[misc, name-defined]
        trace: str = dspy.InputField()
        skill_md: str = dspy.OutputField()

    class _Program(dspy.Module):  # type: ignore[misc, name-defined]
        def __init__(self) -> None:
            super().__init__()
            self.step = dspy.Predict(_Sig)

        def forward(self, trace: str) -> Any:
            return self.step(trace=trace)

    program = _Program()

    class _FakeOptimizer:
        # GEPA-like: returns the (already-built) program without binding an LM.
        def compile(self, prog: Any, *, trainset: Any) -> Any:
            return program

    # Plenty of identical canned responses so the fake provider never exhausts
    # (DSPy may make more than one call per invocation).
    provider = _provider(*(['{"skill_md": "# Compiled skill"}'] * 20))
    compiler = DSPyCompiler(provider, model_pin="m")
    monkeypatch.setattr(compiler, "make_optimizer", lambda **k: _FakeOptimizer())

    compiled = compiler.compile(_StubProgram(), trainset=["ex"], metric=_metric)

    # No global LM configured — reproduces the drift #3 failure condition.
    dspy.settings.configure(lm=None)
    out = compiled(trace="did X then Y")  # must NOT raise "No LM is loaded"
    assert out.skill_md == "# Compiled skill"
