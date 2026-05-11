"""Tests for `charter.memory.embedding` (F.5 Task 4).

The Embedding protocol is what every memory write that wants ANN search
must go through. v0.1 ships a single deterministic implementation
(`FakeEmbeddingProvider`) — production providers (OpenAI / Anthropic)
land in Phase 1b.

Production contract for the fake provider:

1. **Configurable dimension** — defaults to `EMBEDDING_DIM` (1536) to
   match the `episodes.embedding VECTOR(1536)` column shipped in
   Tasks 1+2.
2. **Pure determinism** — same input always yields the same vector
   (must be safe to use as a deduplication signal).
3. **Unit-normalised** — the vector has L2 norm 1.0, so pgvector's
   cosine distance equals 1 - dot product (the property the ivfflat
   index assumes).
4. **Locality** — similar inputs produce similar vectors. We don't
   need cosine = 0 between unrelated inputs, only that identical
   inputs round-trip and that two distinct inputs are *unlikely* to
   collide.
5. **Protocol conformance** — `FakeEmbeddingProvider` satisfies
   `Embedding` so a production provider can drop in via the same DI
   seam.
"""

from __future__ import annotations

import math

import pytest
from charter.memory.embedding import EMBEDDING_DIM, Embedding, FakeEmbeddingProvider

# ---------------------------- protocol conformance -----------------------


def test_fake_provider_satisfies_embedding_protocol() -> None:
    """`Embedding` is a `runtime_checkable` Protocol — duck-typing must hold."""
    provider: Embedding = FakeEmbeddingProvider()
    assert isinstance(provider, Embedding)


# ---------------------------- dimensionality -----------------------------


def test_fake_provider_defaults_to_embedding_dim() -> None:
    provider = FakeEmbeddingProvider()
    vec = provider.embed("hello")
    assert len(vec) == EMBEDDING_DIM == 1536


@pytest.mark.parametrize("dim", [4, 16, 256, 1024])
def test_fake_provider_honors_custom_dim(dim: int) -> None:
    provider = FakeEmbeddingProvider(dim=dim)
    vec = provider.embed("anything")
    assert len(vec) == dim


def test_fake_provider_rejects_non_positive_dim() -> None:
    with pytest.raises(ValueError):
        FakeEmbeddingProvider(dim=0)
    with pytest.raises(ValueError):
        FakeEmbeddingProvider(dim=-3)


# ---------------------------- determinism --------------------------------


def test_fake_provider_is_deterministic() -> None:
    """Same text → same vector across separate calls AND separate instances."""
    a = FakeEmbeddingProvider(dim=128).embed("repeatable")
    b = FakeEmbeddingProvider(dim=128).embed("repeatable")
    assert a == b
    # Sanity: it isn't trivially all-zeros.
    assert any(v != 0.0 for v in a)


def test_fake_provider_differs_for_different_inputs() -> None:
    provider = FakeEmbeddingProvider(dim=128)
    assert provider.embed("alpha") != provider.embed("beta")


# ---------------------------- unit-normalised ----------------------------


@pytest.mark.parametrize("text", ["", "a", "hello world", "ünicode 🚀", "x" * 1024])
def test_fake_provider_vectors_are_unit_normalised(text: str) -> None:
    """L2 norm == 1 ± 1e-9 so pgvector cosine distance behaves predictably."""
    vec = FakeEmbeddingProvider(dim=64).embed(text)
    norm = math.sqrt(sum(v * v for v in vec))
    assert math.isclose(norm, 1.0, abs_tol=1e-9)


# ---------------------------- floats are JSON-safe -----------------------


def test_fake_provider_returns_python_floats() -> None:
    """The episodes.embedding column round-trips through JSON on aiosqlite —
    elements must be plain Python floats (no numpy scalars, no NaN, no inf).
    """
    vec = FakeEmbeddingProvider(dim=32).embed("payload")
    for v in vec:
        assert isinstance(v, float)
        assert math.isfinite(v)


# ---------------------------- empty input is allowed ---------------------


def test_fake_provider_handles_empty_string() -> None:
    """append_event sometimes carries a synthetic event with no text body."""
    vec = FakeEmbeddingProvider(dim=16).embed("")
    assert len(vec) == 16
    assert math.isclose(math.sqrt(sum(v * v for v in vec)), 1.0, abs_tol=1e-9)
