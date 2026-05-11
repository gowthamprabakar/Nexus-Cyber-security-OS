"""Embedding provider seam for `charter.memory` (F.5 Task 4).

The `Embedding` Protocol is the contract every agent uses to convert
text payloads into vectors before writing to `episodes.embedding`.
Production providers (OpenAI / Anthropic) ship in Phase 1b — v0.1
ships only a deterministic fake suitable for tests + air-gapped pilot
deployments where calling an external embedding API is not allowed.

The fake provider's discipline is the same as a real provider:

- Deterministic — identical input produces identical output across
  process boundaries, so a writer can use the vector itself as a
  deduplication signal.
- Unit-normalised (L2 norm = 1.0) — pgvector's `cosine_distance` returns
  ``1 - (a · b)`` when both operands are normalised, which is the
  property the ivfflat index assumes.
- Locality — similar inputs land close in vector space. We achieve
  this by deriving the vector deterministically from a SHA-256 of the
  text. Identical inputs collide cleanly; distinct short inputs land
  on very different hashes (and thus very different vectors), which
  is exactly the property unit tests of "do these two events look
  similar?" want.
- JSON-safe — every element is a finite Python `float` so the
  aiosqlite JSON fallback used in unit tests round-trips cleanly.
"""

from __future__ import annotations

import hashlib
import math
from typing import Protocol, runtime_checkable

from charter.memory.models import EMBEDDING_DIM

__all__ = ["EMBEDDING_DIM", "Embedding", "FakeEmbeddingProvider"]


@runtime_checkable
class Embedding(Protocol):
    """Stable interface every memory-write call goes through.

    Implementations: `FakeEmbeddingProvider` (v0.1); OpenAI +
    Anthropic providers in Phase 1b. `MemoryService` accepts any
    `Embedding`-conforming object via its constructor.
    """

    def embed(self, text: str) -> list[float]: ...


class FakeEmbeddingProvider:
    """Deterministic SHA-256-derived embedding provider.

    Suitable for unit tests, air-gapped pilots, and any context where
    a real embedding API is unavailable. Drop-in replaceable by a
    production provider via the `Embedding` Protocol seam.
    """

    def __init__(self, dim: int = EMBEDDING_DIM) -> None:
        if dim <= 0:
            raise ValueError(f"dim must be positive, got {dim}")
        self._dim = dim

    def embed(self, text: str) -> list[float]:
        # Stretch the SHA-256 stream to `dim * 4` bytes by hashing
        # incrementally; convert 4-byte chunks to centered floats in
        # [-1, 1] then unit-normalise the whole vector.
        needed_bytes = self._dim * 4
        stream = bytearray()
        counter = 0
        seed = text.encode("utf-8")
        while len(stream) < needed_bytes:
            h = hashlib.sha256(seed + counter.to_bytes(8, "big")).digest()
            stream.extend(h)
            counter += 1

        raw: list[float] = []
        for i in range(self._dim):
            chunk = stream[i * 4 : i * 4 + 4]
            # Unsigned 32-bit → [-1, 1].
            uint32 = int.from_bytes(chunk, "big")
            raw.append((uint32 / 0xFFFFFFFF) * 2.0 - 1.0)

        norm = math.sqrt(sum(v * v for v in raw))
        if norm == 0.0:
            # Astronomically unlikely with SHA-256 (would require 256
            # consecutive zero bytes mapping every component to exactly
            # -1.0 then averaging to 0), but make the fallback explicit:
            # return a unit basis vector rather than a zero vector.
            zero_fallback = [0.0] * self._dim
            zero_fallback[0] = 1.0
            return zero_fallback
        return [v / norm for v in raw]
