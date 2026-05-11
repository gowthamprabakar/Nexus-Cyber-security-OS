"""Nexus memory engines (F.5) — episodic / procedural / semantic stores.

Production-grade SQLAlchemy 2.0 models that back the three memory engines
described in [ADR-009](../../../../../docs/_meta/decisions/ADR-009-memory-architecture.md)
(drafted in F.5 Task 12). The four tables live in `charter.memory.models`:

- `EpisodeModel`      — episodic (agent run events; pgvector embedding).
- `PlaybookModel`     — procedural (versioned NLAH / action policies).
- `EntityModel`       — semantic (knowledge-graph nodes).
- `RelationshipModel` — semantic (knowledge-graph edges).

Typed async accessors (`EpisodicStore`, `ProceduralStore`, `SemanticStore`,
`MemoryService`, `Embedding` Protocol) land in subsequent F.5 tasks and
join this re-export list as they ship.
"""

from __future__ import annotations

from charter.memory.embedding import Embedding, FakeEmbeddingProvider
from charter.memory.episodic import EpisodeRow, EpisodicStore
from charter.memory.models import (
    EMBEDDING_DIM,
    Base,
    EntityModel,
    EpisodeModel,
    PlaybookModel,
    RelationshipModel,
)
from charter.memory.procedural import PlaybookRow, ProceduralStore

__all__ = [
    "EMBEDDING_DIM",
    "Base",
    "Embedding",
    "EntityModel",
    "EpisodeModel",
    "EpisodeRow",
    "EpisodicStore",
    "FakeEmbeddingProvider",
    "PlaybookModel",
    "PlaybookRow",
    "ProceduralStore",
    "RelationshipModel",
]
