"""Canonical audit-action constants for `charter.memory` writes.

Every store-side mutation emits a `charter.audit.AuditLog` entry whose
`action` field is one of the constants below. Locking them at module
scope (with a test that pins each value verbatim) makes a rename an
explicit, test-breaking change rather than a silent payload-schema
drift that downstream verifiers might miss.

Downstream readers (D.7 Investigation, A.4 Meta-Harness) match on
these action strings, so they're effectively a wire-format contract
inside the system.
"""

from __future__ import annotations

ACTION_EPISODE_APPENDED = "episode_appended"
ACTION_PLAYBOOK_PUBLISHED = "playbook_published"
ACTION_ENTITY_UPSERTED = "entity_upserted"
ACTION_RELATIONSHIP_ADDED = "relationship_added"

__all__ = [
    "ACTION_ENTITY_UPSERTED",
    "ACTION_EPISODE_APPENDED",
    "ACTION_PLAYBOOK_PUBLISHED",
    "ACTION_RELATIONSHIP_ADDED",
]
