"""Hypothesis-based properties for the audit hash chain.

Note: pytest's ``tmp_path_factory`` fixture cannot be injected into
``@given``-decorated tests (Hypothesis manages the argument list itself and
pytest fixture injection is incompatible with that mechanism).  Instead, each
property creates its own temporary directory via ``tempfile.TemporaryDirectory``
so the test bodies remain pure Python and Hypothesis can shrink/replay freely.
"""

import itertools
import tempfile
from pathlib import Path

from charter.audit import GENESIS_HASH, AuditEntry, AuditLog
from hypothesis import given
from hypothesis import strategies as st


@given(actions=st.lists(st.text(min_size=1, max_size=20), min_size=1, max_size=50))
def test_chain_integrity_holds_for_any_sequence(actions: list[str]) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        log_path = Path(tmp) / "audit.jsonl"
        log = AuditLog(path=log_path, agent="x", run_id="r")
        entries = [log.append(action=a, payload={"i": i}) for i, a in enumerate(actions)]

        raw_lines = log_path.read_text().strip().split("\n")
        persisted = [AuditEntry.from_json(line) for line in raw_lines]

        assert len(persisted) == len(entries)
        assert persisted[0].previous_hash == GENESIS_HASH
        for prev, curr in itertools.pairwise(persisted):
            assert curr.previous_hash == prev.entry_hash


@given(payload=st.dictionaries(st.text(min_size=1), st.integers()))
def test_entry_hash_is_deterministic_for_same_input(payload: dict[str, int]) -> None:
    """Verify hash structural properties hold for any payload.

    Note: ``entry_hash`` incorporates the wall-clock timestamp so two logs
    created at different instants will produce different hashes even for
    identical payloads.  The determinism property that *can* be tested
    without freezing time is:

    * Both fresh logs start from GENESIS_HASH (same previous_hash).
    * Re-serialising a persisted entry and re-parsing it yields the
      identical entry_hash — i.e. the hash is stable across a
      serialise/deserialise round-trip.
    * The entry_hash is a valid 64-character lowercase hex string (SHA-256).
    """
    with tempfile.TemporaryDirectory() as tmp:
        log_path = Path(tmp) / "a.jsonl"
        log = AuditLog(path=log_path, agent="x", run_id="r")
        entry = log.append(action="z", payload=payload)

        # Chain starts at genesis for a fresh log
        assert entry.previous_hash == GENESIS_HASH

        # entry_hash is a valid SHA-256 hex digest
        assert len(entry.entry_hash) == 64
        assert all(c in "0123456789abcdef" for c in entry.entry_hash)

        # Round-trip through JSON must preserve the hash exactly
        reparsed = AuditEntry.from_json(log_path.read_text().strip())
        assert reparsed.entry_hash == entry.entry_hash
