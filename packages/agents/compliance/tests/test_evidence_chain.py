"""compliance v0.2 Task 16 — evidence hash chain + signed manifest tests (WI-C9)."""

from __future__ import annotations

from compliance.evidence.chain import (
    GENESIS,
    build_manifest,
    chain_entries,
    chain_head,
    verify_chain,
    verify_manifest,
)

_H1 = "a" * 64
_H2 = "b" * 64
_H3 = "c" * 64


def test_chain_links_each_entry() -> None:
    chained = chain_entries([_H1, _H2, _H3])
    assert len(chained) == 3
    assert all(len(ce.chain_hash) == 64 for ce in chained)
    assert chained[0].chain_hash != chained[1].chain_hash  # order matters


def test_chain_head_empty_is_genesis() -> None:
    assert chain_head([]) == GENESIS


def test_verify_clean_chain() -> None:
    assert verify_chain(chain_entries([_H1, _H2, _H3])) is True


def test_verify_detects_tampered_entry() -> None:
    chained = list(chain_entries([_H1, _H2, _H3]))
    # Tamper with the middle entry's hash, keeping its (now stale) chain hash.
    from compliance.evidence.chain import ChainedEntry

    chained[1] = ChainedEntry(entry_hash="d" * 64, chain_hash=chained[1].chain_hash)
    assert verify_chain(chained) is False


def test_verify_detects_reorder() -> None:
    chained = chain_entries([_H1, _H2, _H3])
    reordered = [chained[0], chained[2], chained[1]]
    assert verify_chain(reordered) is False


def test_manifest_placeholder_signature() -> None:
    m = build_manifest(framework_id="cis_aws_v3", entry_hashes=[_H1, _H2])
    assert m.entry_count == 2 and m.signed_by == "compliance-v0.2-placeholder"
    assert len(m.signature) == 64 and m.chain_head == chain_head([_H1, _H2])


def test_manifest_external_signer() -> None:
    def signer(head: str) -> str:
        return "SIG:" + head[:8]

    signer.signer_id = "f6-audit"  # type: ignore[attr-defined]
    m = build_manifest(framework_id="cis_aws_v3", entry_hashes=[_H1], signer=signer)
    assert m.signed_by == "f6-audit" and m.signature.startswith("SIG:")


def test_verify_manifest_detects_tamper() -> None:
    m = build_manifest(framework_id="cis_aws_v3", entry_hashes=[_H1, _H2])
    assert verify_manifest(m, [_H1, _H2]) is True
    assert verify_manifest(m, [_H1, _H3]) is False  # different entries -> different head
