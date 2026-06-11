"""Evidence hash chain + signed manifest (compliance v0.2 Task 16).

Per **WI-C9** a hash **chain** binds the evidence entries in order — each entry's chain hash
folds in the previous one, so altering any entry (or reordering) breaks every chain hash
after it, making tampering detectable. The bundle is sealed by a **signed manifest** over the
chain head.

Signing note: no shared F.5/F.6 signer exists yet, so v0.2 uses a deterministic **placeholder**
signature with an explicit ``signed_by`` marker; when the F.6 audit agent ships (Cycle 11)
its signer replaces the placeholder via the injectable ``signer`` seam (WI-C9).
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Sequence
from dataclasses import dataclass

GENESIS = "0" * 64
_PLACEHOLDER_SIGNER = "compliance-v0.2-placeholder"


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class ChainedEntry:
    entry_hash: str
    chain_hash: str  # sha256(prev_chain_hash + entry_hash)


def chain_entries(entry_hashes: Sequence[str]) -> tuple[ChainedEntry, ...]:
    """Fold the entry hashes into a hash chain (genesis-rooted)."""
    out: list[ChainedEntry] = []
    prev = GENESIS
    for h in entry_hashes:
        chain_hash = _sha256(prev + h)
        out.append(ChainedEntry(entry_hash=h, chain_hash=chain_hash))
        prev = chain_hash
    return tuple(out)


def chain_head(entry_hashes: Sequence[str]) -> str:
    """The final chain hash (or GENESIS for an empty bundle)."""
    chained = chain_entries(entry_hashes)
    return chained[-1].chain_hash if chained else GENESIS


def verify_chain(chained: Sequence[ChainedEntry]) -> bool:
    """Recompute the chain; `False` if any entry hash or link was tampered with."""
    prev = GENESIS
    for ce in chained:
        if _sha256(prev + ce.entry_hash) != ce.chain_hash:
            return False
        prev = ce.chain_hash
    return True


@dataclass(frozen=True, slots=True)
class SignedManifest:
    framework_id: str
    entry_count: int
    chain_head: str
    signature: str
    signed_by: str

    def to_dict(self) -> dict[str, object]:
        return {
            "framework_id": self.framework_id,
            "entry_count": self.entry_count,
            "chain_head": self.chain_head,
            "signature": self.signature,
            "signed_by": self.signed_by,
        }


def build_manifest(
    *,
    framework_id: str,
    entry_hashes: Sequence[str],
    signer: Callable[[str], str] | None = None,
) -> SignedManifest:
    """Seal a bundle with a signed manifest over its chain head. With no ``signer`` the v0.2
    placeholder signs deterministically (F.6 signer slots in here)."""
    head = chain_head(entry_hashes)
    if signer is not None:
        signature = signer(head)
        signed_by = getattr(signer, "signer_id", "external")
    else:
        signature = _sha256(head + "compliance-manifest-v0.2")
        signed_by = _PLACEHOLDER_SIGNER
    return SignedManifest(
        framework_id=framework_id,
        entry_count=len(entry_hashes),
        chain_head=head,
        signature=signature,
        signed_by=signed_by,
    )


def verify_manifest(manifest: SignedManifest, entry_hashes: Sequence[str]) -> bool:
    """`True` if the manifest's chain head still matches the entry hashes (tamper check)."""
    return manifest.chain_head == chain_head(entry_hashes)
