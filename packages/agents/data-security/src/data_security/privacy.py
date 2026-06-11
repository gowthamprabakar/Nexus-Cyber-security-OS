"""Privacy contract + residency invariants (data-security v0.2 Task 3, WI-S8/S9/S10).

The code-level enforcement of Nexus's data-handling contract — the cycle's safety
invariant (mirrors D.3 `assert_authorized` / D.4 `assert_block_authorized`):

- **WI-S9** ``privacy_hash`` — sampled content is hashed (SHA-256); the hash + a label are
  the maximum information any finding may carry.
- **WI-S8** ``assert_privacy_contract`` — raises if a finding's evidence carries **plaintext
  sensitive content** (PII / PHI / PAN / secrets), detected by re-running the classifier
  over every string value. A finding may carry labels + hashes, never raw sensitive bytes.

Backstops pause-trigger #11 (privacy contract violation).
"""

from __future__ import annotations

import hashlib
from typing import Any

from data_security.classifiers.patterns import classify
from data_security.schemas import ClassifierLabel


class PrivacyContractError(RuntimeError):
    """A finding's evidence leaked plaintext sensitive content (WI-S8)."""


def privacy_hash(content: bytes | str) -> str:
    """SHA-256 of sampled content — the only content-derived value a finding may carry."""
    data = content.encode("utf-8") if isinstance(content, str) else content
    return hashlib.sha256(data).hexdigest()


def _leaks_plaintext(value: str) -> bool:
    return classify(value) is not ClassifierLabel.NONE


def assert_privacy_contract(evidence: dict[str, Any]) -> None:
    """Raise if ``evidence`` carries plaintext sensitive content. Every string value (and
    string list element) is re-classified; a non-NONE label means raw sensitive bytes
    leaked into a finding — forbidden (WI-S8). Labels + hashes are allowed."""
    for key, value in evidence.items():
        if isinstance(value, str) and _leaks_plaintext(value):
            raise PrivacyContractError(
                f"evidence[{key!r}] carries plaintext sensitive content — findings may carry "
                f"a classification label + hash only (WI-S8)"
            )
        if isinstance(value, list):
            for item in value:
                if isinstance(item, str) and _leaks_plaintext(item):
                    raise PrivacyContractError(
                        f"evidence[{key!r}] list carries plaintext sensitive content (WI-S8)"
                    )
