"""`detect_dga` — entropy + n-gram heuristic over DnsEvent input.

Pure-function detector (no I/O, no async). Per the Q2 plan
resolution: ML-model-free in v0.1. Operates on the **second-level
label** (the part directly to the left of the public-suffix-style TLD)
of each DNS query name — that's where DGA randomness lives.

**Score components:**

1. **Shannon entropy** of the second-level label. Random-looking
   strings cluster at entropy ≥ 3.5 bits/char (max for 26 letters is
   `log2(26) ≈ 4.70`); legitimate English domains cluster at
   2.5-3.5.
2. **Bigram score** — fraction of consecutive bigrams in the label
   that appear in the bundled top-50 common English bigrams. Random
   labels score low (< 0.10); pronounceable English labels score
   high (> 0.30).

**Composite score** = `entropy_normalised * (1 - bigram_score)`:
- high entropy AND low bigram score → high composite → DGA flag
- bound: composite in [0, 1].

**Defaults:**
- `min_entropy = 3.5` — below this, even a low bigram score is
  expected (short legit names like `aws.amazon.com`'s `aws`).
- `max_bigram_score = 0.30` — above this, even a high-entropy label
  reads as pronounceable; skip.
- `min_label_length = 7` — below 7 chars the statistics aren't
  reliable (short labels can hit any entropy by chance).

**Severity:**
- `entropy >= 4.0 AND bigram_score <= 0.05` → HIGH
- `entropy >= min_entropy AND bigram_score <= max_bigram_score` → MEDIUM

**Suffix allowlist.** Common cloud/CDN suffixes are never flagged,
even if their second-level label looks random (CloudFront edge nodes,
S3 bucket names, ELB hostnames). The allowlist lives at module top
and is the v0.1 substitute for a Phase 1c live allowlist API.
"""

from __future__ import annotations

import math
from collections import Counter
from collections.abc import Sequence

from network_threat.schemas import (
    Detection,
    DnsEvent,
    FindingType,
    Severity,
    short_ip_token,
)

_DETECTOR_ID = "dga@0.1.0"

DEFAULT_MIN_ENTROPY = 3.5
DEFAULT_MAX_BIGRAM_SCORE = 0.30
DEFAULT_MIN_LABEL_LENGTH = 7

# Top-50 most-common English-text bigrams (Norvig; lowercased).
_COMMON_BIGRAMS: frozenset[str] = frozenset(
    {
        "th",
        "he",
        "in",
        "er",
        "an",
        "re",
        "on",
        "at",
        "en",
        "nd",
        "ti",
        "es",
        "or",
        "te",
        "of",
        "ed",
        "is",
        "it",
        "al",
        "ar",
        "st",
        "to",
        "nt",
        "ng",
        "se",
        "ha",
        "as",
        "ou",
        "io",
        "le",
        "ve",
        "co",
        "me",
        "de",
        "hi",
        "ri",
        "ro",
        "ic",
        "ne",
        "ea",
        "ra",
        "ce",
        "li",
        "ch",
        "ll",
        "be",
        "ma",
        "si",
        "om",
        "ur",
    }
)

# CDN / cloud / mail suffixes that ride high entropy but aren't DGA.
# Anything ending in one of these is skipped (the operator already
# trusts the parent surface).
_SUFFIX_ALLOWLIST: tuple[str, ...] = (
    ".cloudfront.net",
    ".amazonaws.com",
    ".s3.amazonaws.com",
    ".s3.us-east-1.amazonaws.com",
    ".elb.amazonaws.com",
    ".execute-api.us-east-1.amazonaws.com",
    ".azureedge.net",
    ".cloudapp.azure.com",
    ".googleusercontent.com",
    ".googleapis.com",
    ".akamai.net",
    ".akamaiedge.net",
    ".akamaihd.net",
    ".cloudflare.com",
    ".cdn.cloudflare.net",
    ".fastly.net",
    ".azurewebsites.net",
)


def detect_dga(
    dns_events: Sequence[DnsEvent],
    *,
    min_entropy: float = DEFAULT_MIN_ENTROPY,
    max_bigram_score: float = DEFAULT_MAX_BIGRAM_SCORE,
    min_label_length: int = DEFAULT_MIN_LABEL_LENGTH,
) -> tuple[Detection, ...]:
    """Score each DnsEvent's qname and emit Detections for DGA suspects.

    One Detection per unique `(src_ip, query_name)` pair — even if a
    DGA-shaped name is queried 100 times in the input, we emit one
    finding (downstream the operator filters by count).
    """
    if min_entropy <= 0:
        raise ValueError(f"min_entropy must be > 0; got {min_entropy}")
    if max_bigram_score < 0 or max_bigram_score > 1:
        raise ValueError(f"max_bigram_score must be in [0, 1]; got {max_bigram_score}")
    if min_label_length < 3:
        raise ValueError(f"min_label_length must be >= 3; got {min_label_length}")

    seen: set[tuple[str, str]] = set()
    out: list[Detection] = []
    seq_by_src: dict[str, int] = {}
    for ev in dns_events:
        key = (ev.src_ip, ev.query_name)
        if key in seen:
            continue
        seen.add(key)
        if _is_allowlisted(ev.query_name):
            continue
        label = _second_level_label(ev.query_name)
        if len(label) < min_label_length:
            continue
        entropy = _shannon_entropy(label)
        bigram_score = _bigram_score(label)
        if entropy < min_entropy:
            continue
        if bigram_score > max_bigram_score:
            continue
        seq_by_src[ev.src_ip] = seq_by_src.get(ev.src_ip, 0) + 1
        out.append(
            _to_detection(
                ev=ev,
                label=label,
                entropy=entropy,
                bigram_score=bigram_score,
                sequence=seq_by_src[ev.src_ip],
            )
        )
    return tuple(out)


def _is_allowlisted(qname: str) -> bool:
    lower = qname.lower()
    return any(lower.endswith(suffix) for suffix in _SUFFIX_ALLOWLIST)


def _second_level_label(qname: str) -> str:
    """Return the second-level label — the part of the domain holding the DGA randomness.

    `malicious.xyz` → `malicious`
    `aaa.bbb.example.com` → `example`
    `a.co` → `a`
    Single-label names → the label itself.
    """
    parts = [p for p in qname.lower().split(".") if p]
    if not parts:
        return ""
    if len(parts) == 1:
        return parts[0]
    return parts[-2]


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _bigram_score(s: str) -> float:
    """Fraction of consecutive bigrams in `s` that appear in `_COMMON_BIGRAMS`.

    Score in [0, 1]; 0 = none of the bigrams are common English, 1 = all are.
    Bigrams with non-alphabetic characters contribute 0 (so `a1b2` scores 0).
    """
    if len(s) < 2:
        return 0.0
    bigrams = [s[i : i + 2] for i in range(len(s) - 1)]
    if not bigrams:
        return 0.0
    matches = sum(1 for b in bigrams if b in _COMMON_BIGRAMS)
    return matches / len(bigrams)


def _to_detection(
    *,
    ev: DnsEvent,
    label: str,
    entropy: float,
    bigram_score: float,
    sequence: int,
) -> Detection:
    severity = _severity_for(entropy, bigram_score=bigram_score)
    finding_id = (
        f"NETWORK-DGA-{short_ip_token(ev.src_ip) if ev.src_ip else 'UNKNOWN'}-"
        f"{sequence:03d}-{label}"
    )
    return Detection(
        finding_type=FindingType.DGA,
        severity=severity,
        title=f"DGA-shaped DNS query: {ev.query_name}",
        description=(
            f"Second-level label {label!r} has Shannon entropy "
            f"{entropy:.2f} (threshold {DEFAULT_MIN_ENTROPY}) and bigram "
            f"score {bigram_score:.2f} (threshold ≤ {DEFAULT_MAX_BIGRAM_SCORE}). "
            f"Pattern consistent with domain-generation-algorithm output."
        ),
        detector_id=_DETECTOR_ID,
        src_ip=ev.src_ip,
        detected_at=ev.timestamp,
        evidence={
            "finding_id": finding_id,
            "query_name": ev.query_name,
            "second_level_label": label,
            "entropy": round(entropy, 4),
            "bigram_score": round(bigram_score, 4),
            "src_ip": ev.src_ip,
            "query_type": ev.query_type,
        },
    )


def _severity_for(entropy: float, *, bigram_score: float) -> Severity:
    if entropy >= 4.0 and bigram_score <= 0.05:
        return Severity.HIGH
    return Severity.MEDIUM


__all__ = [
    "DEFAULT_MAX_BIGRAM_SCORE",
    "DEFAULT_MIN_ENTROPY",
    "DEFAULT_MIN_LABEL_LENGTH",
    "detect_dga",
]
