"""Pure-function detector rules for the D.5 Data Security agent.

Each detector module exports a single ``detect_*`` function. Detectors
are pure: same input → same output, no I/O, no module state. They
consume ``BucketInventory`` + optional classifier-hit signals and
return ``list[CloudPostureFinding]`` (0 or 1 finding per bucket in
v0.1; later detectors may emit multiple).

Severity policy (per plan Tasks 5-8):

- Each detector flags HIGH (or its base severity) on rule violation.
- CRITICAL uplift occurs when a classifier hit (any non-NONE label)
  is present on objects inside the same bucket.
- The CORRELATE stage (Task 9) may add a second uplift level based
  on sibling F.3 cloud-posture findings; the SCORE stage (Task 10)
  applies it. Detectors do not perform F.3 correlation themselves.
"""

from __future__ import annotations

from data_security.detectors.public_bucket import detect_public_bucket
from data_security.detectors.unencrypted import detect_unencrypted

__all__ = ["detect_public_bucket", "detect_unencrypted"]
