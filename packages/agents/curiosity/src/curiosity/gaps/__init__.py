"""Coverage-gap reasoning for curiosity v0.2 (Q4).

D.12 v0.1 shipped region-gap detection only. v0.2 adds per-tenant tunable region thresholds
(``region``) + two NEW gap kinds — ``technique`` (a MITRE technique unseen for N days) and
``time`` (an asset class not scanned in N hours). Per WI-X1 each gap kind is tracked separately.
"""
