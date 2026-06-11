"""D.6 v0.2 Task 3 — live kube-bench → OCSF 2003 normalization tests (byte-identical)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from k8s_posture.normalizers.kube_bench_live import normalize_live_kube_bench
from k8s_posture.tools.kube_bench import _read_sync
from k8s_posture.tools.kube_bench_live import parse_kube_bench_blob
from shared.fabric.envelope import NexusEnvelope

_T = datetime(2026, 6, 11, 12, 0, 0, tzinfo=UTC)


def _envelope() -> NexusEnvelope:
    return NexusEnvelope(
        correlation_id="corr_xyz",
        tenant_id="cust_test",
        agent_id="k8s_posture@0.2.0",
        nlah_version="0.2.0",
        model_pin="deterministic",
        charter_invocation_id="invocation_001",
    )


def _blob() -> dict[str, Any]:
    return {
        "Controls": [
            {
                "node_type": "master",
                "tests": [
                    {
                        "section": "1.2",
                        "desc": "API Server",
                        "results": [
                            {
                                "test_number": "1.2.1",
                                "test_desc": "Ensure anonymous-auth is not enabled",
                                "status": "FAIL",
                                "severity": "HIGH",
                                "remediation": "set --anonymous-auth=false",
                                "scored": True,
                            }
                        ],
                    }
                ],
            }
        ]
    }


def test_normalize_emits_class_uid_2003() -> None:
    kbf = parse_kube_bench_blob(_blob(), detected_at=_T)
    findings = normalize_live_kube_bench(kbf, envelope=_envelope(), scan_time=_T)
    assert len(findings) == 1
    assert findings[0].to_dict()["class_uid"] == 2003


def test_empty_findings() -> None:
    assert normalize_live_kube_bench([], envelope=_envelope(), scan_time=_T) == ()


def test_byte_identical_with_offline(tmp_path: Any) -> None:
    # Live KBFs → normalize == offline KBFs → normalize, for the same JSON + scan_time.
    p = tmp_path / "kb.json"
    p.write_text(json.dumps(_blob()), encoding="utf-8")
    offline_kbf = _read_sync(p)
    live_kbf = parse_kube_bench_blob(_blob(), detected_at=offline_kbf[0].detected_at)

    env = _envelope()
    offline = normalize_live_kube_bench(offline_kbf, envelope=env, scan_time=_T)
    live = normalize_live_kube_bench(live_kbf, envelope=env, scan_time=_T)
    assert [f.to_dict() for f in live] == [f.to_dict() for f in offline]
