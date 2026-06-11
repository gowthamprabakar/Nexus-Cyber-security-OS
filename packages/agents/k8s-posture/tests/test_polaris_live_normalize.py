"""D.6 v0.2 Task 6 — live Polaris → OCSF 2003 normalization tests (byte-identical)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from k8s_posture.normalizers.polaris_live import normalize_live_polaris
from k8s_posture.tools.polaris import _read_sync
from k8s_posture.tools.polaris_live import parse_polaris_blob
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
        "Results": [
            {
                "Name": "web",
                "Namespace": "prod",
                "Kind": "Deployment",
                "PodResult": {
                    "ContainerResults": [
                        {
                            "Name": "app",
                            "Results": {
                                "runAsRootAllowed": {
                                    "ID": "runAsRootAllowed",
                                    "Success": False,
                                    "Severity": "danger",
                                    "Message": "Should not be allowed to run as root",
                                    "Category": "Security",
                                }
                            },
                        }
                    ]
                },
            }
        ]
    }


def test_normalize_emits_class_uid_2003() -> None:
    pf = parse_polaris_blob(_blob(), detected_at=_T)
    findings = normalize_live_polaris(pf, envelope=_envelope(), scan_time=_T)
    assert len(findings) == 1 and findings[0].to_dict()["class_uid"] == 2003


def test_empty_findings() -> None:
    assert normalize_live_polaris([], envelope=_envelope(), scan_time=_T) == ()


def test_byte_identical_with_offline(tmp_path: Any) -> None:
    p = tmp_path / "polaris.json"
    p.write_text(json.dumps(_blob()), encoding="utf-8")
    offline_pf = _read_sync(p)
    live_pf = parse_polaris_blob(_blob(), detected_at=offline_pf[0].detected_at)

    env = _envelope()
    offline = normalize_live_polaris(offline_pf, envelope=env, scan_time=_T)
    live = normalize_live_polaris(live_pf, envelope=env, scan_time=_T)
    assert [f.to_dict() for f in live] == [f.to_dict() for f in offline]
