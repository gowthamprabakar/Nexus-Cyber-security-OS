"""W2 — the privileged-pod detector must surface the pod's service account (the IRSA bridge)."""

from k8s_posture.tools.privileged_pods import privileged_workloads


def _pod(name, *, sa=None, privileged=True):
    spec = {"containers": [{"image": "img:1", "securityContext": {"privileged": privileged}}]}
    if sa is not None:
        spec["serviceAccountName"] = sa
    return {"metadata": {"namespace": "prod", "name": name}, "spec": spec}


def test_extracts_explicit_service_account():
    out = privileged_workloads({"items": [_pod("p1", sa="ci-runner")]})
    assert out[0].service_account == "ci-runner"


def test_defaults_to_default_sa_when_unset():
    out = privileged_workloads({"items": [_pod("p2")]})
    assert out[0].service_account == "default"


def test_non_privileged_pod_is_not_returned():
    out = privileged_workloads({"items": [_pod("p3", sa="x", privileged=False)]})
    assert out == []
