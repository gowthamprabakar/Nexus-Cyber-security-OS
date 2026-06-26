"""Path 6 — privileged-pod parser (pure, no cluster). Flags pods with a privileged
container and pairs each with that container's image ref."""

from k8s_posture.tools.privileged_pods import privileged_workloads


def _pod(name, *, privileged, image="myreg/app:1.0", ns="default"):
    return {
        "metadata": {"name": name, "namespace": ns},
        "spec": {"containers": [{"image": image, "securityContext": {"privileged": privileged}}]},
    }


def test_privileged_pod_is_flagged_with_image():
    doc = {"items": [_pod("web", privileged=True)]}
    out = privileged_workloads(doc)
    assert len(out) == 1
    assert out[0].name == "web"
    assert out[0].namespace == "default"
    assert out[0].image_ref == "myreg/app:1.0"


def test_non_privileged_pod_is_ignored():
    assert privileged_workloads({"items": [_pod("web", privileged=False)]}) == []


def test_pod_without_security_context_is_ignored():
    doc = {"items": [{"metadata": {"name": "x"}, "spec": {"containers": [{"image": "i"}]}}]}
    assert privileged_workloads(doc) == []


def test_empty_returns_nothing():
    assert privileged_workloads({}) == []
    assert privileged_workloads({"items": []}) == []
