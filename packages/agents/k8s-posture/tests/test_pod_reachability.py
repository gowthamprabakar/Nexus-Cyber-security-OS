"""W4 red-team bank — pod-to-pod reachability precision (default-allow, isolation, namespace)."""

from k8s_posture.tools.pod_reachability import PodRef, pod_reach_grants

_C = "arn:aws:eks:us-east-1:1:cluster/prod"


def _p(name, ns="prod", isolated=False):
    return PodRef(pod_id=f"{_C}/namespace/{ns}/pod/{name}", namespace=ns, isolated=isolated)


def test_flat_namespace_pods_reach_each_other():
    grants = pod_reach_grants((_p("a"), _p("b")))
    ids = {(s.rsplit("/", 1)[-1], d.rsplit("/", 1)[-1]) for s, d in grants}
    assert ("a", "b") in ids and ("b", "a") in ids


def test_isolated_destination_not_reachable():
    grants = pod_reach_grants((_p("a"), _p("db", isolated=True)))
    dsts = {d.rsplit("/", 1)[-1] for _s, d in grants}
    assert "db" not in dsts  # nobody reaches the isolated pod


def test_cross_namespace_not_reachable():
    grants = pod_reach_grants((_p("a", ns="prod"), _p("b", ns="staging")))
    assert grants == []


def test_no_self_edge():
    grants = pod_reach_grants((_p("solo"),))
    assert grants == []


def test_source_bounding_avoids_n_squared():
    # NEX-408: with source_pod_ids, only edges FROM the foothold are emitted (O(|src|·n) not O(n²)).
    a, b, c = _p("a"), _p("b"), _p("c")
    foothold = frozenset({a.pod_id})
    grants = pod_reach_grants((a, b, c), source_pod_ids=foothold)
    assert {s for s, _d in grants} == {a.pod_id}  # only 'a' is a source
    assert len(grants) == 2  # a→b, a→c (not the full 6 pairs)
