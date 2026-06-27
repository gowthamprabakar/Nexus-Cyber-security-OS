"""B1 proof: the declarative taxonomy expresses every named archetype's (source, sink, edges) shape.

If a named archetype's source/sink/edges can't be expressed in the taxonomy, the taxonomy is wrong —
this test fails before the generic walker (B2) is built on a faulty model. Also pins the two
archetypes deliberately OUT of the exposure→impact model, so the accounting is complete.
"""

from charter.memory.graph_types import NodeCategory as NC
from meta_harness.attack_paths import _SEVERITY
from meta_harness.path_taxonomy import (
    SOURCE_MARKERS,
    is_traversable,
    match_sink,
    match_source,
)

# Each named exposure→impact archetype as (source node, sink node, edge path) — the shape its
# detector hardcodes. (category, representative-properties).
_EXPOSURE_IMPACT = {
    "crown_jewel": (
        (NC.CLOUD_RESOURCE, {"is_public": True}),
        (NC.DATA_CLASSIFICATION, {}),
        ["RUNS_IMAGE", "VULNERABLE_TO", "ASSUMES", "HAS_ACCESS_TO", "EXPOSES_DATA"],
    ),
    "public_secret": (
        (NC.CLOUD_RESOURCE, {"is_public": True}),
        (NC.DATA_CLASSIFICATION, {}),
        ["EXPOSES_DATA"],
    ),
    "internet_exposed_vulnerable": (
        (NC.CLOUD_RESOURCE, {"is_public": True}),
        (NC.CVE_FINDING, {}),
        ["RUNS_IMAGE", "VULNERABLE_TO"],
    ),
    "privileged_vulnerable": (
        (NC.K8S_OBJECT, {"privileged": True}),
        (NC.CVE_FINDING, {}),
        ["RUNS_IMAGE", "VULNERABLE_TO"],
    ),
    "public_unencrypted": (
        (NC.CLOUD_RESOURCE, {"is_public": True}),
        (NC.DATA_CLASSIFICATION, {}),
        ["EXPOSES_DATA"],
    ),
    "external_trust": (
        (NC.IDENTITY, {"external_trust": True}),
        (NC.DATA_CLASSIFICATION, {}),
        ["HAS_ACCESS_TO", "EXPOSES_DATA"],
    ),
    "exposed_ai_sensitive_data": (
        (NC.AI_SERVICE, {}),
        (NC.DATA_CLASSIFICATION, {}),
        ["HAS_ACCESS_TO", "EXPOSES_DATA"],
    ),
    "resource_based_data": (
        (NC.CLOUD_RESOURCE, {"policy_readers": ["arn:aws:iam::1:role/x"]}),
        (NC.DATA_CLASSIFICATION, {}),
        ["CONTAINS"],
    ),
    "fine_grained_data": (
        (NC.IDENTITY, {}),
        (NC.DATA_CLASSIFICATION, {}),
        ["HAS_ACCESS_TO", "EXPOSES_DATA"],
    ),
    "privilege_escalation": (
        (NC.IDENTITY, {}),
        (NC.DATA_CLASSIFICATION, {}),
        ["ASSUMES", "HAS_ACCESS_TO", "EXPOSES_DATA"],
    ),
    "runtime_exploit_vulnerable": (
        (NC.PROCESS_EVENT, {}),
        (NC.CVE_FINDING, {}),
        ["EXECUTED_ON", "RUNS_IMAGE", "VULNERABLE_TO"],
    ),
}

# Named archetypes that are a DIFFERENT correlation shape (not exposure→impact) and stay named-only.
_OUT_OF_MODEL = {"malicious_destination", "iac_misconfig_deployed"}


def test_every_exposure_impact_archetype_is_expressible():
    for name, ((src_cat, src_props), (sink_cat, sink_props), edges) in _EXPOSURE_IMPACT.items():
        assert match_source(src_cat.value, src_props) is not None, f"{name}: source not expressible"
        assert match_sink(sink_cat.value, sink_props) is not None, f"{name}: sink not expressible"
        for edge in edges:
            assert is_traversable(edge), f"{name}: edge {edge} not traversable"


def test_taxonomy_accounts_for_every_named_archetype():
    # Every named archetype is either expressible in the model or a documented out-of-model shape.
    assert _EXPOSURE_IMPACT.keys() | _OUT_OF_MODEL == set(_SEVERITY)


def test_non_attack_edges_are_not_traversable():
    # Control-plane / audit / compliance edges are not attack progression.
    for edge in ("AFFECTS", "MAPS_TO_REQUIREMENT", "REMEDIATES", "SATISFIES", "VIOLATES"):
        assert not is_traversable(edge)


def test_source_marker_specificity_order():
    # external_identity (specific) is matched before identity_principal (catch-all).
    assert match_source(NC.IDENTITY.value, {"external_trust": True}) == "external_identity"
    assert match_source(NC.IDENTITY.value, {}) == "identity_principal"
    names = [m.name for m in SOURCE_MARKERS]
    assert names.index("external_identity") < names.index("identity_principal")
