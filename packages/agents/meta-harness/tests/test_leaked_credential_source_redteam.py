"""Red-team bank for the slice #3 leaked-credential source marker — the toxic-combination crux.

The blast-radius path must light up ONLY for a credential actually leaked in code (appsec
``leaked=True``), never for a key the identity agent merely inventoried. This pins that precision:
the source marker, not the SECRET node alone, is what makes a leak an attack source.
"""

from charter.memory.graph_types import NodeCategory
from meta_harness.path_taxonomy import match_source

_SECRET = NodeCategory.SECRET.value
_IDENTITY = NodeCategory.IDENTITY.value


def test_leaked_secret_is_a_source():
    assert match_source(_SECRET, {"kind": "aws-access-key", "leaked": True}) == "leaked_credential"


def test_owned_but_not_leaked_secret_is_not_a_source():
    # identity inventories every access key (OWNS); only appsec sets leaked=True. A merely-owned
    # key must NOT be an attack source, or every IAM user's key would manufacture a false path.
    assert match_source(_SECRET, {"kind": "aws-access-key"}) is None


def test_leaked_flag_must_be_true_not_just_present():
    assert match_source(_SECRET, {"kind": "aws-access-key", "leaked": False}) is None


def test_leaked_flag_on_non_secret_node_does_not_match_this_marker():
    # The marker is SECRET-scoped; a stray leaked= on another category must not trip it.
    assert match_source(_IDENTITY, {"leaked": True}) != "leaked_credential"
