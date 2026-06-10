"""Tests for the hoisted cloud-agnostic CredentialResolver contract (Pattern A, Task 4)."""

from __future__ import annotations

from typing import Any

import pytest
from charter import CredentialResolver
from charter.credentials import CredentialResolver as CredentialResolverDirect


class _AwsLike(CredentialResolver):
    """A boto3-shaped resolver (mirrors F.3): `_profile` slot, `client(service, region)`."""

    __slots__ = ("_profile",)

    def __init__(self, *, profile: str | None = None) -> None:
        self._profile = profile

    @property
    def profile(self) -> str | None:
        return self._profile

    def client(self, service: str, *, region: str | None = None) -> Any:
        return ("aws", service, region, self._profile)


class _AzureLike(CredentialResolver):
    """An azure-identity-shaped resolver (mirrors D.5): `_source` slot, different client sig."""

    __slots__ = ("_source",)

    def __init__(self, *, source: str | None = None) -> None:
        self._source = source

    @property
    def source(self) -> str | None:
        return self._source

    def client(self, client_cls: Any, *, subscription_id: str | None = None) -> Any:
        return ("azure", client_cls, subscription_id, self._source)


def test_export_is_same_object() -> None:
    assert CredentialResolver is CredentialResolverDirect


def test_abstract_base_cannot_be_instantiated() -> None:
    with pytest.raises(TypeError):
        CredentialResolver()  # type: ignore[abstract]


def test_subclass_missing_client_cannot_instantiate() -> None:
    class _NoClient(CredentialResolver):
        __slots__ = ()

    with pytest.raises(TypeError):
        _NoClient()  # type: ignore[abstract]


def test_aws_like_conforms_and_works() -> None:
    r = _AwsLike(profile="prod")
    assert isinstance(r, CredentialResolver)
    assert r.profile == "prod"
    assert r.client("iam") == ("aws", "iam", None, "prod")
    assert r.client("s3", region="us-west-2") == ("aws", "s3", "us-west-2", "prod")


def test_azure_like_conforms_with_different_client_signature() -> None:
    r = _AzureLike(source="cli")
    assert isinstance(r, CredentialResolver)
    assert r.source == "cli"
    assert r.client(object, subscription_id="sub-1")[0] == "azure"


def test_none_identifier_is_the_default_chain_semantic() -> None:
    assert _AwsLike().profile is None
    assert _AzureLike().source is None


def test_subclass_owns_its_own_slot_not_the_base() -> None:
    # The base is stateless; each subclass keeps its own identifier slot.
    assert CredentialResolver.__slots__ == ()
    assert _AwsLike.__slots__ == ("_profile",)
    assert {s: getattr(_AwsLike(profile="p"), s) for s in _AwsLike.__slots__} == {"_profile": "p"}


def test_instances_are_slot_only_no_dict() -> None:
    # Secret-safety is structural: no __dict__ to stash arbitrary material on.
    r = _AwsLike(profile="p")
    assert not hasattr(r, "__dict__")
