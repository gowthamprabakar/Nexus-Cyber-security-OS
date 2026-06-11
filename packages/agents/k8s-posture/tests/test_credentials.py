"""D.6 v0.2 Task 15 — kubeconfig credential safety tests (WI-K9)."""

from __future__ import annotations

from k8s_posture.credentials import (
    SafeKubeconfig,
    redact_kubeconfig,
    redact_secret_value,
)

_KUBECONFIG = """\
apiVersion: v1
clusters:
- cluster:
    server: https://eks.example.com
  name: prod
users:
- name: prod
  user:
    token: super-secret-bearer-token-abc123
    client-certificate-data: BASE64CERTDATA==
    client-key-data: BASE64KEYDATA==
"""


def test_safe_kubeconfig_repr_has_no_secret() -> None:
    cfg = SafeKubeconfig("/home/user/.kube/config")
    assert "config" in repr(cfg) and "token" not in repr(cfg).lower()
    assert cfg.path == "/home/user/.kube/config"


def test_redact_kubeconfig_redacts_token() -> None:
    out = redact_kubeconfig(_KUBECONFIG)
    assert "super-secret-bearer-token-abc123" not in out
    assert "REDACTED" in out


def test_redact_kubeconfig_redacts_cert_and_key() -> None:
    out = redact_kubeconfig(_KUBECONFIG)
    assert "BASE64CERTDATA==" not in out and "BASE64KEYDATA==" not in out


def test_redact_kubeconfig_preserves_non_secrets() -> None:
    out = redact_kubeconfig(_KUBECONFIG)
    assert "server: https://eks.example.com" in out and "name: prod" in out


def test_redact_secret_value() -> None:
    assert redact_secret_value("token", "abc") == "***REDACTED***"
    assert redact_secret_value("client-key-data", "k") == "***REDACTED***"
    assert redact_secret_value("server", "https://x") == "https://x"


def test_redact_is_case_insensitive() -> None:
    assert redact_kubeconfig("    Token: secretval").endswith("REDACTED***")
