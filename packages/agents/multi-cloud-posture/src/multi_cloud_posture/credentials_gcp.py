"""D.5 GCP credential-resolution seam (v0.2 Task 6).

Mirrors the **contract** of `cloud_posture.CredentialResolver` (Q1 — same shape,
GCP-native; literal charter hoist deferred to D.2 per ADR-007). The substrate seal
stays empty.

Resolves a `google-auth` credential via **Application Default Credentials** (Q3 —
one unified chain): a Service-Account key file (`GOOGLE_APPLICATION_CREDENTIALS`)
in dev, Workload Identity Federation in prod, both behind `google.auth.default()`.
Only the source **name** is stored; the secret material is resolved inside
`google-auth` and never passes through — or is logged by — this class.
"""

from __future__ import annotations

import os
from typing import Any

# Accepted `--gcp-credential-source` values. "adc" (the default) and
# "workload-identity" both flow through `google.auth.default()`;
# "service-account" loads an explicit key file.
GCP_CREDENTIAL_SOURCES = ("adc", "service-account", "workload-identity")


class GcpCredentialResolver:
    """Resolves a google-auth credential (+ default project) for a run.

    No source → ADC (`google.auth.default()`), the recommended default. The
    resolver's only state is the source name; no secret material is stored or
    logged.
    """

    __slots__ = ("_source",)

    def __init__(self, *, source: str | None = None) -> None:
        if source is not None and source not in GCP_CREDENTIAL_SOURCES:
            raise ValueError(
                f"unknown gcp credential source: {source!r}; "
                f"expected one of {GCP_CREDENTIAL_SOURCES}"
            )
        self._source = source

    @property
    def source(self) -> str | None:
        """The explicit source, or `None` for ADC."""
        return self._source

    def resolve_credential(self) -> tuple[Any, str | None]:
        """Return `(credentials, project_id)`.

        `None`/"adc"/"workload-identity" → `google.auth.default()` (project may be
        `None`). "service-account" → an explicit key file from
        `GOOGLE_APPLICATION_CREDENTIALS`, with the project read from the key.
        """
        if self._source == "service-account":
            from google.oauth2 import service_account

            path = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
            if not path:
                raise ValueError(
                    "gcp credential source 'service-account' requires "
                    "GOOGLE_APPLICATION_CREDENTIALS to point at a key file"
                )
            creds = service_account.Credentials.from_service_account_file(path)  # type: ignore[no-untyped-call]
            return creds, getattr(creds, "project_id", None)

        import google.auth

        credentials, project_id = google.auth.default()
        return credentials, project_id

    def client(self, client_cls: Any, **kwargs: Any) -> Any:
        """A GCP SDK client from the resolved credential."""
        credentials, _ = self.resolve_credential()
        return client_cls(credentials=credentials, **kwargs)
