"""``SSPMEvalRunner`` — the canonical ``EvalRunner`` for the D.10 SSPM agent (PR6).

Brings D.10 to fleet eval parity (mirrors the appsec / cloud-posture runners) so the
agent joins the meta-harness eval + skill-improvement loop.

Each case fixture drives one or more connectors with **structured** data (not raw URLs);
the runner builds the deterministic fakes (``_FakeHttp`` / ``_FakeGraph``) and injects them
into ``agent.run`` via the connector seams — then reads ``findings.json`` and compares to
``case.expected``.

Fixture keys (under ``fixture``):
- ``github: {org, two_factor_required, default_repository_permission,
  members_can_create_public_repos, repos: [{name, private, default_branch, protected,
  security_and_analysis}]}``
- ``m365: {tenant, security_defaults_enabled, allow_invites_from, user_consent,
  conditional_access_count, global_admins, oauth_grants: [{client_id, scopes}]}``
- ``slack: {team_id, team_name, members: [...], approved_apps: [{id, name, scopes}]}``

Comparison shape (under ``expected``):
- ``finding_count: int`` — total OCSF 2003 findings.
- ``by_type: {discriminator: int}`` — per ``finding_info.types[0]``, checked when present.

Registered via ``pyproject.toml`` ``[project.entry-points."nexus_eval_runners"]``.
"""

from __future__ import annotations

import json
import os
from collections import Counter
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from charter.contract import BudgetSpec, ExecutionContract
from charter.llm import LLMProvider
from eval_framework.cases import EvalCase
from eval_framework.runner import RunOutcome

from sspm import agent as agent_mod
from sspm.tools.github_org import GITHUB_API
from sspm.tools.slack import SLACK_API

_PERMITTED = ["read_github_org", "read_m365_tenant", "read_slack_workspace"]
_DUMMY_ENV = {
    "NEXUS_SSPM_GITHUB_TOKEN": "ghp_eval",
    "NEXUS_SSPM_SLACK_TOKEN": "xoxb-eval",
}


class _FakeHttp:
    def __init__(self, routes: dict[str, tuple[int, dict[str, str], Any]]) -> None:
        self.routes = routes

    async def get(
        self, url: str, *, headers: dict[str, str] | None = None
    ) -> tuple[int, dict[str, str], Any]:
        return self.routes.get(url, (404, {}, {"ok": False}))


class _FakeGraph:
    def __init__(
        self, collections: dict[str, list[dict[str, Any]]], objects: dict[str, dict[str, Any]]
    ) -> None:
        self._c = collections
        self._o = objects

    async def get_all(self, resource: str, *, select: str | None = None) -> list[dict[str, Any]]:
        return self._c.get(resource, [])

    async def get_one(self, resource: str) -> dict[str, Any]:
        return self._o.get(resource, {})


@contextmanager
def _dummy_tokens() -> Any:
    saved = {k: os.environ.get(k) for k in _DUMMY_ENV}
    os.environ.update(_DUMMY_ENV)
    try:
        yield
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def _github_routes(gh: dict[str, Any]) -> dict[str, tuple[int, dict[str, str], Any]]:
    org = str(gh["org"])
    routes: dict[str, tuple[int, dict[str, str], Any]] = {
        f"{GITHUB_API}/orgs/{org}": (
            200,
            {},
            {
                "two_factor_requirement_enabled": gh.get("two_factor_required"),
                "default_repository_permission": gh.get("default_repository_permission", "read"),
                "members_can_create_public_repositories": gh.get(
                    "members_can_create_public_repos", False
                ),
            },
        )
    }
    repos: list[dict[str, Any]] = []
    for r in gh.get("repos", []):
        branch = str(r.get("default_branch", "main"))
        repos.append(
            {
                "name": r["name"],
                "private": r.get("private", True),
                "default_branch": branch,
                "security_and_analysis": r.get("security_and_analysis"),
            }
        )
        prot = r.get("protected")
        status = 200 if prot is True else 404 if prot is False else 403
        routes[f"{GITHUB_API}/repos/{org}/{r['name']}/branches/{branch}/protection"] = (
            status,
            {},
            {},
        )
    routes[f"{GITHUB_API}/orgs/{org}/repos?per_page=100"] = (200, {}, repos)
    return routes


def _m365_fake(m: dict[str, Any]) -> _FakeGraph:
    objects: dict[str, dict[str, Any]] = {}
    if "security_defaults_enabled" in m:
        objects["policies/identitySecurityDefaultsEnforcementPolicy"] = {
            "isEnabled": m["security_defaults_enabled"]
        }
    objects["policies/authorizationPolicy"] = {
        "allowInvitesFrom": m.get("allow_invites_from", "adminsAndGuestInviters"),
        "defaultUserRolePermissions": {
            "permissionGrantPoliciesAssigned": ["x"] if m.get("user_consent") else []
        },
    }
    collections: dict[str, list[dict[str, Any]]] = {
        "identity/conditionalAccessPolicies": [{}] * int(m.get("conditional_access_count", 0)),
        "oauth2PermissionGrants": [
            {"clientId": g["client_id"], "scope": " ".join(g.get("scopes", []))}
            for g in m.get("oauth_grants", [])
        ],
    }
    admins = m.get("global_admins")
    if admins is not None:
        collections["directoryRoles"] = [
            {"id": "ga", "roleTemplateId": "62e90394-69f5-4237-9190-012177145e10"}
        ]
        collections["directoryRoles/ga/members"] = [{"id": f"u{i}"} for i in range(int(admins))]
    return _FakeGraph(collections, objects)


def _slack_routes(s: dict[str, Any]) -> dict[str, tuple[int, dict[str, str], Any]]:
    apps = s.get("approved_apps")
    apps_resp: tuple[int, dict[str, str], Any] = (
        (
            200,
            {},
            {
                "ok": True,
                "approved_apps": [
                    {
                        "app": {"id": a["id"], "name": a.get("name", "")},
                        "scopes": a.get("scopes", []),
                    }
                    for a in apps
                ],
            },
        )
        if apps is not None
        else (200, {}, {"ok": False, "error": "not_an_enterprise_install"})
    )
    return {
        f"{SLACK_API}/team.info": (
            200,
            {},
            {"ok": True, "team": {"id": s.get("team_id", "T0"), "name": s.get("team_name", "")}},
        ),
        f"{SLACK_API}/users.list?limit=200": (
            200,
            {},
            {"ok": True, "members": list(s.get("members", [])), "response_metadata": {}},
        ),
        f"{SLACK_API}/admin.apps.approved.list?limit=100": apps_resp,
    }


class SSPMEvalRunner:
    """Reference ``EvalRunner`` for the SSPM agent."""

    @property
    def agent_name(self) -> str:
        return "sspm"

    async def run(
        self,
        case: EvalCase,
        *,
        workspace: Path,
        llm_provider: LLMProvider | None = None,
    ) -> RunOutcome:
        del llm_provider  # SSPM connectors are deterministic; no LLM in the loop
        workspace.mkdir(parents=True, exist_ok=True)
        contract = _build_contract(case, workspace)
        fx = case.fixture

        kwargs: dict[str, Any] = {}
        if "github" in fx:
            kwargs["github_org"] = str(fx["github"]["org"])
            kwargs["github_transport"] = _FakeHttp(_github_routes(fx["github"]))
        if "m365" in fx:
            kwargs["m365_tenant"] = str(fx["m365"].get("tenant", "tenant"))
            kwargs["m365_graph"] = _m365_fake(fx["m365"])
        if "slack" in fx:
            kwargs["slack_workspace"] = True
            kwargs["slack_transport"] = _FakeHttp(_slack_routes(fx["slack"]))

        with _dummy_tokens():
            await agent_mod.run(contract, **kwargs)

        ws = Path(contract.workspace)
        findings = _read_findings(ws)
        by_type = Counter(f["finding_info"]["types"][0] for f in findings)
        actuals: dict[str, Any] = {"finding_count": len(findings), "by_type": dict(by_type)}
        passed, reason = _evaluate(case, len(findings), by_type)
        audit = ws / "audit.jsonl"
        return passed, reason, actuals, audit if audit.exists() else None


def _read_findings(workspace: Path) -> list[dict[str, Any]]:
    path = workspace / "findings.json"
    if not path.is_file():
        return []
    doc = json.loads(path.read_text(encoding="utf-8"))
    out: list[dict[str, Any]] = doc.get("findings", [])
    return out


def _build_contract(case: EvalCase, workspace_root: Path) -> ExecutionContract:
    return ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="sspm",
        customer_id="cust_eval",
        task=case.description or case.case_id,
        required_outputs=["findings.json", "summary.md"],
        budget=BudgetSpec(
            llm_calls=1, tokens=1, wall_clock_sec=60.0, cloud_api_calls=200, mb_written=10
        ),
        permitted_tools=_PERMITTED,
        completion_condition="findings.json AND summary.md exist",
        escalation_rules=[],
        workspace=str(workspace_root / "ws"),
        persistent_root=str(workspace_root / "p"),
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )


def _evaluate(case: EvalCase, finding_count: int, by_type: Counter[str]) -> tuple[bool, str | None]:
    expected_count = case.expected.get("finding_count")
    if expected_count is not None and finding_count != int(expected_count):
        return False, f"finding_count expected {expected_count}, got {finding_count}"
    for disc, want in (case.expected.get("by_type") or {}).items():
        actual = by_type.get(str(disc), 0)
        if actual != int(want):
            return False, f"by_type '{disc}' expected {want}, got {actual}"
    return True, None


__all__ = ["SSPMEvalRunner"]
