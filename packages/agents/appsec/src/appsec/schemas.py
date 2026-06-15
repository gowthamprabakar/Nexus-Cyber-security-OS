"""AppSec schemas — repo inventory + finding/report shapes (D.14 v0.1).

v0.1 (B-1 PR1) defines the substrate shapes: ``RepoRef`` / ``RepoInventory`` for
discovery, and ``Severity`` / ``AppSecFinding`` / ``FindingsReport`` ready for the
scanners that land in B-1 PR2+. No OCSF emission yet — the finding model is
intentionally minimal and additive.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class Severity(StrEnum):
    """Finding severity, aligned with the fleet's lowercase severity vocabulary."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class RepoRef(BaseModel):
    """A single discovered source repository (no secret material)."""

    model_config = ConfigDict(frozen=True)

    host: str = Field(min_length=1)  # github | gitlab | bitbucket
    owner: str = Field(min_length=1)
    name: str = Field(min_length=1)
    clone_url: str = Field(min_length=1)
    default_branch: str = "main"
    visibility: str = "unknown"  # public | private | internal | unknown

    @property
    def slug(self) -> str:
        """Stable ``host/owner/name`` identifier."""
        return f"{self.host}/{self.owner}/{self.name}"


class RepoInventory(BaseModel):
    """The repo-discovery output artifact (``repo_inventory.json``)."""

    agent: str
    agent_version: str
    customer_id: str
    run_id: str
    discovered_at: datetime
    repositories: tuple[RepoRef, ...] = ()

    @property
    def total(self) -> int:
        return len(self.repositories)


class AppSecFinding(BaseModel):
    """A single application-security finding (scanners populate these in B-1 PR2+)."""

    model_config = ConfigDict(frozen=True)

    finding_id: str
    rule_id: str
    severity: Severity
    title: str
    description: str
    repo_slug: str
    location: str = ""  # path[:line] within the repo


class FindingsReport(BaseModel):
    """The agent's findings artifact (``findings.json``)."""

    agent: str
    agent_version: str
    customer_id: str
    run_id: str
    scan_started_at: datetime
    scan_completed_at: datetime
    findings: list[AppSecFinding] = Field(default_factory=list)

    def add_finding(self, finding: AppSecFinding) -> None:
        self.findings.append(finding)

    @property
    def total(self) -> int:
        return len(self.findings)
