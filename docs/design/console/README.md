# Nexus Cyber OS — Console UI Mockups

Reference UI mockups for the Nexus Cyber OS operator console. Generated with [Google Stitch](https://stitch.withgoogle.com) and preserved here as the design-time source-of-truth for the eventual frontend implementation (Tracks S.1–S.4, currently zero-LOC).

## What's here

42 screen mockups + 1 design system doc. Each screen directory contains:

- `code.html` — the rendered Tailwind-based prototype (open in a browser).
- `screen.png` — a flat screenshot of the mockup.

The [`obsidian/DESIGN.md`](obsidian/DESIGN.md) file captures the design system (palette, typography, elevation rules) shared across every screen.

## Screen catalog (grouped)

### Command surfaces

- [`command_center_obsidian_theme/`](command_center_obsidian_theme/) — main operator landing page (Obsidian theme)
- [`conversation_workspace_obsidian_theme/`](conversation_workspace_obsidian_theme/) — agent conversation workspace
- [`briefing_room_nexus_cyber_os/`](briefing_room_nexus_cyber_os/) — exec briefing surface
- [`audit_theatre_nexus_cyber_os/`](audit_theatre_nexus_cyber_os/) — F.6 audit replay theatre
- [`compliance_theatre_nexus_cyber_os/`](compliance_theatre_nexus_cyber_os/) — compliance evidence theatre

### Findings (per-track surfaces — map to ADR-007 agents)

- [`cspm_findings_nexus_cyber_os/`](cspm_findings_nexus_cyber_os/) — F.3 / D.5 / D.6 (CSPM family)
- [`workload_findings_cwpp_nexus_cyber_os/`](workload_findings_cwpp_nexus_cyber_os/) — D.3 CWPP
- [`identity_findings_ciem_nexus_cyber_os/`](identity_findings_ciem_nexus_cyber_os/) — D.2 CIEM
- [`vulnerability_findings_nexus_cyber_os/`](vulnerability_findings_nexus_cyber_os/) — D.1 vulnerability
- [`network_findings_nexus_cyber_os/`](network_findings_nexus_cyber_os/) — D.4 network threat
- [`data_security_findings_nexus_cyber_os/`](data_security_findings_nexus_cyber_os/) — data security findings
- [`finding_detail_reasoning_first_nexus_cyber_os/`](finding_detail_reasoning_first_nexus_cyber_os/) — single-finding deep-dive

### Inventory

- [`asset_inventory_nexus_cyber_os/`](asset_inventory_nexus_cyber_os/)
- [`identity_inventory_nexus_cyber_os/`](identity_inventory_nexus_cyber_os/)
- [`data_inventory_nexus_cyber_os/`](data_inventory_nexus_cyber_os/)

### Investigation + remediation

- [`attack_path_explorer_nexus_cyber_os/`](attack_path_explorer_nexus_cyber_os/) — D.7 attack-path correlation
- [`investigation_workspace_nexus_cyber_os/`](investigation_workspace_nexus_cyber_os/) — D.7 investigation surface
- [`approval_queue_nexus_cyber_os/`](approval_queue_nexus_cyber_os/) — Track-A Tier-3 approval gate
- [`approval_detail_nexus_cyber_os/`](approval_detail_nexus_cyber_os/) — single-approval deep-dive
- [`autonomous_action_log_nexus_cyber_os/`](autonomous_action_log_nexus_cyber_os/) — Track-A action chain
- [`remediation_orchestration_nexus_cyber_os/`](remediation_orchestration_nexus_cyber_os/) — Track-A orchestration

### Compliance

- [`compliance_overview_nexus_cyber_os/`](compliance_overview_nexus_cyber_os/)
- [`compliance_framework_detail_nexus_cyber_os/`](compliance_framework_detail_nexus_cyber_os/)

### Platform / admin

- [`integrations_nexus_cyber_os/`](integrations_nexus_cyber_os/) — connector / integration catalog
- [`refined_integration_setup_nexus_cyber_os/`](refined_integration_setup_nexus_cyber_os/) — connector setup flow
- [`configuration_administration_nexus_cyber_os/`](configuration_administration_nexus_cyber_os/)
- [`policy_administration_nexus_cyber_os/`](policy_administration_nexus_cyber_os/)
- [`team_directory_nexus_cyber_os/`](team_directory_nexus_cyber_os/)
- [`tenant_administration_nexus_cyber_os/`](tenant_administration_nexus_cyber_os/)
- [`reporting_subscriptions_nexus_cyber_os/`](reporting_subscriptions_nexus_cyber_os/)
- [`schedules_jobs_nexus_cyber_os/`](schedules_jobs_nexus_cyber_os/)
- [`custom_dashboards_builder_nexus_cyber_os/`](custom_dashboards_builder_nexus_cyber_os/)

### Builder / dev

- [`agent_workshop_nexus_cyber_os/`](agent_workshop_nexus_cyber_os/) — agent prompt-editing workspace
- [`api_developer_portal_nexus_cyber_os/`](api_developer_portal_nexus_cyber_os/) — public API portal
- [`self_evolution_dashboard_nexus_cyber_os/`](self_evolution_dashboard_nexus_cyber_os/) — meta-harness self-improvement dashboard

## How to use

- **Designers / PMs**: open `code.html` in a browser; click around. The mockups are static HTML — no backend wiring.
- **Frontend implementers** (when Tracks S.1–S.4 land): use these mockups as the visual contract; the Obsidian palette + typography from `obsidian/DESIGN.md` is normative.
- **Agent owners**: cross-link the relevant screen from your agent's `README.md` if you want operator-facing context (e.g., `cspm_findings_nexus_cyber_os/` from `packages/agents/cloud-posture/README.md`).

## Status

These are **design artifacts**, not implementation. The frontend is currently zero-LOC (Tracks S.1–S.4 deliberately deferred behind detection track per the phase plan). Mockups will be revised iteratively as the agent surface stabilises.
