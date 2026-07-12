# Making the Vulnerability-Management persona real — design

**Status:** approved (brainstorming), pending spec review
**Date:** 2026-07-12
**Grounding:** the deep gap analysis at `scratchpad/gap-analysis.html` (five-analyst teardown of the Nexus Console mock's Vuln persona, judged at three layers: mock frontend / read-API backend / core engine) + `scratchpad/engine-facts.md`.

## Problem

The Nexus Console mock is a pixel-perfect **design prototype**, not a working app: it makes zero backend calls, every number is a hardcoded literal, and every action is a toast or has no handler. We have a real engine and a real read-API (10 endpoints, PR #811) but the two are not connected. The goal is to make the Vuln persona **real end-to-end** — the mock's exact design, driven by real engine data, with working controls — built in verifiable slices, no lipstick.

## Decisions (from brainstorming)

1. **Plan structure:** produce the full sequenced program roadmap, then write a detailed buildable spec+plan for **slice 1 only** (frontend rebuild + wiring). Later phases are specced when we reach them. Rationale: the scope spans ~10 independent subsystems of very different sizes; detail-planning all of them at once (especially the safety-critical remediation engine) produces a plan that is thin exactly where it is most dangerous.
2. **Frontend vehicle:** rebuild the frontend in React (`apps/web`, already scaffolded) **reusing the mock's exact CSS + markup**, driven by the read-API, with genuinely working buttons. Not a reinterpretation — a faithful port. Rationale: the mock is a Stitch-exported single HTML file that loads React from a CDN and compiles a custom framework (DCLogic) in-browser — not shippable or maintainable. A faithful port preserves the design byte-for-byte while producing a real product.
3. **Gap handling:** every page/control from the mock is present in the rebuilt app; anything without a producer shows a **truthful gap-state** ("End-of-Life scanning not available yet", Cure Execute disabled with "needs the remediation engine", etc.) that flips to real as each backend lands. No hidden nav, no sample-data lipstick.

## Program roadmap (the full sequence)

| Phase                                 | What                                                                                                                                                                                                                                                                                                                                                                                                                                                   | Size / notes                          |
| ------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------- |
| **1. Frontend rebuild + live wiring** | _Slice 1 (detailed below)._ Vuln persona rebuilt in React reusing the mock's design; wired to the 10 existing read-API endpoints; 7 backend-real pages live, rest gap-stated; free actions working; fixes wrong columns/attributions + the **secp256k1 copy**.                                                                                                                                                                                         | days; backend already exists          |
| **2. Backend wiring / expose**        | Read-only endpoints for what the engine already computes but hides: attack-paths (graph + Top Issues + Investigation), CSPM findings, per-finding detail-join, audit hashes in the list, posture→board aggregates. Then flip the corresponding gap-stated pages to real.                                                                                                                                                                               | days                                  |
| **3. Backend gap endpoints**          | Action/write endpoints the buttons need where a core capability exists to back them: saved views, ignore-rules, export service, comments.                                                                                                                                                                                                                                                                                                              | days                                  |
| **4. Core producers**                 | Each its own spec→plan→build, in dependency order: Threat-Intel surfacing (D.8 exists — cheapest) → Time-series/trends store (unblocks every delta + the Opened-vs-Resolved chart + Overview) → Security Score → Cure-Queue store → End-of-Life (needs a data-source decision) → Ask-Nexus AI → **Cloud remediation engine** (safety-critical; its own gated program — dry-run/execute/contract/rollback; the advisory tier is all that exists today). | weeks; remediation is safety-critical |
| **5. Test + verify**                  | Woven into every slice, not a trailing phase: automated tests + page-by-page fidelity approval per slice.                                                                                                                                                                                                                                                                                                                                              | continuous                            |

Non-goal for this document: detailing phases 2–5. They get their own spec when reached.

## Slice 1 — detailed design (frontend rebuild + live wiring)

**Goal:** the Vuln persona, rebuilt in `apps/web` reusing the mock's exact design, real end-to-end for everything the current backend supports, honest gap-states for the rest.

### Architecture — faithful port, not reinterpretation

The mock styles everything with CSS variables (from `themes()`) + ~1,611 inline `style=` attributes and **zero classes**, across 2 global `<style>` blocks (Stitch output). The port is therefore mechanical and fidelity-preserving:

- Extract the mock's 2 `<style>` blocks + the `themes()` variables → the app's global stylesheet + `:root` dark/light CSS variables, **byte-identical**.
- Port each view's markup **including its inline styles** into a React component, swapping only the framework:
  - `{{ binding }}` → React props / expressions
  - `<sc-for list="{{x}}" as="v">` → `x.map(v => …)`
  - `<sc-if value="{{c}}">` → `{c && …}`
  - `on*="{{ handler }}"` → `onClick={…}` (real handler)
- The design (every color, spacing, inline style) is preserved verbatim; only **DCLogic→React** and **hardcoded-data→read-API** change. This is why fidelity is achievable — we copy the design, we do not redraw it.

The mock/component source is already unwrapped to `scratchpad/mock-component.js` (logic + `themes()` + data method shapes) and `scratchpad/mock-markup.html` (per-view markup) for reference.

### Components (units, each independently testable)

- **`AppShell`** — the sidebar (persona picker + sectioned nav from `personas()`), top bar (project/scope/search/trial/theme/avatar), trial banner, and client-side view state (mirrors the mock's `state.view` / `state.persona`). Owns routing between pages.
- **7 page components**, each bound to its read-API endpoint through the existing `apps/web/src/api/client.ts`:
  - `VulnerabilityFindings` → `/v1/findings/vulnerabilities` (+ detail)
  - `Catalog` → `/v1/findings/catalog`
  - `Patch` → `/v1/findings/available-fixes`
  - `Sbom` → `/v1/inventory/sbom`
  - `ContainerImages` → `/v1/inventory/container-images`
  - `CloudResources` → `/v1/inventory/cloud-resources`
  - `AuditChain` → `/v1/audit` (+ `/v1/audit/verify`)
- **`DetailPanel`** — the shared finding drawer, driven by the selected row (full per-finding detail arrives in Phase 2 via a detail-join endpoint; slice 1 uses the row data + the existing `/v1/findings/vulnerabilities/{cve}` detail endpoint where applicable).
- **`GapState`** — a single shared component rendering the honest "not available yet — needs `<producer>`" state, used for every page/control without a backend.
- Reuse the existing `apps/web` `api/client.ts`, `api/types.ts`, and `auth/TenantProvider.tsx`.

### Data flow + states

`page → client.ts fetch → read-API (tenant-scoped via X-Tenant-Id) → render`. Every list/data component implements four states: **loading**, **error + retry**, **empty**, and **gap** (via `GapState`). No hardcoded rows anywhere — real data or an honest state.

### Correctness fixes carried in slice 1 (from the gap analysis)

- **Container Images:** show the endpoint's real fields (`packages`, `vulnerabilities` counts), not the findings column set.
- **Cloud Resources:** show `is_public`, `region`, `cloud`, and the real `kind`; drop the phantom Severity column the endpoint has no field for.
- **Catalog:** show KEV / EPSS / affected-count columns the endpoint provides.
- **Attribution:** correct Catalog/Patch/EOL from "D.3 Cloud Posture" to the right agent (D.1).
- **Audit chain copy:** replace "signature valid · secp256k1" with "hash-chained · integrity verified" — the engine is SHA-256 hash-chained, not signed. **This is a must-fix false product claim.**

### Working actions in slice 1 (the "free" ones — backend already exists)

- **Filters** (severity, and any the endpoints support) → sent as query params to the read-API.
- **Verify integrity** (Audit page) → real call to `/v1/audit/verify`, rendering the actual verdict.
- **Export** → client-side serialization of the loaded data to a downloaded file.

Every other action (Cure simulate/execute, Ignore, Save-as, Ask-Nexus send, comments, bulk actions) → the honest `GapState` / disabled-with-a-reason, because its backend does not exist yet (phases 2–4).

### Testing (your "testcase for everything")

- **Component tests** (vitest + `@testing-library/react`, extending the existing `apps/web` pattern) per page: renders real data, each of the four states, filter behavior, and the gap-state where applicable.
- **Endpoint tests** already exist for the read-API; any endpoint touched gets its test updated.
- **Fidelity gate:** a headless screenshot of each rebuilt page, served over http with real timing (the method that matches a real browser, not virtual-time), placed beside the mock screenshot for **page-by-page eye-approval by the operator** before moving to the next page.
- **Full suite green** before the slice is "done": `uv run mypy` (no args) + `uv run pytest` + `pnpm --filter nexus-web run typecheck && lint && test && build`.

### Build sequence (task order; each task = build → verify → operator approval)

1. **AppShell** — extract mock CSS/theme, build the shell (sidebar + top bar + view routing), gap-state placeholder pages.
2. **VulnerabilityFindings** — the **fidelity proof**. Rebuilt from the mock's markup, wired to the real endpoint, all four states, filters. Operator eye-approves against the mock before continuing.
3. **The other 6 pages** — Catalog, Patch, SBOM, Container Images, Cloud Resources, Audit — one task each, applying the proven pattern + the correctness fixes.
4. **DetailPanel** — per-finding drawer with real row data.
5. **GapState wiring** — every gap page/control shows its honest state.
6. **Free actions** — filters as query params, Verify-integrity, Export.
7. **Tests + fidelity pass + full-suite green.**

## Non-goals / explicitly deferred

- All of phases 2–5 (backend expose/gaps, core producers, remediation engine) — specced later.
- The **cloud remediation engine** is safety-critical and out of scope for any near-term slice; Cure actions stay gap-stated.
- No new design — the rebuild reproduces the mock exactly; visual changes are out of scope.

## Success criteria for slice 1

- The Vuln persona renders in `apps/web` **indistinguishable from the mock** (operator-approved page-by-page).
- The 7 backend-real pages show **genuine read-API data** with working loading/error/empty states.
- Every gap page/control shows an **honest state** naming what it needs — no fake data, no dead buttons pretending to work.
- The secp256k1 misrepresentation is corrected.
- Filters, Verify-integrity, and Export genuinely work.
- Full test suite green; component tests cover every page and state.
