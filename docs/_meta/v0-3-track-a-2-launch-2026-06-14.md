# v0.3 / Phase D — Track A Workstream A-2 launch (D.1 vulnerability reachability) — 2026-06-14

> **Status:** Workstream launch / scope-of-record. Track A discipline = self-merge cascade;
> substrate seal EMPTY expected (additive-only). Baseline 20% (verified) → target ~65%
> (+5.9pp weighted — the single largest agent-level lever per #647 §Dimension 2).

## 1. What A-2 is

Depth on D.1 Vulnerability: move beyond container-image scanning to **host/serverless
OS-package coverage, filesystem language-SCA, runtime-process reachability, and
secrets-in-runtime**. D.1 today scans images (Trivy) + registries (A-1.2).

## 2. Ground-truth (6-agent recon, read-only vs main) — what's net-new vs already-covered

**Critical correction (FLAG-3):** Trivy — already the agent's scanner
(`tools/trivy.py`) — **natively does OS-package AND language-package vuln matching
_within images_** (`normalizer.py:60-88` maps `os-pkgs`/`lang-pkgs`). So the net-new
A-2 surface is **new _targets_ (hosts / serverless / filesystems / running processes)**,
not a new detection engine. The 20%→65% target must be scoped against _surface
coverage_, not re-counting image SCA that already works.

| capability                                                     | net-new?                                                          | seam                                                                             |
| -------------------------------------------------------------- | ----------------------------------------------------------------- | -------------------------------------------------------------------------------- |
| 1. OS-package on EC2/Lambda hosts                              | NET-NEW target (engine exists)                                    | `tools/host_scan.py` wrapping `trivy fs`/`vm`/`rootfs`/lambda; reuses normalizer |
| 2. Language SCA on filesystems/repos                           | mostly covered (images); net-new = fs/repo target + cargo/gem map | `trivy fs` route + extend `_to_package_manager`                                  |
| 3. **CVE→runtime-process linking (reachability — the +5.9pp)** | **NET-NEW; hardest**                                              | needs a package→loaded-lib→PID join no data source produces today — see Fork A   |
| 4. Secrets-in-runtime                                          | NET-NEW                                                           | new scanner wrapper — but OCSF 2002 is the wrong emission class — see Fork B     |

## 3. Licenses (verified — pause trigger #23 CLEAR for the primary tools)

All Go binaries invoked as subprocess (same model as the already-used Trivy):

| tool                 | license      | verdict        |
| -------------------- | ------------ | -------------- |
| Trivy (in use)       | Apache-2.0   | ✅             |
| OSV-Scanner          | Apache-2.0   | ✅             |
| Syft                 | Apache-2.0   | ✅             |
| Grype                | Apache-2.0   | ✅             |
| (secrets) gitleaks   | MIT          | ✅             |
| (secrets) trufflehog | **AGPL-3.0** | ⛔ avoid (#23) |

Most A-2 work can run on **Trivy alone** (fs/vm/secret scanners) — OSV/Syft/Grype are
optional. None of the four primaries trips #23.

## 4. Substrate check (#19/#29) — CLEAR

A-2 capabilities 1–3 live entirely in `packages/agents/vulnerability`. The existing
`AffectedPackage` (`schemas.py:93`) already models OS + language packages (ecosystem is a
free string). The one addition reachability/host needs — a `location` / host-or-process
context — is an **additive optional field** (defaults None; `FINDING_ID_RE` still
validates) → no breaking schemas.py change, **no charter/shared edit**. OCSF 2002 emission
is a plain dict, additively extensible.

## 5. Node-type declaration (Phase 0 design-awareness)

`Image | SBOM | Vulnerability | OSPackage | LanguagePackage`. Today: **Vulnerability**
exists (`VulnerabilityRecord`); **Image** is implicit; **OSPackage/LanguagePackage**
collapse into `AffectedPackage` (distinguished by ecosystem string); **SBOM** does not
exist anywhere (fully net-new if/when SBOM emission is added — and see Q-AppSec-1 for
SBOM ownership vs the AppSec agent).

## 6. PR cascade (cheapest/highest-confidence first)

```
A-2.1  Language SCA on filesystems    (trivy fs route + cargo/gem map)   — clean extension
A-2.2  OS-package host scanning       (trivy fs/vm/lambda wrapper)       — net-new target, reuses normalizer
A-2.3  CVE→runtime-process reachability                                  — GATED on Fork A (operator)
A-2.4  Secrets-in-runtime                                                — GATED on Fork B (operator)
```

A-2.1 + A-2.2 are clean self-merge increments (additive, byte-identical offline default,
`NEXUS_LIVE_*`-gated live lanes). A-2.3 + A-2.4 wait on the two forks below.

## 7. Two forks for operator decision (do not build blind — mirrors A-1)

### Fork A — reachability depth (the +5.9pp lever)

True CVE→PID reachability needs a package→loaded-library→process join. **No data source in
the repo produces this today.** runtime-threat (D.3) has an osquery wrapper, but it emits
_threat-filtered detection findings_, not a package-linkable process inventory.

- **(A1) Shallow heuristic now** — sibling-read runtime-threat's process findings, match
  CVE'd package _names_ against running process names. Buildable in A-2; heuristic
  (over/under-counts); does NOT fully earn +5.9pp.
- **(A2) Deep correlator** — net-new OS-specific osquery package↔file↔PID join in D.1.
  The only path that genuinely earns +5.9pp; substantial, OS-specific build.

### Fork B — secrets-in-runtime emission target

A runtime secret is **not** an OCSF 2002 Vulnerability Finding (`FINDING_ID_RE` is
CVE-shaped). Options: a new local Data-Security/Detection class (additive), or route to
data-security (DSPM). Secrets scanner: Trivy `secret` or gitleaks (MIT) — **not**
trufflehog (AGPL, #23).

## 8. A-2 completion criteria

```
✅ A-2.1 + A-2.2 cascade (host + filesystem coverage), additive, seal EMPTY
✅ A-2.3 reachability per Fork-A decision; A-2.4 secrets per Fork-B decision
✅ Each PR: byte-identical offline default; NEXUS_LIVE_* gated; package + ruff + mypy green
✅ Node-type declaration carried; honest coverage recompute (surface vs re-count)
✅ A-2 verification record at close
```

## 9. References

- Phase D readiness audit — `phase-d-readiness-audit-2026-06-14.md` §Dimension 2 (D.1 lever).
- v0.3 / Phase D directive (operator, 2026-06-14) — Track A §A-2.
- A-2 ground-truth recon (2026-06-14) — the net-new-vs-covered + Fork-A/B findings above.
