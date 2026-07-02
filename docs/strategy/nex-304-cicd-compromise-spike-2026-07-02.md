# NEX-304 — CI/CD Compromise Spike (ADR) — SPIKE OUTPUT

**Deliverable: go/no-go on the reverse-edge problem. Status: GO (as a named detector).**

## The problem (deferred twice — was W5)

A CI/CD compromise path runs code→cloud: a poisoned repo/pipeline → the resources it deploys →
production. But the graph's code-to-cloud edges point the OTHER way — `DEPLOYED_VIA` (resource→artifact),
`DEFINED_IN` (artifact/secret→repo), `BUILT_FROM` (image→repo) all point toward the code. A generic
forward walk would need a reverse edge, which is why W5/NEX-304 kept getting deferred.

## The resolution (the NEX-203 insight, again)

**A named detector joins the chain in its natural direction — it does not need a forward-traversable
edge.** So no reverse edge, no walker change. `find_cicd_compromise` reuses the EXACT chain the existing
`find_resource_from_misconfigured_iac` walks:

```
resource --DEPLOYED_VIA--> IAC_ARTIFACT --DEFINED_IN--> repo   (and)   SECRET{leaked} --DEFINED_IN--> repo
```

If the repo a resource was deployed from ALSO holds a leaked credential, an attacker with that leaked
pipeline credential can poison the deploy → the production resource's supply chain is compromised.

## Proof

`test_path_cicd_compromise_e2e.py`: a resource DEPLOYED_VIA an artifact DEFINED_IN a repo, plus appsec's
REAL leaked-credential writer on the same repo → `find_all` surfaces `cicd_compromise`, coverage counts
it. Reuses existing edges + the real appsec writer. PASSES.

## Consequence

- The "reverse-edge problem" was never real for a named detector — same lesson as NEX-203 (deep/awkward
  shapes → named detectors, not generic-walker gymnastics).
- `cicd_compromise` is BUILT → **the catalog is 28/28 (100%) families built.**
- W5's `BUILT_FROM` as a *traversable* edge stays correctly deferred (provenance, not attack-progression);
  the useful CI/CD signal is captured here without it.
