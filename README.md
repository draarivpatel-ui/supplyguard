# SupplyGuard

A static, fully offline dependency-risk workbench. It parses a lockfile or
requirement list, scores heuristic signals, renders the dependency graph,
previews quarantine blast radius, evaluates a deterministic CI/CD policy
gate, diffs two inventories, and exports SARIF, CycloneDX, CSV, Markdown,
audit, and SHA-256 attestation reports. Everything runs in the browser
from local files: no external network requests, no install step, no build
step.

**Live demo:** [https://aariv.me/supplyguard/](https://aariv.me/supplyguard/)

## Run

```
npm run serve
```

Then open `http://127.0.0.1:4173` in a browser. The app is plain ES
modules, so opening `index.html` over `file://` is not supported; it must
be served over HTTP. There are no dependencies and `npm install` is not
required. Assets and module URLs are relative, so the site also works
under a subpath such as a project page.

## Test

```
nice -n 15 npm test
```

Verified locally on Node v26.8.1: 555 tests passed, 0 failed, 0 skipped, 0 cancelled.

Requires Node 22 or later. The suite is split across `core.test.js`
(engine), `policy.test.js` (gate, blast radius, exposure paths),
`diff.test.js` (version ordering, inventory comparison), and
`attest.test.js` (SHA-256, canonical JSON, CSV safety, attestation,
bookmarks). Two optional checks cover the rest:

- `node test/browser.js` drives the UI in Chrome. Set `CHROME_PATH` to a
  Chrome binary when it is not found automatically.
- `python3 test/validate-schemas.py /path/to/schemas` validates exported
  SARIF and CycloneDX documents against locally supplied schema files.

## What it reads

- npm `package-lock.json` (lockfileVersion 2 and 3) with a flag on the
  older metadata format. The lifecycle flag, sources, and digests are
  metadata; hook bodies are not available in normal lockfiles, and digests
  are not checked against artifact bytes.
- Python requirement files, declared requirements only. No resolver, no
  environment-marker evaluation; directives and unsupported syntax are
  rejected as parse errors.
- `Cargo.lock`, a supported subset. The dependency graph is anchored by a
  virtual root computed from source strongly connected components.
- CycloneDX 1.5 JSON components and dependency references. This is not a
  full-schema importer.

## Workbench

- **Policy gate**: five deterministic checks (install hooks, lookalike
  count, unpinned declarations, severity ceiling, license denylist) over
  reachable findings only. Each rule is off, warn, or block, and the
  verdict resolves to PASS, WARN, or BLOCK. No advisory feed or registry
  is consulted; the same inputs always produce the same verdict.
- **Blast radius**: the inspector lists a component's direct and
  transitive dependents plus its shortest exposure paths from the root.
  Preview quarantine reports the counterfactual score delta, cleared
  contributing findings, and orphaned components without staging a
  change.
- **Lockfile diff**: compare two scenarios, the current analysis, or
  pasted inventories. Reports added, removed, upgraded, downgraded,
  equivalent, pinned, unpinned, mixed, expanded, and reduced version
  sets; the net risk delta; and newly
  introduced or resolved signals.
- **Attestation**: a SHA-256 digest over the canonical evidence bundle,
  policy, and gate verdict. The Verify panel recomputes the digest
  in-page and rejects payloads that no longer match it. The digest is
  unkeyed, so it detects corruption or casual edits only when compared
  against a copy kept elsewhere; it is not an identity signature and
  not a vulnerability scan.
- **Self-tests**: the Verify panel replays engine proofs (FIPS 180-4
  vectors, cycle-safe BFS paths, diff anti-symmetry, gate determinism,
  CSV neutralization, tamper detection) on synthetic input.
- **Bookmarking**: the preset scenario, its staged changes, gate
  configuration, active tab, and diff sources serialize into `#audit=`
  so a review link restores the same deterministic state. Imported file
  content and pasted diff text are never
  stored in the URL.

## Limits

- Inputs are capped at 2 MiB, 3000 components, and 18000 dependency edges.
  Larger inputs are rejected rather than truncated.
- The graph panel projects at most 90 nodes; the analysis and findings
  always cover the full input, and truncation is annotated on screen.
- Scores are weighted contributions summed over reachable findings and
  capped at 100. A 0 score is not a statement of safety.
- Affected counts are reverse-transitive dependents, excluding the virtual
  root.
- CycloneDX output is a 1.5 component graph, not a full SBOM schema import.
- The remediation simulator edits metadata only: pin, upgrade, and
  quarantine are counterfactual. There is no resolver run and no
  re-evaluation of a candidate package's contents, so cleared findings
  reflect missing metadata, not verified safety.
- Preset scenarios are synthetic demonstration data, labeled as such in
  the interface.
- The attestation digest is unkeyed: anyone who edits the payload can
  recompute it, so in-page verification detects corruption, not forgery.
  Comparing the digest to a copy kept elsewhere is what proves a payload
  is unaltered; it is never signature validation.
- The lockfile diff compares parsed models, not raw text; two lockfiles
  that produce the same component graph diff as identical.
- The license denylist only inspects license metadata present in the
  input. The npm and Cargo parsers never read licenses, so on those
  inputs the check reports zero coverage and can never trigger; the
  gate does not pretend to have checked. CycloneDX is the supported
  license source, so the check reports its
  coverage alongside the verdict.

## Layout

- `index.html`, `styles.css`, `favicon.svg`: the shell and visual system.
- `src/app.js`: UI state, import/drop, inspector, findings table, exports,
  print brief, keyboard and theme controls.
- `src/viz.js`: deterministic layered SVG graph projection.
- `src/parsers.js`, `src/detectors.js`, `src/presets.js`, `src/exports.js`,
  `src/graph.js`: parsing, scoring, scenarios, export writers, and graph
  helpers.
- `src/policy.js`: exposure paths, dependents, blast-radius reports, and
  the policy gate.
- `src/diff.js`: version ordering and the inventory and signal comparator.
- `src/attest.js`: attestation, the bookmark codec, and the self-test
  catalog.
- `src/sha256.js`: pure-JavaScript SHA-256 (FIPS 180-4).
- `test/`: engine test suite.
