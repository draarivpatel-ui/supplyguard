# SupplyGuard

A static, fully offline dependency-risk instrument. It parses a lockfile or
requirement list, scores heuristic signals, renders the dependency graph,
and exports SARIF, CycloneDX, CSV, and audit reports. Everything runs in
the browser from local files: no external network requests, no install
step, no build step.

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

Requires Node 22 or later. `core.test.js` covers the engine. Two optional
checks cover the rest:

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

## Layout

- `index.html`, `styles.css`, `favicon.svg`: the shell and visual system.
- `src/app.js`: UI state, import/drop, inspector, findings table, exports,
  print brief, keyboard and theme controls.
- `src/viz.js`: deterministic layered SVG graph projection.
- `src/parsers.js`, `src/detectors.js`, `src/presets.js`, `src/exports.js`,
  `src/graph.js`: parsing, scoring, scenarios, export writers, and graph
  helpers.
- `test/`: engine test suite.
