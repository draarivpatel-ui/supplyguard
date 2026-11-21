# SupplyGuard

A client-side dependency-risk instrument. It parses a lockfile or dependency
list (through `src/parsers.js`), scores heuristic risk signals (through
`src/detectors.js`), renders the dependency graph, and exports SARIF,
CycloneDX, CSV, and audit reports (through `src/exports.js`).

## Product facts

- Everything runs in the browser. The CSP allows no network access
  (`connect-src 'none'`), no remote scripts, styles, images, or workers, and
  the app never fetches a URL. Only local assets are referenced.
- Four bundled preset scenarios (`lifecycle`, `lookalikes`, `scope`,
  `baseline`) ship as synthetic demonstration data; the UI labels them as
  such wherever they appear.
- Imported files are read as text with a 2 MB limit checked before reading.
  Parse failures surface in the live status region and never replace the
  current analysis.
- Findings are heuristic signals from dependency metadata. The interface
  states that a finding does not confirm a vulnerable code path executes;
  no copy claims certainty.
- The remediation simulator (`simulate`) stages pin, upgrade, and quarantine
  changes against the baseline model. Candidate versions and integrity
  values are typed by the user; the UI never generates or implies a verified
  hash. Metrics compare baseline against simulated state.
- The risk score, metrics, findings, and graph all render real analysis
  output. Empty states show `n/a` or explanatory text, never placeholder
  numbers.
- The dependency graph is a deterministic BFS projection (depth columns,
  name-sorted rows). Projection is capped at 90 rendered nodes for very
  large graphs; a note states the cap and that analysis still covers all
  components. Unreachable components sit in a dashed `unreachable` column;
  quarantined components carry a dashed coral outline and a Q tag.
- Exports download as Blob object URLs that are revoked after dispatch.
- Print produces a one-page executive brief: provenance, scoped disclaimer,
  summary metrics, and the first five findings. All app UI is hidden in
  print.
- Keyboard shortcuts are off by default and guarded (no modifiers, repeats,
  composition, prevented events, or interactive/editable targets). `f`
  focuses the severity filter, `g` focuses the component menu. Escape is
  not bound.
- Themes follow the system by default; the header toggle cycles
  auto, light, dark and persists the choice locally.
