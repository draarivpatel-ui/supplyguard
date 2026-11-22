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
- The workbench tabs (Policy gate, Lockfile diff, Verify) run on the
  loaded analysis and bundled scenarios under the same offline
  guarantee: no advisory feed, registry, or URL is consulted.
- The policy gate evaluates five rules (install hooks, lookalike count,
  unpinned declarations, severity ceiling, license denylist) against
  reachable findings and reports PASS, WARN, or BLOCK. Levels and
  ceilings are configurable; the verdict recomputes deterministically.
- The inspector's blast-radius block enumerates direct and transitive
  dependents and the shortest exposure paths. The quarantine preview
  reports the score delta, cleared contributing findings, and orphaned
  components without staging a change.
- The lockfile diff reports added, removed, and version-changed
  packages with direction, net risk delta, and newly introduced or
  resolved signals. Pasted inventories are parsed locally and never
  stored in bookmark links.
- The attestation export binds the canonical evidence bundle, policy,
  and gate verdict to one unkeyed SHA-256 digest. The Verify panel
  recomputes it in-page and rejects payloads that no longer match, which
  detects corruption or casual edits; proving integrity requires
  comparing the digest against a copy kept elsewhere. It is an integrity
  attestation, not an identity signature.
- `#audit=` bookmark hashes encode the preset scenario, its staged
  changes, gate configuration, active tab, and diff sources so the same
  deterministic state reloads. Imported file content is never encoded.
  Malformed hashes are rejected, never guessed.
- The Verify panel runs self-tests covering SHA-256 known-answer
  vectors, typosquat detection, cycle-safe BFS, diff anti-symmetry,
  gate determinism, CSV neutralization, and attestation tamper
  detection.
