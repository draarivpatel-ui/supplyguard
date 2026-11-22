# SupplyGuard design notes

An editorial instrument on near-black evergreen. The dark world is the
identity; the light theme is the same instrument printed on warm ivory
stock. Mode: Operate. The user is scanning risk, so precision and
restraint carry the design. The body carries a quiet diagonal wash; the
graph-paper grid lives only inside the graph canvas, where it works as a
tracing surface rather than decoration.

## Palette

Dark (default): paper `#0d1611`, panels `#132019`/`#18281f`, ink `#f0e8d4`
(warm ivory), lines `#233a2c`/`#33523e`. Lime `#a8e34a` is the trace accent
(selection, focus, active states). Evidence colors: coral `#e0684e` for
high severity and the highlighted trace, amber `#e0a63f` for medium and
provenance points, sage `#79a888` for low.

Light (`data-theme="light"` or `prefers-color-scheme`): paper `#f4eedd`,
ink `#17261b`, lime darkened to `#3a690c`, amber `#94630e`, coral `#b23f2c`.

## Type

- Wordmark and print brief: Georgia (installed serif).
- UI voice: humanist sans stack `Optima, Candara, "Segoe UI", Frutiger,
  "Myriad Pro", "Lucida Grande", -apple-system, Verdana`.
- Monospace (`ui-monospace, "SF Mono", Menlo, Consolas`) only for data:
  scores, metrics, versions, filenames, rule IDs, depth labels. All
  numerals in metrics are tabular.

## Layout

Compact header (wordmark, export group, print, theme and shortcut
toggles), then a full-width strip of four equal scenario selectors, a
status strip (import/drop, risk score with baseline compare, tabular
metrics, provenance, and input/evidence notes collapsed behind a details
disclosure), the grid-backed SVG graph beside an anchored (sticky)
inspector, then a sortable findings table. In the inspector, remediation
actions sit immediately under the severity badges; artifact metadata and
the long evidence trail collapse into disclosures below. Under 1080px the
workspace stacks; the graph keeps its own horizontal scroll and the
document never overflows horizontally. A workbench row sits under the
findings table: a tablist (Policy gate, Lockfile diff, Verify) with
roving tabindex and `aria-selected`, each panel on the same grid.
Gate verdicts reuse evidence colors: coral for BLOCK, amber for WARN,
lime for PASS; check rows tint the same scale. Diff tables mark
direction with plain glyphs (up/down arrows, tilde, plus, minus) rather
than new color channels, and the attestation and self-test results use
the standard pass/fail text colors.

## Rules honored

No eyebrow or tagline anywhere; headings stand alone. No em or en dashes in
copy or code comments (the interpunct `·` separates inline data). Scrolling
is instant. No inline styles, scripts, or handlers; all
data text is assigned with `textContent`. The graph is `createElementNS`
SVG with a `viewBox`, focusable `role="button"` nodes (Enter/Space
activation, `aria-pressed`, `aria-label`), and a native `<select>` plus
findings rows as the non-SVG selection path.
