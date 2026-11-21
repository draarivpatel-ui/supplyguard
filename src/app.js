import { parseInput, MAX_BYTES } from './parsers.js';
import { analyze, simulate } from './detectors.js';
import { presets, loadPreset } from './presets.js';
import { makeExport, sha256 } from './exports.js';
import { renderGraph } from './viz.js';

const SEV_RANK = { high: 0, medium: 1, low: 2 };
const THEME_MODES = ['auto', 'light', 'dark'];

const state = {
  presetId: null,
  inputKind: null, // 'preset' | 'file'
  sourceLabel: '',
  sourceFormat: '',
  baseModel: null,
  model: null,
  analysis: null,
  baseAnalysis: null,
  changes: new Map(),
  selectedId: null,
  filter: 'all',
  sort: { key: 'severity', dir: 1 },
  inputFingerprint: null,
  shortcuts: false,
  theme: 'auto',
};

let generation = 0;
const nodeById = new Map();
const els = {};

/* ---------- small DOM helpers ---------- */

function el(tag, className, text) {
  const n = document.createElement(tag);
  if (className) n.className = className;
  if (text != null) n.textContent = text;
  return n;
}

function clear(n) {
  if (n) n.textContent = '';
}

function setStatus(msg, isError) {
  els.status.textContent = msg;
  els.status.classList.toggle('error', Boolean(isError));
}

function nodeName(id) {
  const n = nodeById.get(id);
  return n ? n.name : String(id);
}

function mapGet(map, id) {
  return map && typeof map.get === 'function' ? map.get(id) : null;
}

function depthOf(id) {
  const d = mapGet(state.analysis && state.analysis.depths, id);
  return typeof d === 'number' ? d : null;
}

/* ---------- model adoption ---------- */

function adoptModel(model, meta) {
  let analysis;
  try {
    analysis = analyze(model);
  } catch (err) {
    setStatus('Analysis failed: ' + err.message, true);
    return false;
  }
  state.inputKind = meta.kind;
  state.sourceLabel = meta.label || '';
  state.sourceFormat = model.format || meta.format || '';
  state.presetId = meta.presetId ?? null;
  state.inputFingerprint = meta.fingerprintPromise;
  state.changes = new Map();
  state.baseModel = model;
  state.model = model;
  state.baseAnalysis = analysis;
  state.analysis = analysis;
  state.selectedId = analysis.findings.find((f) => f.reachable)?.nodeId ?? null;
  nodeById.clear();
  for (const n of model.nodes || []) nodeById.set(n.id, n);
  if (els.warnings && els.warnings.parentElement) els.warnings.parentElement.open = false;
  render();
  return true;
}

function loadScenario(id) {
  ++generation;
  const preset = (presets || []).find((p) => p.id === id);
  if (!preset) {
    setStatus('Unknown scenario: ' + id, true);
    return;
  }
  let model;
  try {
    model = loadPreset(id);
  } catch (err) {
    setStatus('Scenario failed to load: ' + err.message, true);
    return;
  }
  if (
    adoptModel(model, {
      kind: 'preset',
      presetId: id,
      label: preset.title,
      format: preset.file,
      fingerprintPromise: sha256(model.inputText).catch(() => null),
    })
  ) {
    setStatus('Loaded scenario ' + preset.title + ' (synthetic demonstration data).');
  }
}

async function handleFile(file) {
  if (!file) return;
  const gen = ++generation;
  if (file.size > MAX_BYTES) {
    setStatus(
      'Import failed: ' +
        file.name +
        ' is ' +
        (file.size / 1048576).toFixed(1) +
        ' MB. The limit is ' +
        Math.round(MAX_BYTES / 1048576) +
        ' MB.',
      true
    );
    return;
  }
  try {
    const bytes = new Uint8Array(await file.arrayBuffer());
    if (gen !== generation) return;
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    const model = parseInput(text, file.name);
    if (
      adoptModel(model, {
        kind: 'file',
        label: file.name,
        fingerprintPromise: sha256(bytes).catch(() => null),
      })
    ) {
      setStatus('Imported ' + file.name + '.');
    }
  } catch (err) {
    if (gen === generation) setStatus('Import failed: ' + err.message, true);
  }
}

/* ---------- remediation ---------- */

function commitChanges(next, refocusSelector) {
  let model, analysis;
  try {
    const args = new Map([...next].map(([k, v]) => [k, { ...v }]));
    model = next.size ? simulate(state.baseModel, args) : state.baseModel;
    analysis = analyze(model);
  } catch (err) {
    setStatus('Change rejected: ' + err.message, true);
    return;
  }
  state.changes = next;
  state.model = model;
  state.analysis = analysis;
  nodeById.clear();
  for (const n of model.nodes || []) nodeById.set(n.id, n);
  render();
  setStatus(
    next.size
      ? 'Simulation updated: ' + next.size + ' staged change' + (next.size === 1 ? '' : 's') + ' applied to the baseline.'
      : 'Simulation cleared. Baseline analysis restored.'
  );
  let target = refocusSelector ? els.inspector.querySelector(refocusSelector) : null;
  if (target && target.disabled) target = null;
  if (!target) {
    target = els.inspector.querySelector('h2');
    if (target) target.tabIndex = -1;
  }
  if (target) target.focus();
}

function stageRemediation(node, action) {
  let change;
  if (action === 'pin') {
    change = { action: 'pin' };
  } else if (action === 'quarantine') {
    change = { action: 'quarantine' };
  } else {
    const versionField = document.getElementById('rem-version');
    const integrityField = document.getElementById('rem-integrity');
    const version = versionField ? versionField.value.trim() : '';
    if (!version) {
      setStatus('Type a candidate version before staging an upgrade.', true);
      if (versionField) versionField.focus();
      return;
    }
    change = { action: 'upgrade', version };
    const integrity = integrityField ? integrityField.value.trim() : '';
    if (integrity) change.integrity = integrity;
  }
  const next = new Map(state.changes);
  next.set(node.id, change);
  commitChanges(next, '[data-remediation="' + action + '"]');
}

/* ---------- selection ---------- */

function onGraphSelect(id) {
  selectNode(id, { refocus: true });
}

function selectNode(id, opts) {
  state.selectedId = id;
  renderGraph(els.graph, state.analysis, state.selectedId, onGraphSelect);
  renderInspector();
  for (const row of els.findings.querySelectorAll('tr[data-node]')) {
    row.classList.toggle('selected', row.dataset.node === id);
  }
  if (els.componentSelect && nodeById.has(id)) els.componentSelect.value = id;
  if (opts && opts.refocus) {
    const b = els.graph.querySelector('[data-node="' + (window.CSS ? CSS.escape(id) : id) + '"]');
    if (b) b.focus();
  }
}

/* ---------- render ---------- */

function render() {
  renderScenarioStrip();
  renderStatusStrip();
  renderComponentSelect();
  renderGraph(els.graph, state.analysis, state.selectedId, onGraphSelect);
  renderInspector();
  renderFindings();
  renderPrintBrief();
}

function renderScenarioStrip() {
  for (const b of els.scenarios.querySelectorAll('[data-preset]')) {
    b.setAttribute('aria-pressed', String(b.dataset.preset === state.presetId));
  }
}

function scoreBand(score) {
  if (score == null) return '';
  if (score >= 67) return 'score-high';
  if (score >= 34) return 'score-mid';
  return 'score-low';
}

function renderStatusStrip() {
  const a = state.analysis;
  els.riskScore.textContent = a ? String(a.score) : 'n/a';
  els.riskScore.className = a ? scoreBand(a.score) : '';

  clear(els.metrics);
  const m = (a && a.metrics) || {};
  const rows = [
    ['reachable', (m.reachable == null ? 0 : m.reachable) + ' / ' + (m.nodes == null ? 0 : m.nodes)],
    ['affected', m.affected == null ? '0' : String(m.affected)],
    ['flagged', m.flagged == null ? String(a ? a.findings.length : 0) : String(m.flagged)],
    ['max depth', m.maxDepth == null ? 'n/a' : String(m.maxDepth)],
    ['components', m.nodes == null ? '0' : String(m.nodes)],
    ['edges', m.edges == null ? '0' : String(m.edges)],
  ];
  for (const [k, v] of rows) {
    const cell = el('div');
    cell.append(el('dt', null, k));
    cell.append(el('dd', null, v));
    els.metrics.append(cell);
  }

  if (state.inputKind === 'preset') {
    els.provenance.textContent = '';
    els.provenance.append(
      el('strong', null, 'Synthetic scenario'),
      document.createTextNode(' ' + (state.sourceLabel || '') + '. Not a real package audit.')
    );
  } else if (state.inputKind === 'file') {
    els.provenance.textContent = '';
    els.provenance.append(
      el('strong', null, 'Imported input'),
      document.createTextNode(' ' + state.sourceLabel + (state.sourceFormat ? ' · format ' + state.sourceFormat : '') + '.')
    );
  } else {
    els.provenance.textContent = 'No input loaded yet.';
  }

  clear(els.warnings);
  const notes = (state.model && state.model.notes) || [];
  els.warnings.parentElement.hidden = !notes.length;
  for (const w of notes) els.warnings.append(el('li', null, w));

  const cmp = els.compare;
  cmp.textContent = '';
  if (state.changes.size && state.baseAnalysis && a) {
    const b = state.baseAnalysis;
    const bm = b.metrics || {};
    cmp.append(
      document.createTextNode('baseline ' + b.score + ' '),
      el('strong', null, '→ ' + a.score),
      document.createTextNode(
        ' · findings ' + b.findings.length + ' → ' + a.findings.length +
        ' · affected ' + (bm.affected == null ? 0 : bm.affected) + ' → ' + (m.affected == null ? 0 : m.affected) +
        ' · reachable ' + (bm.reachable == null ? 0 : bm.reachable) + ' → ' + (m.reachable == null ? 0 : m.reachable)
      )
    );
  }
}

function renderComponentSelect() {
  const sel = els.componentSelect;
  if (!sel) return;
  const cur = state.selectedId;
  clear(sel);
  const none = el('option', null, 'Select a component');
  none.value = '';
  sel.append(none);
  const nodes = [...(state.model ? state.model.nodes : [])].sort(
    (a, b) =>
      (depthOf(a.id) ?? 999) - (depthOf(b.id) ?? 999) ||
      String(a.name).localeCompare(String(b.name)) ||
      String(a.id).localeCompare(String(b.id))
  );
  for (const n of nodes) {
    const d = depthOf(n.id);
    const o = el(
      'option',
      null,
      (d == null ? 'no path' : 'depth ' + d) + ' · ' + n.name + (n.version ? ' ' + n.version : '')
    );
    o.value = n.id;
    sel.append(o);
  }
  sel.value = cur != null && nodeById.has(cur) ? cur : '';
}

/* ---------- inspector ---------- */

function metaRow(dl, k, v) {
  dl.append(el('dt', null, k));
  dl.append(el('dd', null, v == null || v === '' ? 'not recorded' : String(v)));
}

function renderInspector() {
  const host = els.inspector;
  clear(host);
  host.append(el('h2', null, 'Inspector'));
  const a = state.analysis;
  if (!a) {
    host.append(el('p', 'dim', 'Run an analysis to inspect components.'));
    renderRemediation(host, null);
    return;
  }
  const node = state.selectedId != null ? nodeById.get(state.selectedId) : null;
  if (!node) {
    host.append(
      el(
        'p',
        'dim',
        'Select a component in the graph, the component menu, or a findings row to inspect its dependency path, evidence, and remediation options.'
      )
    );
    renderRemediation(host, null);
    return;
  }

  const h3 = el('h3', 'node-name', node.name);
  if (node.version) h3.append(document.createTextNode(' '), el('span', 'ver', 'v' + node.version));
  host.append(h3);

  const badges = el('div', 'badges');
  const nodeFindings = a.findings.filter((f) => f.nodeId === node.id);
  const best = nodeFindings.reduce((acc, f) => Math.min(acc, SEV_RANK[f.severity] ?? 9), 9);
  if (best < 9) {
    const sevName = ['high', 'medium', 'low'][best];
    badges.append(el('span', 'badge b-' + (best === 0 ? 'high' : best === 1 ? 'med' : 'low'), sevName + ' severity'));
  } else {
    badges.append(el('span', 'badge', 'no findings'));
  }
  if (node.quarantined) badges.append(el('span', 'badge b-quar', 'quarantined'));
  if (node.unresolved) badges.append(el('span', 'badge b-warn', 'unresolved'));
  if (depthOf(node.id) == null) badges.append(el('span', 'badge b-warn', 'unreachable'));
  host.append(badges);

  renderRemediation(host, node);

  host.append(el('h3', 'sub-title', 'Dependency path'));
  const path = mapGet(a.paths, node.id);
  if (Array.isArray(path) && path.length) {
    const ol = el('ol', 'path-list');
    for (const pid of path) {
      const pn = nodeById.get(pid);
      const li = el('li');
      li.append(el('span', 'mono', (pn && pn.name) || String(pid)));
      if (pn && pn.version) li.append(document.createTextNode(' '), el('span', 'dim', 'v' + pn.version));
      ol.append(li);
    }
    host.append(ol);
  } else {
    host.append(el('p', 'dim', 'No dependency path reaches this component from the root.'));
  }

  const dl = el('dl', 'meta');
  metaRow(dl, 'ecosystem', node.ecosystem);
  metaRow(dl, 'location', node.location);
  metaRow(dl, 'resolved', node.resolved);
  metaRow(dl, 'integrity', node.integrity ? node.integrity : 'none recorded');
  const details = el('details', 'artifact-details');
  details.append(el('summary', null, 'Artifact metadata'));
  details.append(dl);
  host.append(details);

  host.append(el('h3', 'sub-title', 'Evidence'));
  if (!nodeFindings.length) {
    host.append(el('p', 'dim', 'No findings are attached to this component.'));
  }
  for (const f of nodeFindings) {
    const card = el('div', 'finding-card');
    const top = el('div');
    top.append(el('span', 'sev sev-' + f.severity, f.severity));
    top.append(document.createTextNode(' '), el('span', 'f-title', f.title));
    card.append(top);
    card.append(el('p', null, f.evidence));
    if (f.recommendation) card.append(el('p', null, 'Recommendation: ' + f.recommendation));
    card.append(el('p', 'f-rule', f.ruleId + ' · ' + (f.points || 0) + ' pts'));
    host.append(card);
  }

  const contribs = (a.contributions || []).filter((c) => c.nodeId === node.id);
  if (contribs.length) {
    host.append(el('h3', 'sub-title', 'Score provenance'));
    const ul = el('ul', 'contrib');
    for (const c of contribs) {
      const li = el('li');
      li.append(el('span', 'rule', c.ruleId));
      li.append(el('span', 'pts', '+' + (c.points || 0)));
      ul.append(li);
    }
    host.append(ul);
  }

  const affected = new Set();
  for (const f of nodeFindings) for (const id of f.affected || []) affected.add(id);
  if (affected.size) {
    host.append(el('h3', 'sub-title', 'Affected dependents'));
    const wrap = el('div', 'affected-list');
    for (const id of [...affected].sort((x, y) => nodeName(x).localeCompare(nodeName(y)))) {
      const b = el('button', null, nodeName(id));
      b.type = 'button';
      b.addEventListener('click', () => selectNode(id));
      wrap.append(b);
    }
    host.append(wrap);
  }
}

function labeledInput(labelText, id, placeholder) {
  const lab = el('label', null, labelText);
  const input = document.createElement('input');
  input.type = 'text';
  input.id = id;
  input.autocomplete = 'off';
  input.spellcheck = false;
  if (placeholder) input.placeholder = placeholder;
  lab.append(input);
  return lab;
}

function renderRemediation(host, node) {
  host.append(el('h3', 'sub-title', 'Remediation simulation'));
  host.append(
    el(
      'p',
      'dim',
      'Counterfactual only: nothing is written back, and cleared findings reflect missing metadata, not safety.'
    )
  );

  if (node) {
    const format = (state.baseModel && state.baseModel.format) || '';
    const reasons = {
      pin: node.root
        ? 'The root component cannot be remediated.'
        : node.unresolved
          ? 'An unresolved reference can only be quarantined.'
          : !node.version
            ? 'Pinning needs a concrete resolved version.'
            : ['npm', 'pypi'].includes(format)
              ? ''
              : 'Pinning is available for npm or pypi inputs.',
      upgrade: node.root
        ? 'The root component cannot be remediated.'
        : node.unresolved
          ? 'An unresolved reference can only be quarantined.'
          : format === 'npm' && node.ecosystem === 'npm'
            ? ''
            : 'Upgrades apply to npm components in npm inputs.',
      quarantine: node.root ? 'The root component cannot be remediated.' : '',
    };
    const makeBtn = (act, label) => {
      const b = el('button', 'rem-btn', label);
      b.type = 'button';
      b.dataset.remediation = act;
      if (reasons[act]) {
        b.disabled = true;
        b.title = reasons[act];
      } else {
        b.addEventListener('click', () => stageRemediation(node, act));
      }
      return b;
    };

    const cur = state.changes.get(node.id);
    if (cur) {
      const line = el('p', 'change-line');
      line.append(
        el('span', 'mono', 'staged ' + cur.action + (cur.version ? ' → ' + cur.version : ''))
      );
      const disc = el('button', 'mini', 'Discard');
      disc.type = 'button';
      disc.addEventListener('click', () => {
        const next = new Map(state.changes);
        next.delete(node.id);
        commitChanges(next, '#reset-remediation');
      });
      line.append(disc);
      host.append(line);
    }

    const btns = el('div', 'rem-btns');
    btns.append(makeBtn('quarantine', 'Quarantine'), makeBtn('pin', 'Pin'));
    host.append(btns);

    const controls = el('div', 'rem-controls');
    controls.append(labeledInput('Candidate version', 'rem-version', 'e.g. 2.1.4'));
    controls.append(labeledInput('Integrity (optional, real SHA-512 SRI only)', 'rem-integrity', 'sha512-…'));
    host.append(controls);

    const upWrap = el('div', 'rem-btns');
    upWrap.append(makeBtn('upgrade', 'Upgrade'));
    host.append(upWrap);
  }

  const reset = el('button', 'rem-btn', 'Reset all changes');
  reset.type = 'button';
  reset.id = 'reset-remediation';
  reset.disabled = !state.changes.size;
  reset.addEventListener('click', () => commitChanges(new Map(), '#reset-remediation'));
  host.append(reset);
}

/* ---------- findings table ---------- */

const SORTERS = {
  severity: (x, y) => (SEV_RANK[x.severity] ?? 9) - (SEV_RANK[y.severity] ?? 9),
  component: (x, y) => nodeName(x.nodeId).localeCompare(nodeName(y.nodeId)),
  depth: (x, y) => (x.depth == null ? 999 : x.depth) - (y.depth == null ? 999 : y.depth),
  points: (x, y) => (y.points || 0) - (x.points || 0),
};

function renderFindings() {
  const host = els.findings;
  clear(host);
  const a = state.analysis;
  const all = (a && a.findings) || [];
  const list = all.filter((f) => state.filter === 'all' || f.severity === state.filter);
  const primary = SORTERS[state.sort.key] || SORTERS.severity;
  list.sort(
    (x, y) =>
      primary(x, y) * state.sort.dir ||
      (SEV_RANK[x.severity] ?? 9) - (SEV_RANK[y.severity] ?? 9) ||
      nodeName(x.nodeId).localeCompare(nodeName(y.nodeId))
  );

  els.findingsCount.textContent =
    list.length + ' of ' + all.length + ' findings' + (state.filter !== 'all' ? ' (' + state.filter + ' only)' : '');

  if (!all.length) {
    host.append(el('p', 'dim', 'No findings for this input.'));
    return;
  }
  if (!list.length) {
    host.append(el('p', 'dim', 'No ' + state.filter + ' severity findings.'));
    return;
  }

  const table = el('table');
  const thead = el('thead');
  const hr = el('tr');
  const cols = [
    ['severity', 'Severity', true],
    ['component', 'Component', true],
    ['depth', 'Depth', true],
    [null, 'Finding', false],
    ['points', 'Points', true],
  ];
  for (const [key, label, sortable] of cols) {
    const th = el('th', null);
    if (sortable) {
      if (state.sort.key === key) {
        th.setAttribute('aria-sort', state.sort.dir === 1 ? 'ascending' : 'descending');
      }
      const b = el('button', null);
      b.type = 'button';
      b.dataset.sort = key;
      b.append(document.createTextNode(label + ' '));
      b.append(el('span', 'dir', state.sort.key === key ? (state.sort.dir === 1 ? '↑' : '↓') : '↕'));
      b.addEventListener('click', () => {
        if (state.sort.key === key) state.sort.dir *= -1;
        else {
          state.sort.key = key;
          state.sort.dir = 1;
        }
        renderFindings();
        const again = els.findings.querySelector('[data-sort="' + key + '"]');
        if (again) again.focus();
      });
      th.append(b);
    } else {
      th.textContent = label;
    }
    hr.append(th);
  }
  thead.append(hr);
  table.append(thead);

  const tbody = el('tbody');
  for (const f of list) {
    const tr = el('tr');
    tr.dataset.node = f.nodeId;
    if (f.nodeId === state.selectedId) tr.className = 'selected';

    const tdSev = el('td');
    tdSev.append(el('span', 'sev sev-' + f.severity, f.severity));
    tr.append(tdSev);

    const tdComp = el('td');
    const nb = nodeById.get(f.nodeId);
    const cb = el('button', 'comp-btn', nodeName(f.nodeId));
    cb.type = 'button';
    cb.addEventListener('click', () => selectNode(f.nodeId));
    tdComp.append(cb);
    if (nb && nb.version) tdComp.append(el('span', 'cell-ver', 'v' + nb.version));
    tr.append(tdComp);

    tr.append(el('td', 'cell-depth', f.depth == null ? 'no path' : 'depth ' + f.depth));

    const tdFind = el('td');
    tdFind.append(el('span', null, f.title));
    if (f.evidence) tdFind.append(el('span', 'cell-evi', f.evidence));
    tr.append(tdFind);

    tr.append(el('td', 'cell-pts', String(f.points || 0)));

    tr.addEventListener('click', (e) => {
      if (e.target !== cb) selectNode(f.nodeId);
    });
    tbody.append(tr);
  }
  table.append(tbody);
  host.append(table);
}

/* ---------- print brief ---------- */

function renderPrintBrief() {
  const host = els.printBrief;
  clear(host);
  const a = state.analysis;
  if (!a) return;
  host.append(el('h2', null, 'SupplyGuard executive brief'));
  host.append(
    el(
      'p',
      'print-disc',
      'Scope: this brief summarizes the current analysis snapshot. Findings are heuristic signals from dependency metadata, not confirmed exploit paths, and a listed pattern is not guaranteed to execute. Preset scenarios are synthetic.'
    )
  );
  host.append(
    el(
      'p',
      'print-meta',
      'Source: ' +
        (state.sourceLabel || 'unknown') +
        ' · format ' +
        (state.sourceFormat || (a.model && a.model.format) || 'unknown') +
        ' · ' +
        state.changes.size +
        ' staged change(s) applied'
    )
  );
  const m = a.metrics || {};
  host.append(
    el(
      'p',
      'print-sum',
      'Risk score ' +
        a.score +
        ' · findings ' +
        a.findings.length +
        ' · affected ' +
        (m.affected == null ? 0 : m.affected) +
        ' · reachable ' +
        (m.reachable == null ? 0 : m.reachable) +
        ' of ' +
        (m.nodes == null ? 0 : m.nodes) +
        ' · max depth ' +
        (m.maxDepth == null ? 'n/a' : m.maxDepth)
    )
  );
  const ol = el('ol');
  for (const f of a.findings.slice(0, 5)) {
    const li = el('li');
    li.append(el('strong', null, f.severity + ' · ' + nodeName(f.nodeId) + ' · '));
    li.append(document.createTextNode(f.title + (f.recommendation ? ' ' + f.recommendation : '')));
    ol.append(li);
  }
  host.append(ol);
  host.append(el('p', 'print-foot', 'Generated by SupplyGuard for this snapshot only. See the interactive analysis for the full finding set.'));
}

/* ---------- exports ---------- */

async function onExport(kind) {
  const analysis = state.analysis;
  if (!analysis) {
    setStatus('Nothing to export yet.', true);
    return;
  }
  const fingerprint = state.inputFingerprint;
  const changes = new Map(state.changes);
  try {
    setStatus('Preparing ' + kind + ' export…');
    const result = await makeExport(kind, analysis, {
      inputFingerprint: await fingerprint,
      changes,
    });
    const blob = new Blob([result.text], { type: result.mime || 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = result.filename || 'supplyguard-' + kind + '.txt';
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    if (analysis === state.analysis) setStatus('Exported ' + (result.filename || kind) + '.');
  } catch (err) {
    if (analysis === state.analysis) setStatus('Export failed: ' + err.message, true);
  }
}

/* ---------- keyboard, theme, shortcuts ---------- */

const INTERACTIVE_ROLES = new Set([
  'textbox', 'combobox', 'searchbox', 'spinbutton', 'slider', 'button', 'link',
  'checkbox', 'radio', 'switch', 'tab', 'menuitem', 'option', 'listbox',
]);

function isInteractive(elm) {
  if (!elm || elm.nodeType !== 1) return false;
  if (elm.isContentEditable) return true;
  if (elm.closest('a,button,input,textarea,select,summary,option')) return true;
  const roleHost = elm.closest('[role]');
  return Boolean(roleHost && INTERACTIVE_ROLES.has(roleHost.getAttribute('role')));
}

function onKeydown(e) {
  if (!state.shortcuts) return;
  if (e.defaultPrevented || e.repeat || e.isComposing) return;
  if (e.ctrlKey || e.metaKey || e.altKey || e.shiftKey) return;
  if (isInteractive(e.target) || isInteractive(document.activeElement)) return;
  if (e.key === 'f' || e.key === 'F') {
    e.preventDefault();
    const chip = els.severityFilter.querySelector('button');
    if (chip) chip.focus();
  } else if (e.key === 'g' || e.key === 'G') {
    e.preventDefault();
    els.componentSelect.focus();
  }
}

function applyTheme(mode) {
  state.theme = mode;
  const root = document.documentElement;
  if (mode === 'auto') root.removeAttribute('data-theme');
  else root.setAttribute('data-theme', mode);
  els.themeToggle.textContent = 'Theme: ' + mode;
  els.themeToggle.setAttribute('aria-pressed', String(mode !== 'auto'));
  try {
    localStorage.setItem('supplyguard-theme', mode);
  } catch (_) {}
}

/* ---------- boot ---------- */

function buildScenarioButtons() {
  clear(els.scenarios);
  for (const p of presets || []) {
    const b = el('button', 'scenario');
    b.type = 'button';
    b.dataset.preset = p.id;
    b.setAttribute('aria-pressed', 'false');
    b.append(el('span', 'scenario-title', p.title));
    if (p.description) b.append(el('span', 'scenario-desc', p.description));
    if (p.file) b.append(el('span', 'scenario-file', p.file));
    b.addEventListener('click', () => loadScenario(p.id));
    els.scenarios.append(b);
  }
}

function init() {
  els.scenarios = document.getElementById('scenarios');
  els.status = document.getElementById('status');
  els.riskScore = document.getElementById('risk-score');
  els.metrics = document.getElementById('metrics');
  els.provenance = document.getElementById('provenance');
  els.warnings = document.getElementById('warnings');
  els.compare = document.getElementById('baseline-compare');
  els.graph = document.getElementById('graph');
  els.inspector = document.getElementById('inspector');
  els.findings = document.getElementById('findings');
  els.findingsCount = document.getElementById('findings-count');
  els.severityFilter = document.getElementById('severity-filter');
  els.componentSelect = document.getElementById('component-select');
  els.printBrief = document.getElementById('print-brief');
  els.themeToggle = document.getElementById('theme-toggle');
  els.shortcutsBtn = document.getElementById('shortcuts');
  els.shortcutHint = document.getElementById('shortcut-hint');
  els.dropZone = document.getElementById('drop-zone');
  els.fileInput = document.getElementById('file-input');

  buildScenarioButtons();

  els.fileInput.addEventListener('change', () => {
    handleFile(els.fileInput.files && els.fileInput.files[0]);
    els.fileInput.value = '';
  });

  const dz = els.dropZone;
  for (const ev of ['dragenter', 'dragover']) {
    dz.addEventListener(ev, (e) => {
      e.preventDefault();
      dz.classList.add('drop-over');
    });
  }
  for (const ev of ['dragleave', 'drop']) {
    dz.addEventListener(ev, (e) => {
      e.preventDefault();
      dz.classList.remove('drop-over');
    });
  }
  dz.addEventListener('drop', (e) => {
    const f = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
    handleFile(f);
  });
  window.addEventListener('dragover', (e) => e.preventDefault());
  window.addEventListener('drop', (e) => e.preventDefault());

  for (const b of els.severityFilter.querySelectorAll('[data-filter]')) {
    b.addEventListener('click', () => {
      state.filter = b.dataset.filter;
      for (const other of els.severityFilter.querySelectorAll('[data-filter]')) {
        other.setAttribute('aria-pressed', String(other === b));
      }
      renderFindings();
    });
  }

  els.componentSelect.addEventListener('change', () => {
    if (els.componentSelect.value) selectNode(els.componentSelect.value);
  });

  for (const b of document.querySelectorAll('[data-export]')) {
    b.addEventListener('click', () => onExport(b.dataset.export));
  }
  document.getElementById('print-button').addEventListener('click', () => window.print());

  els.themeToggle.addEventListener('click', () => {
    const next = THEME_MODES[(THEME_MODES.indexOf(state.theme) + 1) % THEME_MODES.length];
    applyTheme(next);
  });
  let stored = 'auto';
  try {
    stored = localStorage.getItem('supplyguard-theme') || 'auto';
  } catch (_) {}
  applyTheme(THEME_MODES.includes(stored) ? stored : 'auto');

  els.shortcutsBtn.addEventListener('click', () => {
    state.shortcuts = !state.shortcuts;
    els.shortcutsBtn.setAttribute('aria-pressed', String(state.shortcuts));
    els.shortcutsBtn.textContent = 'Keyboard shortcuts ' + (state.shortcuts ? 'on' : 'off');
    els.shortcutHint.textContent = state.shortcuts
      ? 'Shortcuts on: f focuses the severity filter, g focuses the component menu.'
      : '';
  });
  document.addEventListener('keydown', onKeydown);

  if ((presets || []).length) {
    loadScenario(presets[0].id);
  } else {
    render();
    setStatus('Scenario presets are not available yet.');
  }
}

init();
