import { parseInput, MAX_BYTES } from './parsers.js';
import { analyze, simulate } from './detectors.js';
import { presets, loadPreset } from './presets.js';
import { makeExport, sha256 } from './exports.js';
import { renderGraph } from './viz.js';
import { blastRadius, dependents, exposurePaths, policyGate, sanitizePolicy, DEFAULT_POLICY } from './policy.js';
import { diffAnalyses } from './diff.js';
import { decodeBookmark, encodeBookmark, makeAttestation, runSelfTests, verifyAttestation } from './attest.js';

const SEV_RANK = { high: 0, medium: 1, low: 2 };
const THEME_MODES = ['auto', 'light', 'dark'];
const TAB_IDS = ['policy', 'diff', 'verify'];

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
  policy: { ...DEFAULT_POLICY, licenseDeny: [] },
  gate: null,
  tab: 'policy',
  diff: { left: 'preset:baseline', right: 'preset:lifecycle', result: null, labels: null, error: '' },
  selfTests: null,
  attestCheck: null,
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

/* A stored diff computed against "current analysis" goes stale the moment
   the model changes (scenario switch, import, staged change). */
function dropStaleDiff() {
  if (state.diff.left === 'current' || state.diff.right === 'current') {
    state.diff.result = null;
    state.diff.labels = null;
    state.diff.error = '';
  }
}

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
  dropStaleDiff();
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
    setStatus(
      'Loaded scenario ' + preset.title + ' (synthetic demonstration data). ' + (preset.description || '')
    );
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
  dropStaleDiff();
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
  if (els.componentSelect) {
    els.componentSelect.value = id != null && nodeById.has(id) ? id : '';
  }
  if (opts && opts.refocus && id != null) {
    let target = null;
    if (window.CSS && CSS.escape) {
      try {
        target = els.graph.querySelector('[data-node="' + CSS.escape(id) + '"]');
      } catch (_) {}
    }
    if (!target) {
      for (const g of els.graph.querySelectorAll('[data-node]')) {
        if (g.getAttribute('data-node') === id) {
          target = g;
          break;
        }
      }
    }
    if (target) target.focus();
  }
}

/* ---------- render ---------- */

function render() {
  state.gate = state.analysis ? policyGate(state.analysis, state.policy) : null;
  renderScenarioStrip();
  renderStatusStrip();
  renderComponentSelect();
  renderGraph(els.graph, state.analysis, state.selectedId, onGraphSelect);
  renderInspector();
  renderFindings();
  renderPrintBrief();
  updatePolicyPanel();
  renderDiffSources();
  renderDiffResults();
  syncBookmark();
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
  if (a && state.gate) {
    cmp.append(
      el('span', 'gate-chip g-' + state.gate.verdict.toLowerCase(), 'gate ' + state.gate.verdict),
      document.createTextNode(state.changes.size ? ' ' : '')
    );
  }
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

  renderBlast(host, node);
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
      const cell = el('span', 'rem-cell');
      const b = el('button', 'rem-btn', label);
      b.type = 'button';
      b.dataset.remediation = act;
      cell.append(b);
      if (reasons[act]) {
        b.disabled = true;
        b.title = reasons[act];
        const reason = el('p', 'rem-reason', reasons[act]);
        reason.id = 'rem-reason-' + act;
        b.setAttribute('aria-describedby', reason.id);
        cell.append(reason);
      } else {
        b.addEventListener('click', () => stageRemediation(node, act));
      }
      return cell;
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

/* ---------- blast radius preview ---------- */

function chipList(host, items, limit = 14) {
  const wrap = el('div', 'affected-list');
  for (const item of items.slice(0, limit)) {
    const b = el('button', null, item.name);
    b.type = 'button';
    b.addEventListener('click', () => selectNode(item.id));
    wrap.append(b);
  }
  if (items.length > limit) wrap.append(el('span', 'dim', '+' + (items.length - limit) + ' more'));
  host.append(wrap);
}

function renderBlast(host, node) {
  if (node.root || node.id === (state.model && state.model.rootId)) return;
  host.append(el('h3', 'sub-title', 'Blast radius'));
  let view;
  try {
    const { direct, transitive } = dependents(state.model, node.id);
    view = { direct, transitive, paths: exposurePaths(state.model, node.id, 65) };
  } catch {
    host.append(el('p', 'dim', 'Blast radius is not available for this component.'));
    return;
  }
  if (node.quarantined) {
    host.append(el('p', 'dim', 'This component is quarantined in the simulation, so it is not in the active graph.'));
    return;
  }
  const dl = el('dl', 'blast-stats');
  const stat = (key, value) => {
    dl.append(el('dt', null, key));
    dl.append(el('dd', null, String(value)));
  };
  stat('exposure paths', view.paths.length
    ? (view.paths.length > 64 ? '64+' : view.paths.length) + ' · depth ' + (view.paths[0].length - 1)
    : 'none');
  stat('direct dependents', view.direct.length);
  stat('transitive dependents', view.transitive.length);
  host.append(dl);
  if (view.direct.length) {
    host.append(el('p', 'blast-label', 'Direct dependents'));
    chipList(host, view.direct);
  }
  const directIds = new Set(view.direct.map(item => item.id));
  const further = view.transitive.filter(item => !directIds.has(item.id));
  if (further.length) {
    host.append(el('p', 'blast-label', 'Further transitive dependents'));
    chipList(host, further);
  }
  const btn = el('button', 'rem-btn', 'Preview quarantine');
  btn.type = 'button';
  btn.id = 'blast-preview';
  const resultBox = el('div', 'blast-result');
  btn.addEventListener('click', () => {
    clear(resultBox);
    try {
      renderBlastReport(resultBox, blastRadius(state.model, node.id));
    } catch (err) {
      resultBox.append(el('p', 'dim', err.message));
    }
  });
  host.append(btn);
  host.append(resultBox);
}

function renderBlastReport(host, report) {
  const sum = el('p', 'blast-delta');
  sum.append(
    document.createTextNode('quarantine ' + report.name + ': score '),
    el('strong', null, report.score.before + ' \u2192 ' + report.score.after),
    document.createTextNode(' · ' + report.findings.cleared + ' contributing finding' +
      (report.findings.cleared === 1 ? '' : 's') + ' cleared · ' +
      report.orphaned.length + ' orphaned')
  );
  host.append(sum);
  if (report.cleared.length) {
    const list = el('ul', 'contrib');
    for (const item of report.cleared.slice(0, 10)) {
      const li = el('li');
      li.append(el('span', 'rule', item.ruleId + ' ' + item.title));
      li.append(el('span', 'pts', item.severity));
      list.append(li);
    }
    if (report.cleared.length > 10) list.append(el('li', null, '+' + (report.cleared.length - 10) + ' more'));
    host.append(list);
  }
  if (report.orphaned.length) {
    host.append(el('p', 'blast-label', 'Becomes unreachable'));
    chipList(host, report.orphaned);
  }
  host.append(el('p', 'dim', 'Preview only. Stage the change under Remediation to apply it.'));
}

/* ---------- workbench: policy gate, lockfile diff, verify ---------- */

function activateTab(id) {
  state.tab = TAB_IDS.includes(id) ? id : 'policy';
  for (const tabId of TAB_IDS) {
    const btn = document.getElementById('tab-' + tabId);
    const panel = document.getElementById('panel-' + tabId);
    const active = tabId === state.tab;
    btn.setAttribute('aria-selected', String(active));
    btn.tabIndex = active ? 0 : -1;
    panel.hidden = !active;
  }
  syncBookmark();
}

function gateControl(id) {
  return els.panelPolicy.querySelector('tr[data-check="' + id + '"] .gate-control');
}

function levelSelect(value, levels, onChange) {
  const sel = document.createElement('select');
  sel.className = 'gate-select';
  for (const level of levels) {
    const opt = el('option', null, level);
    opt.value = level;
    sel.append(opt);
  }
  sel.value = value;
  sel.addEventListener('change', () => onChange(sel.value));
  return sel;
}

function numberInput(value, onChange) {
  const input = document.createElement('input');
  input.type = 'text';
  input.className = 'gate-num mono';
  input.inputMode = 'numeric';
  input.autocomplete = 'off';
  input.spellcheck = false;
  input.value = String(value);
  input.setAttribute('aria-label', 'allowed count before the rule triggers');
  input.addEventListener('change', () => {
    const parsed = /^\d{1,6}$/.test(input.value.trim()) ? Number(input.value.trim()) : 0;
    input.value = String(parsed);
    onChange(parsed);
  });
  return input;
}

function setPolicy(key, value) {
  state.policy[key] = value;
  state.policy = sanitizePolicy(state.policy);
  state.gate = state.analysis ? policyGate(state.analysis, state.policy) : null;
  updatePolicyPanel();
  renderStatusStrip();
  syncBookmark();
}

function buildPolicyPanel() {
  const host = els.panelPolicy;
  clear(host);
  host.dataset.built = '1';
  host.append(el('h2', null, 'Policy gate'));
  const head = el('div', 'gate-head');
  head.append(el('span', 'gate-verdict', 'n/a'));
  head.append(el('p', 'dim', 'A deterministic CI/CD gate replayed offline. Only findings reachable from the root count. No advisory feed or registry is consulted.'));
  host.append(head);
  const table = el('table', 'gate-table');
  const tbody = el('tbody');
  for (const [id, label] of [
    ['install-scripts', 'Install lifecycle hooks'],
    ['typosquat', 'Lookalike names over ceiling'],
    ['unpinned', 'Unpinned declarations over ceiling'],
    ['severity-ceiling', 'Severity ceiling'],
    ['license-deny', 'License denylist'],
  ]) {
    const tr = el('tr');
    tr.dataset.check = id;
    tr.append(el('td', 'gate-label', label));
    tr.append(el('td', 'gate-control'));
    tr.append(el('td', 'gate-state'));
    tr.append(el('td', 'gate-detail dim'));
    tbody.append(tr);
  }
  table.append(tbody);
  host.append(table);

  const policy = state.policy;
  gateControl('install-scripts').append(levelSelect(policy.installScripts, ['off', 'warn', 'block'], value => {
    setPolicy('installScripts', value);
  }));
  const typoCell = gateControl('typosquat');
  typoCell.append(levelSelect(policy.typosquat, ['off', 'warn', 'block'], value => setPolicy('typosquat', value)));
  typoCell.append(document.createTextNode(' max '));
  typoCell.append(numberInput(policy.typosquatMax, value => setPolicy('typosquatMax', value)));
  const unpinnedCell = gateControl('unpinned');
  unpinnedCell.append(levelSelect(policy.unpinned, ['off', 'warn', 'block'], value => setPolicy('unpinned', value)));
  unpinnedCell.append(document.createTextNode(' max '));
  unpinnedCell.append(numberInput(policy.unpinnedMax, value => setPolicy('unpinnedMax', value)));
  gateControl('severity-ceiling').append(levelSelect(policy.severityCeiling, ['off', 'high', 'medium', 'low'], value => {
    setPolicy('severityCeiling', value);
  }));
  const deny = document.createElement('input');
  deny.type = 'text';
  deny.id = 'gate-license-deny';
  deny.className = 'gate-licenses mono';
  deny.autocomplete = 'off';
  deny.spellcheck = false;
  deny.placeholder = 'GPL-3.0-only, AGPL-3.0-only';
  deny.value = policy.licenseDeny.join(', ');
  deny.addEventListener('change', () => {
    setPolicy('licenseDeny', deny.value.split(',').map(item => item.trim()).filter(Boolean));
    deny.value = state.policy.licenseDeny.join(', ');
  });
  gateControl('license-deny').append(deny);
}

function syncPolicyControls() {
  const host = els.panelPolicy;
  if (!host || !host.dataset.built) return;
  const rows = [
    ['install-scripts', state.policy.installScripts, 0],
    ['typosquat', state.policy.typosquat, 0], ['typosquat', state.policy.typosquatMax, 1],
    ['unpinned', state.policy.unpinned, 0], ['unpinned', state.policy.unpinnedMax, 1],
    ['severity-ceiling', state.policy.severityCeiling, 0],
  ];
  for (const [id, value, index] of rows) {
    const widget = gateControl(id).querySelectorAll('select,input')[index];
    if (widget) widget.value = String(value);
  }
  const deny = host.querySelector('#gate-license-deny');
  if (deny) deny.value = state.policy.licenseDeny.join(', ');
}

function updatePolicyPanel() {
  const host = els.panelPolicy;
  if (!host || !host.dataset.built) return;
  const badge = host.querySelector('.gate-verdict');
  const gate = state.gate;
  if (!gate) {
    badge.textContent = 'n/a';
    badge.dataset.verdict = 'none';
    for (const tr of host.querySelectorAll('tr[data-check]')) {
      tr.querySelector('.gate-state').textContent = '';
      tr.querySelector('.gate-detail').textContent = 'load an input to evaluate';
    }
    return;
  }
  badge.textContent = gate.verdict;
  badge.dataset.verdict = gate.verdict.toLowerCase();
  for (const check of gate.checks) {
    const tr = host.querySelector('tr[data-check="' + check.id + '"]');
    const stateCell = tr.querySelector('.gate-state');
    stateCell.textContent = check.triggered ? check.level.toUpperCase() : 'pass';
    stateCell.className = 'gate-state gs-' + (check.triggered ? check.level : 'pass');
    let detail = check.detail;
    if (check.id === 'license-deny') {
      detail += ' · ' + check.coverage.recorded + ' licensed component' + (check.coverage.recorded === 1 ? '' : 's');
    }
    tr.querySelector('.gate-detail').textContent = detail;
  }
  syncPolicyControls();
}

/* ---------- lockfile diff ---------- */

function diffSources() {
  const list = [['', 'choose a source']];
  if (state.model) list.push(['current', 'Current analysis']);
  for (const preset of presets || []) list.push(['preset:' + preset.id, 'Scenario ' + preset.title + ' (synthetic)']);
  return list;
}

function buildDiffPanel() {
  const host = els.panelDiff;
  clear(host);
  host.dataset.built = '1';
  host.append(el('h2', null, 'Lockfile diff'));
  host.append(el('p', 'dim', 'Compare two inventories from local data only: scenarios, the current analysis, or pasted text. Pasted content stays in this tab and is not stored in the bookmark link.'));
  const grid = el('div', 'diff-grid');
  for (const [side, sideLabel] of [['left', 'Before'], ['right', 'After']]) {
    const box = el('div', 'diff-side');
    const label = el('label', 'diff-label', sideLabel);
    const sel = document.createElement('select');
    sel.id = 'diff-' + side;
    label.append(sel);
    box.append(label);
    const area = document.createElement('textarea');
    area.id = 'diff-' + side + '-text';
    area.rows = 5;
    area.spellcheck = false;
    area.placeholder = 'or paste a lockfile, requirements list, Cargo.lock, or CycloneDX JSON';
    area.setAttribute('aria-label', sideLabel + ' pasted inventory');
    box.append(area);
    grid.append(box);
  }
  host.append(grid);
  const actions = el('div', 'diff-actions');
  const run = el('button', 'rem-btn', 'Compare');
  run.type = 'button';
  run.id = 'diff-run';
  run.addEventListener('click', runDiff);
  const swap = el('button', 'rem-btn', 'Swap sides');
  swap.type = 'button';
  swap.id = 'diff-swap';
  swap.addEventListener('click', () => {
    [state.diff.left, state.diff.right] = [state.diff.right, state.diff.left];
    [els.diffLeftText.value, els.diffRightText.value] = [els.diffRightText.value, els.diffLeftText.value];
    state.diff.result = null;
    state.diff.labels = null;
    state.diff.error = '';
    renderDiffSources();
    renderDiffResults();
    syncBookmark();
  });
  actions.append(run, swap);
  host.append(actions);
  const results = el('div', 'diff-results');
  host.append(results);
  els.diffLeft = host.querySelector('#diff-left');
  els.diffRight = host.querySelector('#diff-right');
  els.diffLeftText = host.querySelector('#diff-left-text');
  els.diffRightText = host.querySelector('#diff-right-text');
  for (const [side, sel] of [['left', els.diffLeft], ['right', els.diffRight]]) {
    sel.addEventListener('change', () => {
      state.diff[side] = sel.value;
      state.diff.result = null;
      state.diff.labels = null;
      state.diff.error = '';
      renderDiffResults();
      syncBookmark();
    });
    const area = side === 'left' ? els.diffLeftText : els.diffRightText;
    area.addEventListener('input', () => {
      if (!state.diff.result && !state.diff.error) return;
      state.diff.result = null;
      state.diff.labels = null;
      state.diff.error = '';
      renderDiffResults();
    });
  }
}

function renderDiffSources() {
  if (!els.diffLeft) return;
  const options = diffSources();
  for (const [side, sel] of [['left', els.diffLeft], ['right', els.diffRight]]) {
    const wanted = state.diff[side];
    clear(sel);
    for (const [value, label] of options) {
      const opt = el('option', null, label);
      opt.value = value;
      sel.append(opt);
    }
    sel.value = options.some(([value]) => value === wanted) ? wanted : 'preset:baseline';
    state.diff[side] = sel.value;
  }
}

function diffSideModel(side) {
  const sel = side === 'left' ? els.diffLeft : els.diffRight;
  const area = side === 'left' ? els.diffLeftText : els.diffRightText;
  const pasted = area.value.trim();
  if (pasted) {
    // parseInput picks its parser from the file name, so name the paste by
    // what it looks like: TOML tables mean Cargo.lock, everything else is
    // routed by content (JSON wins on '{' inside parseInput itself).
    const name = /^\s*\[\[package\]\]/m.test(pasted) ? 'pasted Cargo.lock' : 'pasted inventory';
    return { model: parseInput(pasted, name), label: 'pasted input' };
  }
  if (sel.value === 'current') {
    if (!state.model) throw new Error('No current analysis is loaded.');
    return { model: state.model, label: 'current analysis' };
  }
  const preset = (presets || []).find(item => 'preset:' + item.id === sel.value);
  if (!preset) throw new Error('Choose a source for the ' + side + ' side.');
  return { model: loadPreset(preset.id), label: 'scenario ' + preset.title };
}

function runDiff() {
  try {
    const left = diffSideModel('left');
    const right = diffSideModel('right');
    state.diff.result = diffAnalyses(analyze(left.model), analyze(right.model));
    state.diff.labels = { left: left.label, right: right.label };
    state.diff.error = '';
  } catch (err) {
    state.diff.result = null;
    state.diff.error = err.message;
  }
  renderDiffResults();
}

function diffGroup(host, title, rows, fill) {
  const box = el('div', 'diff-group');
  box.append(el('h3', null, title + ' (' + rows.length + ')'));
  if (!rows.length) {
    box.append(el('p', 'dim', 'none'));
    host.append(box);
    return;
  }
  const table = el('table', 'diff-table');
  const tbody = el('tbody');
  for (const row of rows) {
    const tr = el('tr');
    fill(tr, row);
    tbody.append(tr);
  }
  table.append(tbody);
  box.append(table);
  host.append(box);
}

const DIRECTION_MARK = { upgraded: ['\u2191', 'dd-up'], downgraded: ['\u2193', 'dd-down'], equivalent: ['=', 'dd-mix'], pinned: ['●', 'dd-up'], unpinned: ['○', 'dd-down'], mixed: ['~', 'dd-mix'], expanded: ['+', 'dd-add'], reduced: ['-', 'dd-rem'] };

function renderDiffResults() {
  const host = els.panelDiff?.querySelector('.diff-results');
  if (!host) return;
  clear(host);
  if (state.diff.error) {
    host.append(el('p', 'dim', 'Diff failed: ' + state.diff.error));
    return;
  }
  const d = state.diff.result;
  if (!d) {
    host.append(el('p', 'dim', 'Pick a before and after source, or paste inventories, then run Compare.'));
    return;
  }
  const labels = state.diff.labels;
  const signed = value => (value > 0 ? '+' : '') + value;
  const sum = el('p', 'diff-sum');
  sum.append(
    el('strong', null, labels.left + ' \u2192 ' + labels.right),
    document.createTextNode(' · net risk delta ' + signed(d.score.delta)),
    document.createTextNode(' · score ' + d.score.before + ' \u2192 ' + d.score.after),
    document.createTextNode(' · findings ' + d.findings.before + ' \u2192 ' + d.findings.after),
    document.createTextNode(' · reachable ' + d.reachable.before + ' \u2192 ' + d.reachable.after),
    document.createTextNode(' · affected ' + d.affected.before + ' \u2192 ' + d.affected.after)
  );
  host.append(sum);
  diffGroup(host, 'Added', d.added, (tr, item) => {
    tr.append(el('td', 'dd-mark dd-add', '+'), el('td', null, item.name),
      el('td', 'mono', item.versions.join(', ') || 'unversioned'), el('td', 'dim', item.ecosystem));
  });
  diffGroup(host, 'Removed', d.removed, (tr, item) => {
    tr.append(el('td', 'dd-mark dd-rem', '-'), el('td', null, item.name),
      el('td', 'mono', item.versions.join(', ') || 'unversioned'), el('td', 'dim', item.ecosystem));
  });
  diffGroup(host, 'Changed', d.changed, (tr, item) => {
    const [mark, cls] = DIRECTION_MARK[item.direction] || DIRECTION_MARK.mixed;
    const label = versions => versions.map(v => v || 'unversioned').join(', ');
    tr.append(el('td', 'dd-mark ' + cls, mark), el('td', null, item.name),
      el('td', 'mono', label(item.from) + ' \u2192 ' + label(item.to)),
      el('td', 'dim', item.direction + ' · ' + item.ecosystem));
  });
  diffGroup(host, 'Newly introduced risk signals', d.signals.introduced, (tr, item) => {
    const td = el('td');
    td.append(el('span', 'sev sev-' + item.severity, item.severity));
    tr.append(el('td', 'dd-mark dd-rem', '!'), td, el('td', null, item.name),
      el('td', null, item.ruleId + ' · ' + item.title));
  });
  diffGroup(host, 'Resolved signals', d.signals.resolved, (tr, item) => {
    const td = el('td');
    td.append(el('span', 'sev sev-' + item.severity, item.severity));
    tr.append(el('td', 'dd-mark dd-add', '\u2713'), td, el('td', null, item.name),
      el('td', null, item.ruleId + ' · ' + item.title));
  });
}

/* ---------- verify panel ---------- */

function buildVerifyPanel() {
  const host = els.panelVerify;
  clear(host);
  host.append(el('h2', null, 'Verify'));
  host.append(el('p', 'dim', 'Replay the engine proofs in this page. Every check runs offline against deterministic synthetic input.'));
  const run = el('button', 'rem-btn', 'Run self-tests');
  run.type = 'button';
  run.id = 'run-selftests';
  run.addEventListener('click', runSelfTestPanel);
  host.append(run);
  host.append(el('p', 'st-count'));
  const list = el('ol', 'selftest-list');
  host.append(list);
  host.append(el('h3', 'sub-title', 'Attestation check'));
  host.append(el('p', 'dim', 'Paste an attestation export to recompute its SHA-256 digest and detect alteration or corruption. The digest is not a signature: only a digest kept separately proves a payload is unaltered.'));
  const area = document.createElement('textarea');
  area.id = 'attest-input';
  area.rows = 6;
  area.spellcheck = false;
  area.placeholder = '{... supplyguard.attestation.json ...}';
  area.setAttribute('aria-label', 'attestation export to verify');
  host.append(area);
  const check = el('button', 'rem-btn', 'Verify attestation');
  check.type = 'button';
  check.id = 'verify-attest';
  check.addEventListener('click', runAttestCheck);
  host.append(check);
  host.append(el('p', 'attest-result'));
}

function runSelfTestPanel() {
  state.selfTests = runSelfTests();
  const host = els.panelVerify;
  const list = host.querySelector('.selftest-list');
  const count = host.querySelector('.st-count');
  clear(list);
  let passed = 0;
  for (const item of state.selfTests) {
    if (item.ok) passed++;
    const li = el('li');
    li.append(el('span', 'st ' + (item.ok ? 'st-ok' : 'st-fail'), item.ok ? 'pass' : 'fail'));
    li.append(document.createTextNode(' '));
    li.append(el('span', 'st-name', item.name));
    li.append(document.createTextNode(' '));
    li.append(el('span', 'dim mono', item.detail));
    list.append(li);
  }
  count.textContent = passed + ' of ' + state.selfTests.length + ' self-tests pass';
  count.className = 'st-count ' + (passed === state.selfTests.length ? 'st-ok-text' : 'st-fail-text');
}

function runAttestCheck() {
  const input = els.panelVerify.querySelector('#attest-input');
  const out = els.panelVerify.querySelector('.attest-result');
  const result = verifyAttestation(input.value);
  state.attestCheck = result;
  if (result.ok) {
    out.textContent = 'verified · gate ' + (result.verdict || 'n/a') + ' · sha256 ' + result.computed.slice(0, 20) + '\u2026';
    out.className = 'attest-result st-ok-text';
  } else {
    out.textContent = 'not verified: ' + (result.error || 'digest mismatch; the payload was altered or corrupted');
    out.className = 'attest-result st-fail-text';
  }
}

/* ---------- bookmark ---------- */

function syncBookmark() {
  try {
    // Only preset scenarios restore deterministically; imported file content
    // and its staged changes can never be rebuilt from a link.
    const fromPreset = state.inputKind === 'preset';
    const encoded = encodeBookmark({
      presetId: fromPreset ? state.presetId : null,
      changes: fromPreset ? state.changes : null,
      policy: state.policy,
      tab: state.tab,
      diff: { left: state.diff.left, right: state.diff.right },
    });
    if (encoded) {
      history.replaceState(null, '', '#' + encoded);
      state.bookmarkTooLarge = false;
    } else {
      history.replaceState(null, '', location.pathname + location.search);
      state.bookmarkTooLarge = true;
    }
    return Boolean(encoded);
  } catch (_) { return false; }
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

function downloadText(text, filename, mime) {
  const blob = new Blob([text], { type: mime || 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename || 'supplyguard-export.txt';
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

async function onExport(kind) {
  const analysis = state.analysis;
  if (!analysis) {
    setStatus('Nothing to export yet.', true);
    return;
  }
  const fingerprint = state.inputFingerprint;
  const changes = new Map(state.changes);
  try {
    if (kind === 'sign') {
      setStatus('Preparing attestation…');
      const result = makeAttestation(analysis, {
        inputFingerprint: await fingerprint,
        changes,
        policy: state.policy,
      });
      if (analysis !== state.analysis) return;
      downloadText(result.text, result.filename, result.mime);
      setStatus('Exported ' + result.filename + ' · gate ' + result.verdict + ' · sha256 ' + result.digest.slice(0, 20) + '…');
      return;
    }
    setStatus('Preparing ' + kind + ' export…');
    const result = await makeExport(kind, analysis, {
      inputFingerprint: await fingerprint,
      changes,
      gate: state.gate ? state.gate.verdict : null,
    });
    if (analysis !== state.analysis) return;
    downloadText(result.text, result.filename, result.mime);
    setStatus('Exported ' + (result.filename || kind) + '.');
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
    if (p.description) b.setAttribute('aria-label', p.title + '. ' + p.description);
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
  els.panelPolicy = document.getElementById('panel-policy');
  els.panelDiff = document.getElementById('panel-diff');
  els.panelVerify = document.getElementById('panel-verify');
  els.bookmarkBtn = document.getElementById('bookmark-button');

  buildScenarioButtons();
  buildPolicyPanel();
  buildDiffPanel();
  buildVerifyPanel();

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
    selectNode(els.componentSelect.value || null);
  });

  for (const b of document.querySelectorAll('[data-export]')) {
    b.addEventListener('click', () => onExport(b.dataset.export));
  }
  document.getElementById('print-button').addEventListener('click', () => window.print());
  els.bookmarkBtn.addEventListener('click', async () => {
    const ok = syncBookmark();
    if (!ok || state.bookmarkTooLarge) {
      setStatus('This state is too large to store in a bookmark link.', true);
      return;
    }
    try {
      await navigator.clipboard.writeText(location.href);
      setStatus(state.inputKind === 'preset'
        ? 'Bookmark link copied. It restores this scenario, staged changes, policy, and view.'
        : 'Bookmark link copied. It restores policy and view; imported file content is not stored in links.');
    } catch {
      setStatus('Bookmark link is in the address bar; copy it from there.');
    }
  });

  const tabs = TAB_IDS.map(id => document.getElementById('tab-' + id));
  for (const [index, tab] of tabs.entries()) {
    tab.addEventListener('click', () => activateTab(TAB_IDS[index]));
    tab.addEventListener('keydown', e => {
      let next = null;
      if (e.key === 'ArrowRight') next = (index + 1) % tabs.length;
      else if (e.key === 'ArrowLeft') next = (index - 1 + tabs.length) % tabs.length;
      else if (e.key === 'Home') next = 0;
      else if (e.key === 'End') next = tabs.length - 1;
      if (next != null) {
        e.preventDefault();
        activateTab(TAB_IDS[next]);
        tabs[next].focus();
      }
    });
  }

  els.themeToggle.addEventListener('click', () => {
    const next = THEME_MODES[(THEME_MODES.indexOf(state.theme) + 1) % THEME_MODES.length];
    applyTheme(next);
  });
  let stored = 'auto';
  try {
    stored = localStorage.getItem('supplyguard-theme') || 'auto';
  } catch (_) {}
  applyTheme(THEME_MODES.includes(stored) ? stored : 'auto');

  function setShortcuts(on) {
    state.shortcuts = on;
    els.shortcutsBtn.setAttribute('aria-pressed', String(on));
    els.shortcutsBtn.textContent = 'Keyboard shortcuts ' + (on ? 'on' : 'off');
    els.shortcutHint.textContent = on
      ? 'Shortcuts on: f focuses the severity filter, g focuses the component menu.'
      : '';
    try {
      localStorage.setItem('supplyguard-shortcuts', on ? 'on' : 'off');
    } catch (_) {}
  }
  els.shortcutsBtn.addEventListener('click', () => setShortcuts(!state.shortcuts));
  let storedShortcuts = 'off';
  try {
    storedShortcuts = localStorage.getItem('supplyguard-shortcuts') || 'off';
  } catch (_) {}
  setShortcuts(storedShortcuts === 'on');
  document.addEventListener('keydown', onKeydown);

  function applyBookmark(bookmark, { initial } = {}) {
    // On a live restore, fields the encoder omitted are defaults: reset
    // them so the page shows exactly the state the link describes.
    if (bookmark.policy || !initial) {
      state.policy = sanitizePolicy(bookmark.policy ?? DEFAULT_POLICY);
      syncPolicyControls();
    }
    if (bookmark.diff) {
      state.diff.left = bookmark.diff.left;
      state.diff.right = bookmark.diff.right;
    } else if (!initial) {
      state.diff.left = '';
      state.diff.right = '';
    }
    if (bookmark.diff || !initial) {
      state.diff.result = null;
      state.diff.labels = null;
      state.diff.error = '';
    }
    if (!initial) {
      // Pasted text outranks the pickers, so a live restore must drop it or
      // the restored selection is silently ignored.
      if (els.diffLeftText) els.diffLeftText.value = '';
      if (els.diffRightText) els.diffRightText.value = '';
    }
    const wanted = bookmark.presetId && (presets || []).some(p => p.id === bookmark.presetId)
      ? bookmark.presetId
      : (initial ? (presets || [])[0]?.id : null);
    if (wanted) loadScenario(wanted);
    else if (initial) { render(); setStatus('Scenario presets are not available yet.'); }
    else render();
    if (bookmark.changes && bookmark.changes.size) commitChanges(bookmark.changes);
    else if (!initial && state.changes.size) commitChanges(new Map());
    activateTab(bookmark.tab ?? (initial ? null : 'policy'));
  }
  const bookmark = decodeBookmark(location.hash);
  if (bookmark) applyBookmark(bookmark, { initial: true });
  else applyBookmark({ }, { initial: true });
  window.addEventListener('hashchange', () => {
    const next = decodeBookmark(location.hash);
    if (next) applyBookmark(next);
  });
}

init();
