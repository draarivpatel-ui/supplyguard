/* viz.js: deterministic layered SVG rendering of the dependency graph.
   Only projection is limited here; the analysis itself is never trimmed. */

import { compare } from './graph.js';

const SVG_NS = 'http://www.w3.org/2000/svg';

const NODE_W = 132;
const NODE_H = 48;
const COL_GAP = 29;
const ROW_GAP = 18;
const PAD = 18;
const HEADER = 28;
const MAX_RENDER_NODES = 90;

const SEV_RANK = { high: 0, medium: 1, low: 2 };
const SEV_NAME = ['high', 'medium', 'low'];

function el(tag, attrs) {
  const n = document.createElementNS(SVG_NS, tag);
  for (const k in attrs) n.setAttribute(k, attrs[k]);
  return n;
}

function txt(x, y, str, cls, anchor) {
  const t = el('text', { x, y, class: cls });
  if (anchor) t.setAttribute('text-anchor', anchor);
  t.textContent = str;
  return t;
}

function clip(str, n) {
  const chars = [...String(str == null ? '' : str)];
  return chars.length > n ? chars.slice(0, n - 1).join('') + '…' : chars.join('');
}

function note(str) {
  const p = document.createElement('p');
  p.className = 'graph-note';
  p.textContent = str;
  return p;
}

export function renderGraph(container, analysis, selectedId, onSelect) {
  container.textContent = '';
  const model = analysis && analysis.model;
  const nodes = (model && model.nodes) || [];
  if (!nodes.length) {
    container.append(note('Nothing to draw yet: the current input has no components.'));
    return { shown: 0, truncated: 0 };
  }

  const findings = analysis.findings || [];
  const depths = analysis.depths;
  const paths = analysis.paths;

  const sevOf = new Map();
  for (const f of findings) {
    const r = SEV_RANK[f.severity];
    if (r == null) continue;
    const cur = sevOf.get(f.nodeId);
    if (cur == null || r < cur) sevOf.set(f.nodeId, r);
  }

  const depthOf = (id) => {
    const d = depths && typeof depths.get === 'function' ? depths.get(id) : null;
    return typeof d === 'number' ? d : null;
  };
  const pathOf = (id) => {
    const p = paths && typeof paths.get === 'function' ? paths.get(id) : null;
    return Array.isArray(p) && p.length ? p : null;
  };

  /* Highlighted trace: the selected component's path. With no selection the
     most severe flagged path opens the graph on real evidence. When the
     selection has no path, nothing unrelated is highlighted. */
  let hiPath = null;
  let hiSev = 'low';
  if (selectedId != null) {
    const p = pathOf(selectedId);
    if (p) {
      hiPath = p;
      const r = sevOf.get(selectedId);
      hiSev = r == null ? 'low' : SEV_NAME[r];
    }
  } else {
    const flagged = findings
      .filter((f) => Array.isArray(f.path) && f.path.length)
      .sort((a, b) => (SEV_RANK[a.severity] ?? 9) - (SEV_RANK[b.severity] ?? 9));
    if (flagged.length) {
      hiPath = flagged[0].path;
      hiSev = flagged[0].severity || 'low';
    }
  }
  const onPath = new Set(hiPath || []);
  const pathEdge = new Set();
  if (hiPath) {
    for (let i = 0; i + 1 < hiPath.length; i++) pathEdge.add(JSON.stringify([hiPath[i], hiPath[i + 1]]));
  }

  /* Projection limit: root and the highlighted trace get mandatory priority,
     then flagged components by severity, then BFS order. The cap is enforced
     even when the priority set alone exceeds it, root and selection first.
     Truncation is annotated below the graph. */
  let shown = nodes;
  let truncated = 0;
  if (nodes.length > MAX_RENDER_NODES) {
    const pathPriority =
      hiPath && hiPath.length >= MAX_RENDER_NODES
        ? [...hiPath.slice(0, 44), ...hiPath.slice(-45)]
        : hiPath ?? [];
    const keep = new Set([model.rootId, ...pathPriority]);
    if (selectedId != null) keep.add(selectedId);
    const rest = nodes
      .filter((n) => !keep.has(n.id))
      .sort(
        (a, b) =>
          (sevOf.get(a.id) ?? 9) - (sevOf.get(b.id) ?? 9) ||
          (depthOf(a.id) ?? 999) - (depthOf(b.id) ?? 999) ||
          compare(String(a.name), String(b.name)) ||
          compare(String(a.id), String(b.id))
      );
    for (const n of rest) {
      if (keep.size >= MAX_RENDER_NODES) break;
      keep.add(n.id);
    }
    shown = nodes.filter((n) => keep.has(n.id));
    if (shown.length > MAX_RENDER_NODES) {
      const priority = (n) => (n.id === model.rootId || n.id === selectedId ? 0 : 1);
      shown = [...shown].sort((a, b) => priority(a) - priority(b)).slice(0, MAX_RENDER_NODES);
    }
    truncated = nodes.length - shown.length;
  }

  /* Deterministic BFS layering: column = depth, unreachable in a final
     dashed column, every layer sorted by name then id. */
  const layers = new Map();
  const unreachable = [];
  for (const n of shown) {
    const d = depthOf(n.id);
    if (d == null) unreachable.push(n);
    else {
      const arr = layers.get(d) || [];
      arr.push(n);
      layers.set(d, arr);
    }
  }
  const depthKeys = [...layers.keys()].sort((a, b) => a - b);
  const byName = (a, b) =>
    compare(String(a.name), String(b.name)) || compare(String(a.id), String(b.id));
  for (const arr of layers.values()) arr.sort(byName);
  unreachable.sort(byName);

  const cols = depthKeys.length + (unreachable.length ? 1 : 0);
  const colX = (i) => PAD + i * (NODE_W + COL_GAP);
  const maxRows = Math.max(1, ...[...layers.values()].map((a) => a.length), unreachable.length);
  const W = PAD * 2 + cols * (NODE_W + COL_GAP) - COL_GAP;
  const H = PAD + HEADER + maxRows * (NODE_H + ROW_GAP) - ROW_GAP + PAD;

  const pos = new Map();
  depthKeys.forEach((d, ci) => {
    layers.get(d).forEach((n, ri) =>
      pos.set(n.id, { x: colX(ci), y: PAD + HEADER + ri * (NODE_H + ROW_GAP), unreach: false })
    );
  });
  if (unreachable.length) {
    const ci = depthKeys.length;
    unreachable.forEach((n, ri) =>
      pos.set(n.id, { x: colX(ci), y: PAD + HEADER + ri * (NODE_H + ROW_GAP), unreach: true })
    );
  }

  const svg = el('svg', {
    width: W,
    height: H,
    viewBox: `0 0 ${W} ${H}`,
    role: 'group',
    'aria-label': 'Dependency graph, layered by depth from the root',
  });

  depthKeys.forEach((d, ci) => {
    svg.append(txt(colX(ci) + 2, PAD + 8, 'depth ' + d, 'layer-label'));
  });
  if (unreachable.length) {
    svg.append(txt(colX(depthKeys.length) + 2, PAD + 8, 'unreachable', 'layer-label'));
  }

  const quarantined = new Set(nodes.filter((n) => n.quarantined).map((n) => n.id));
  for (const e of model.edges || []) {
    const a = pos.get(e.from);
    const b = pos.get(e.to);
    if (!a || !b) continue;
    const ln = el('line', {
      x1: a.x + NODE_W,
      y1: a.y + NODE_H / 2,
      x2: b.x,
      y2: b.y + NODE_H / 2,
      class: 'edge',
    });
    if (pathEdge.has(JSON.stringify([e.from, e.to]))) ln.setAttribute('class', 'edge hi-' + hiSev);
    else if (a.unreach || b.unreach || quarantined.has(e.from) || quarantined.has(e.to))
      ln.setAttribute('class', 'edge dim');
    svg.append(ln);
  }

  /* Roving tabindex: one stop in the graph, arrows move by screen geometry,
     Enter or Space activates. Home and End jump to the first and last node. */
  const focusCells = [];
  const moveFocus = (fromId, key) => {
    const current = focusCells.find((cell) => cell.id === fromId);
    if (!current) return;
    let best = null;
    let bestScore = Infinity;
    for (const cell of focusCells) {
      if (cell === current) continue;
      const dx = cell.x - current.x;
      const dy = cell.y - current.y;
      let score = null;
      if (key === 'ArrowRight' && dx > 0) score = dx * 8 + Math.abs(dy);
      if (key === 'ArrowLeft' && dx < 0) score = -dx * 8 + Math.abs(dy);
      if (key === 'ArrowDown' && dy > 0) score = dy * 8 + Math.abs(dx);
      if (key === 'ArrowUp' && dy < 0) score = -dy * 8 + Math.abs(dx);
      if (score !== null && score < bestScore) {
        bestScore = score;
        best = cell;
      }
    }
    if (best) best.g.focus();
  };

  for (const n of shown) {
    const p = pos.get(n.id);
    const r = sevOf.get(n.id);
    const cls = ['node'];
    if (r != null) cls.push('sev-' + SEV_NAME[r]);
    if (p.unreach) cls.push('unreachable');
    if (n.quarantined) cls.push('quarantined');
    if (n.id === selectedId) cls.push('selected');
    if (onPath.has(n.id)) cls.push('on-path', 'hi-' + hiSev);
    if (n.id === model.rootId || n.root) cls.push('is-root');

    const g = el('g', {
      class: cls.join(' '),
      'data-node': n.id,
      role: 'button',
      tabindex: '-1',
      'aria-pressed': n.id === selectedId ? 'true' : 'false',
      transform: `translate(${p.x},${p.y})`,
    });

    const statusBits = [];
    if (r != null) statusBits.push(SEV_NAME[r] + ' severity signal');
    if (p.unreach) statusBits.push('unreachable from root');
    if (n.quarantined) statusBits.push('quarantined');
    g.setAttribute(
      'aria-label',
      'Select ' +
        n.name +
        (n.version ? ' ' + n.version : '') +
        (statusBits.length ? ', ' + statusBits.join(', ') : '')
    );

    g.append(el('rect', { width: NODE_W, height: NODE_H, rx: 6 }));
    const textX = r != null ? 26 : 12;
    if (r != null) g.append(el('circle', { class: 'dot sev-' + SEV_NAME[r], cx: 14, cy: NODE_H / 2, r: 4.5 }));
    g.append(txt(textX, 21, clip(n.name, 17), 'name'));
    const sub = [n.version ? 'v' + n.version : null, n.ecosystem].filter(Boolean).join(' · ');
    g.append(txt(textX, 37, clip(sub || 'unversioned', 17), 'sub mono'));
    if (n.id === model.rootId || n.root) g.append(txt(NODE_W - 10, 15, 'root', 'tag mono', 'end'));
    if (n.quarantined) g.append(txt(NODE_W - 8, NODE_H - 8, 'Q', 'qtag mono', 'end'));

    const title = el('title', {});
    title.textContent =
      n.name +
      (n.version ? ' ' + n.version : '') +
      (statusBits.length ? ' (' + statusBits.join(', ') + ')' : '');
    g.append(title);

    focusCells.push({ id: n.id, x: p.x, y: p.y, g });

    const fire = () => {
      if (typeof onSelect === 'function') onSelect(n.id);
    };
    g.addEventListener('click', fire);
    g.addEventListener('focus', () => {
      for (const cell of focusCells) cell.g.setAttribute('tabindex', cell.g === g ? '0' : '-1');
    });
    g.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        fire();
      } else if (e.key.startsWith('Arrow')) {
        e.preventDefault();
        moveFocus(n.id, e.key);
      } else if (e.key === 'Home' || e.key === 'End') {
        e.preventDefault();
        const edge = e.key === 'Home' ? focusCells[0] : focusCells[focusCells.length - 1];
        if (edge) edge.g.focus();
      }
    });
    svg.append(g);
  }

  const initialFocus =
    (selectedId != null && focusCells.find((cell) => cell.id === selectedId)) || focusCells[0];
  if (initialFocus) initialFocus.g.setAttribute('tabindex', '0');

  container.append(svg);

  const notes = [];
  if (truncated) {
    notes.push(
      `Graph projection shows ${shown.length} of ${nodes.length} components, prioritized by the highlighted trace and findings. Analysis and the findings table still cover all ${nodes.length}.`
    );
  }
  if (selectedId != null && !pathOf(selectedId)) {
    notes.push('No dependency path reaches the selected component.');
  } else if (!hiPath && findings.length) {
    notes.push('No flagged dependency path is available to highlight.');
  }
  const nonRoot = nodes.filter((n) => n.id !== model.rootId && !n.root);
  if (nonRoot.length && nonRoot.every((n) => n.quarantined)) {
    notes.push('Every component is quarantined in this simulation.');
  }
  for (const m of notes) container.append(note(m));

  return { shown: shown.length, truncated };
}
