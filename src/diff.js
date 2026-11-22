/* diff.js: compare two parsed inventories (presets, imports, or the live
   analysis) as a reviewer reads a dependency pull request: what was added,
   removed, raised, lowered, and which risk signals are newly introduced.
   Everything is computed from local models; no registry is consulted. */

import { analyze } from './detectors.js';
import { compare } from './graph.js';

const canonicalName = (name, ecosystem) => (ecosystem === 'pypi'
  ? String(name).toLowerCase().replace(/[-_.]+/g, '-')
  : String(name).toLowerCase());

/* Semver and PEP 440 style ordering: numeric segments compare by value,
   a release ranks above its prereleases, build metadata is ignored, and
   non-numeric tails fall back to codepoint order. Deterministic for any
   strings the parsers accept. */
/* A numeric core segment may carry a prerelease tag like rc1 or a2. Tags
   rank below the plain release (PEP 440 style: dev < a < b < rc < release
   < post), so 1.2rc1 sorts before 1.2 rather than after 1.10. */
const TAG_RANK = { dev: 0, a: 1, alpha: 1, b: 2, beta: 2, m: 2.5, milestone: 2.5, c: 3, pre: 3, preview: 3, rc: 3, post: 5, rev: 5, r: 5, p: 5 };

export function compareVersions(left, right) {
  const split = value => {
    const text = String(value ?? '').trim().replace(/^v/i, '');
    const [head, ...pre] = text.split('+')[0].split('-');
    // PEP 440 writes 1.2.dev1 / 1.2.rc1 with the tag as its own segment;
    // join it to the preceding number so an atom sees 2dev1 / 2rc1.
    const core = head
      .replace(/(\d)[._-]?(dev|alpha|beta|milestone|preview|pre|post|rev|rc|a|b|c|m|r)(?=\d|$|[._])/gi, '$1$2')
      .replace(/([a-zA-Z])[._](\d)/g, '$1$2');
    return { core: core.split('.'), pre: pre.join('-') ? pre.join('-').split('.') : [] };
  };
  // Each core position is an atom: a BigInt number plus a tag chain like
  // [rc,1],[dev,1]. A missing chain entry is a plain release (rank 4);
  // unknown tags rank 6 and tie-break on their name so 1k sorts under 1l.
  const atom = x => {
    if (/^\d+$/.test(x)) return { n: BigInt(x), tags: [] };
    /* The tail accepts one alnum run starting with a letter; same language
       as a repeated letters+digits chain, but without the nested
       quantifier that makes 60 letters plus a '!' take minutes. */
    const tagged = /^(\d+)([a-zA-Z][a-zA-Z0-9]*)?$/.exec(x);
    if (!tagged) return null;
    const tags = [...(tagged[2] ?? '').matchAll(/([a-zA-Z]+)(\d*)/g)].map(t => {
      const name = t[1].toLowerCase();
      // Maven's m/milestone only ranks as a milestone when numbered (M1);
      // a bare m is an OpenSSL-style patch letter like l -> m.
      let rank = TAG_RANK[name] ?? 6;
      if ((name === 'm' || name === 'milestone') && !t[2]) rank = 6;
      return [rank, rank === 6 ? name : '', t[2] ? BigInt(t[2]) : 0n];
    });
    return { n: BigInt(tagged[1]), tags };
  };
  const tagCmp = (lt, rt) => {
    for (let i = 0; i < Math.max(lt.length, rt.length); i++) {
      const [lr, lname, ln] = lt[i] ?? [4, '', 0n];
      const [rr, rname, rn] = rt[i] ?? [4, '', 0n];
      if (lr !== rr) return lr - rr;
      const nd = compare(lname, rname);
      if (nd) return nd;
      const dt = ln - rn;
      if (dt) return dt < 0n ? -1 : 1;
    }
    return 0;
  };
  /* A version's core is a release tuple (positions up to and including the
     first prerelease tag, dev/a/b/c/rc/pre rank <= 3) followed by a suffix
     series. Compare release numbers first, padded with zeros, so the tag
     can never outrank a later release number (2.0.post1 < 2.0.1); then
     compare the suffix series pairwise; then the dash prerelease. */
  const lay = s => {
    const atoms = s.core.map(atom);
    const stop = atoms.findIndex(x => x && x.tags.some(t => t[0] <= 3));
    const relEnd = stop === -1 ? s.core.length : stop + 1;
    const suffix = stop === -1
      ? (() => {
        const flat = atoms.flatMap(x => x?.tags ?? []);
        return flat.length ? [{ n: 0n, tags: flat }] : [];
      })()
      : atoms.slice(stop).map((x, i) => {
        const before = i === 0 ? atoms.slice(0, stop).flatMap(y => y?.tags ?? []) : [];
        // The stop atom's number was already compared in the release loop;
        // re-emitting it here would decide cross-written releases twice.
        return x ? { n: i === 0 ? 0n : x.n, tags: [...before, ...x.tags] } : { raw: s.core[stop + i] };
      });
    return { atoms, relEnd, suffix, raw: s.core };
  };
  const sa = split(left);
  const sb = split(right);
  const A = lay(sa);
  const B = lay(sb);
  for (let i = 0; i < Math.max(A.relEnd, B.relEnd); i++) {
    const ax = i < A.relEnd ? A.atoms[i] : { n: 0n, tags: [] };
    const bx = i < B.relEnd ? B.atoms[i] : { n: 0n, tags: [] };
    if (ax && bx) {
      const dn = ax.n - bx.n;
      if (dn) return dn < 0n ? -1 : 1;
    } else if (ax || bx) {
      return ax ? -1 : 1;
    } else {
      const d = compare(A.raw[i] ?? '0', B.raw[i] ?? '0');
      if (d) return d;
    }
  }
  for (let i = 0; i < Math.max(A.suffix.length, B.suffix.length); i++) {
    const ax = i < A.suffix.length ? A.suffix[i] : { n: 0n, tags: [] };
    const bx = i < B.suffix.length ? B.suffix[i] : { n: 0n, tags: [] };
    const axRaw = ax && ax.raw !== undefined;
    const bxRaw = bx && bx.raw !== undefined;
    if (axRaw || bxRaw) {
      if (axRaw !== bxRaw) return axRaw ? 1 : -1;
      const d = compare(ax.raw, bx.raw);
      if (d) return d;
      continue;
    }
    const d = tagCmp(ax.tags, bx.tags) || (ax.n === bx.n ? 0 : ax.n < bx.n ? -1 : 1);
    if (d) return d;
  }
  const preSeg = (x, y) => {
    const nx = /^\d+$/.test(x);
    const ny = /^\d+$/.test(y);
    if (nx && ny) { const d = BigInt(x) - BigInt(y); return d < 0n ? -1 : d > 0n ? 1 : 0; }
    if (nx !== ny) return nx ? -1 : 1;
    return compare(x, y);
  };
  if (!sa.pre.length || !sb.pre.length) return sa.pre.length ? -1 : sb.pre.length ? 1 : 0;
  for (let i = 0; i < Math.max(sa.pre.length, sb.pre.length); i++) {
    if (sa.pre[i] === undefined) return -1;
    if (sb.pre[i] === undefined) return 1;
    const d = preSeg(sa.pre[i], sb.pre[i]);
    if (d) return d;
  }
  return 0;
}

/* Package identity across two inventories: ecosystem plus canonical name.
   Multiple installed versions of one name stay grouped so an upgrade reads
   as one change, not an add and a remove. */
export function inventory(model) {
  const map = new Map();
  for (const node of Array.isArray(model?.nodes) ? model.nodes : []) {
    if (node.root || node.id === model?.rootId) continue;
    const ecosystem = node.ecosystem || '';
    const name = typeof node.name === 'string' && node.name ? node.name : String(node.id);
    const key = `${ecosystem}:${canonicalName(name, ecosystem)}`;
    if (!map.has(key)) map.set(key, { key, ecosystem, name, entries: new Map() });
    const entry = map.get(key);
    const version = typeof node.version === 'string' ? node.version : '';
    if (!entry.entries.has(version)) entry.entries.set(version, []);
    entry.entries.get(version).push({ id: node.id, unresolved: Boolean(node.unresolved) });
  }
  for (const entry of map.values()) {
    entry.versions = [...entry.entries.keys()].sort(compareVersions);
    delete entry.entries;
  }
  return map;
}

export function diffModels(before, after) {
  const left = inventory(before);
  const right = inventory(after);
  const added = [];
  const removed = [];
  const changed = [];
  for (const key of [...new Set([...left.keys(), ...right.keys()])].sort(compare)) {
    const a = left.get(key);
    const b = right.get(key);
    if (!a) {
      added.push({ key, ecosystem: b.ecosystem, name: b.name, versions: b.versions });
      continue;
    }
    if (!b) {
      removed.push({ key, ecosystem: a.ecosystem, name: a.name, versions: a.versions });
      continue;
    }
    const from = a.versions.filter(version => !b.versions.includes(version));
    const to = b.versions.filter(version => !a.versions.includes(version));
    if (!from.length && !to.length) continue;
    let direction;
    if (from.length === 1 && to.length === 1) {
      if (from[0] === '' || to[0] === '') {
        direction = from[0] === '' ? 'pinned' : 'unpinned';
      } else {
        const order = compareVersions(from[0], to[0]);
        direction = order < 0 ? 'upgraded' : order > 0 ? 'downgraded' : 'equivalent';
      }
    } else if (from.length && to.length) {
      // Both lists are already sorted by compareVersions, so the all-below /
      // all-above checks need only the endpoints, not every pair.
      if (compareVersions(from.at(-1), to[0]) < 0) direction = 'upgraded';
      else if (compareVersions(from[0], to.at(-1)) > 0) direction = 'downgraded';
      else direction = 'mixed';
    } else {
      direction = to.length ? 'expanded' : 'reduced';
    }
    changed.push({ key, ecosystem: a.ecosystem, name: a.name, from, to, direction });
  }
  return { added, removed, changed };
}

/* Finding identity across two runs: rule plus canonical component name, so a
   reordered node id or a version bump still lines the signal up. */
function signalKeys(analysis) {
  const byId = new Map((analysis?.model?.nodes ?? []).map(node => [node.id, node]));
  const map = new Map();
  for (const finding of Array.isArray(analysis?.findings) ? analysis.findings : []) {
    const node = byId.get(finding.nodeId);
    const name = node && typeof node.name === 'string' && node.name ? node.name : String(finding.nodeId);
    const ecosystem = node?.ecosystem || '';
    const key = `${finding.ruleId}:${ecosystem}:${canonicalName(name, ecosystem)}`;
    if (!map.has(key)) map.set(key, []);
    map.get(key).push({
      key, ruleId: finding.ruleId, severity: finding.severity, title: finding.title,
      name, version: node?.version ?? '', nodeId: finding.nodeId, points: finding.points ?? 0,
      reachable: Boolean(finding.reachable),
    });
  }
  return map;
}

export function diffAnalyses(beforeAnalysis, afterAnalysis) {
  const before = beforeAnalysis?.model;
  const after = afterAnalysis?.model;
  const delta = diffModels(before, after);
  const leftSignals = signalKeys(beforeAnalysis);
  const rightSignals = signalKeys(afterAnalysis);
  const introduced = [...rightSignals.keys()].filter(key => !leftSignals.has(key))
    .sort(compare).flatMap(key => rightSignals.get(key))
    .sort((a, b) => compare(a.key, b.key));
  const resolved = [...leftSignals.keys()].filter(key => !rightSignals.has(key))
    .sort(compare).flatMap(key => leftSignals.get(key))
    .sort((a, b) => compare(a.key, b.key));
  const metric = (analysis, key) => analysis?.metrics?.[key] ?? 0;
  return {
    ...delta,
    signals: { introduced, resolved },
    score: {
      before: beforeAnalysis?.score ?? 0,
      after: afterAnalysis?.score ?? 0,
      delta: (afterAnalysis?.score ?? 0) - (beforeAnalysis?.score ?? 0),
    },
    findings: { before: beforeAnalysis?.findings?.length ?? 0, after: afterAnalysis?.findings?.length ?? 0 },
    reachable: { before: metric(beforeAnalysis, 'reachable'), after: metric(afterAnalysis, 'reachable') },
    affected: { before: metric(beforeAnalysis, 'affected'), after: metric(afterAnalysis, 'affected') },
  };
}

/* Convenience for pasted text: parse and analyze both sides, letting parse
   errors surface to the caller exactly as the main import path reports them. */
export function diffInputs(beforeText, beforeName, afterText, afterName, parseInput) {
  const beforeModel = parseInput(beforeText, beforeName);
  const afterModel = parseInput(afterText, afterName);
  return { beforeModel, afterModel, diff: diffAnalyses(analyze(beforeModel), analyze(afterModel)) };
}
