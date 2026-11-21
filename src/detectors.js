import { breadthFirst, compare, indexGraph, trace } from './graph.js';

export const RULES = Object.freeze({
  'SG001': ['Lookalike package name', 'medium', 16, 'Confirm the intended package with its maintainer and compare the exact name.'],
  'SG002': ['Confusable package name', 'high', 27, 'Compare code points against the intended package and use the verified spelling.'],
  'SG003': ['Install lifecycle hook', 'low', 5, 'Review the package manifest and install script without executing it.'],
  'SG004': ['Shell download and pipe indicators', 'high', 28, 'Review this hook and its data flow in an isolated, read-only workflow.'],
  'SG005': ['Encoded content indicator', 'medium', 9, 'Review the encoded content separately without executing it.'],
  'SG006': ['Credential and egress indicators', 'high', 30, 'Check the hook for credential access and outbound data flow.'],
  'SG007': ['Missing SHA-512 integrity', 'medium', 12, 'Regenerate the lockfile with a trusted registry and verify the artifact independently.'],
  'SG008': ['Non-default artifact source', 'medium', 14, 'Confirm the intended source, then verify its ownership and immutable artifact digest.'],
  'SG009': ['Unpinned dependency declaration', 'low', 4, 'Pin the intended version if the project policy requires exact declarations.'],
  'SG010': ['Conflicting installed versions', 'low', 5, 'Confirm why multiple versions are installed before consolidating.'],
  'SG011': ['Lockfile format drift', 'low', 5, 'Compare the lockfile version with the team standard.'],
  'SG012': ['Recorded and expected digests differ', 'high', 30, 'Verify a trusted expected digest against the downloaded artifact before installation.'],
  'SG013': ['Expected private source differs', 'high', 24, 'Verify that the scope is mapped to its intended registry before installation.'],
  'SG014': ['Unresolved dependency reference', 'medium', 8, 'Regenerate or inspect the inventory to recover the missing dependency record.'],
  'SG015': ['Missing package checksum', 'medium', 12, 'Compare the recorded checksum with the verified registry release.'],
  'SG016': ['Local or direct requirement source', 'medium', 14, 'Verify that the direct reference is expected and pinned to a trusted artifact.'],
  'SG017': ['Declared version falls below expected minimum', 'medium', 17, 'Review why the resolved version is older than the trusted baseline.'],
});

const CORPUS = {
  npm: 'react react-dom express lodash axios next vite webpack typescript eslint chalk debug commander dotenv node-fetch prettier semver zod minimist ws yargs postcss rollup esbuild vitest tslib rimraf uuid request got vue svelte'.split(' '),
  pypi: 'requests urllib3 numpy pandas scipy flask django fastapi pillow cryptography pytest pydantic pip setuptools wheel certifi packaging boto3 sqlalchemy aiohttp uvicorn rich click jinja2'.split(' '),
  cargo: 'serde serde_json tokio clap anyhow thiserror syn quote libc rand bytes regex chrono reqwest log tracing hyper once_cell proc-macro2 itertools rayon futures'.split(' '),
};

const CONFUSABLES = new Map(Object.entries({
  '\u0430': 'a', '\u0432': 'b', '\u0441': 'c', '\u0435': 'e', '\u04bb': 'h', '\u0456': 'i', '\u0458': 'j',
  '\u043a': 'k', '\u043c': 'm', '\u043e': 'o', '\u0440': 'p', '\u0455': 's', '\u0442': 't', '\u0445': 'x',
  '\u0443': 'y', '\u0501': 'd', '\u051b': 'q', '\u04cf': 'l', '\u03b1': 'a', '\u03b2': 'b', '\u03b5': 'e',
  '\u03b9': 'i', '\u03ba': 'k', '\u03bf': 'o', '\u03c1': 'p', '\u03c4': 't', '\u03c5': 'u', '\u03c7': 'x',
  '\u03bd': 'v', '\u03f2': 'c',
}));

export const skeleton = value => [...value.normalize('NFKC').toLowerCase()]
  .map(char => CONFUSABLES.get(char) ?? char).join('').replace(/\p{Default_Ignorable_Code_Point}/gu, '');

// True Damerau-Levenshtein, not optimal string alignment. Last positions allow overlapping edits.
export function damerauLevenshtein(left, right) {
  const a = [...left];
  const b = [...right];
  const limit = a.length + b.length;
  const rows = Array.from({ length: a.length + 2 }, () => new Uint32Array(b.length + 2));
  const last = new Map();
  rows[0][0] = limit;
  for (let i = 0; i <= a.length; i++) { rows[i + 1][0] = limit; rows[i + 1][1] = i; }
  for (let j = 0; j <= b.length; j++) { rows[0][j + 1] = limit; rows[1][j + 1] = j; }
  for (let i = 1; i <= a.length; i++) {
    let previousColumn = 0;
    for (let j = 1; j <= b.length; j++) {
      const lastRow = last.get(b[j - 1]) ?? 0;
      const lastColumn = previousColumn;
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      if (!cost) previousColumn = j;
      rows[i + 1][j + 1] = Math.min(
        rows[i][j] + cost,
        rows[i + 1][j] + 1,
        rows[i][j + 1] + 1,
        rows[lastRow][lastColumn] + i - lastRow + j - lastColumn - 1,
      );
    }
    last.set(a[i - 1], i);
  }
  return rows[a.length + 1][b.length + 1];
}

const keyboard = new Map(['1234567890', 'qwertyuiop', 'asdfghjkl', 'zxcvbnm'].flatMap((row, y) =>
  [...row].map((char, x) => [char, [x + [0, 0.25, 0.5, 1][y], y]])));

export function keyboardAdjacent(a, b) {
  const x = keyboard.get(a);
  const y = keyboard.get(b);
  return a !== b && Boolean(x && y && Math.abs(x[0] - y[0]) <= 1 && Math.abs(x[1] - y[1]) <= 1);
}

const canonicalName = (value, ecosystem) => ecosystem === 'pypi' ?
  value.toLowerCase().replace(/[-_.]+/g, '-') : value.toLowerCase();

function typo(item) {
  const names = CORPUS[item.ecosystem];
  if (!names || item.name.startsWith('@')) return null;
  const name = canonicalName(item.name, item.ecosystem);
  if (names.includes(name)) return null;
  const visual = canonicalName(skeleton(item.name), item.ecosystem);
  if (visual !== name && names.includes(visual)) {
    return ['SG002', `The confusable skeleton matches ${visual}. This is a bounded Unicode mapping, not proof of impersonation.`];
  }
  const chars = [...name];
  const candidates = names.filter(value => value.length >= 4 && Math.abs(value.length - chars.length) <= 1)
    .filter(value => damerauLevenshtein(name, value) === 1)
    .map(value => {
      const diff = [...value].flatMap((char, i) => char === chars[i] ? [] : [[char, chars[i]]]);
      return [value, value.length === chars.length && diff.length === 1 && keyboardAdjacent(...diff[0])];
    }).sort((a, b) => Number(b[1]) - Number(a[1]) || compare(a[0], b[0]));
  if (!candidates.length) return null;
  const [match, adjacent] = candidates[0];
  return ['SG001', `One Damerau-Levenshtein edit from ${match}${adjacent ? '; changed key is adjacent on QWERTY' : ''}.`];
}

const HASH_SIZE = { sha256: 32, sha384: 48, sha512: 64 };
export function sriHashes(sri) {
  if (!sri) return [];
  return sri.trim().split(/\s+/).flatMap(token => {
    const match = /^(sha256|sha384|sha512)-([A-Za-z0-9+/]+={0,2})(?:\?[!-~]+)?$/.exec(token);
    if (!match) return [];
    try {
      const binary = atob(match[2]);
      if (binary.length !== HASH_SIZE[match[1]] ||
          btoa(binary).replace(/=+$/, '') !== match[2].replace(/=+$/, '')) return [];
      return [{ alg: `SHA-${match[1].slice(3)}`,
        content: Array.from(binary, value => value.charCodeAt(0).toString(16).padStart(2, '0')).join('') }];
    } catch { return []; }
  });
}
const hasSHA512 = sri => sriHashes(sri).some(hash => hash.alg === 'SHA-512');

export function sourceHost(resolved) {
  try {
    const url = new URL(resolved.replace(/^(?:registry|sparse|git)\+/, ''));
    return url.protocol === 'https:' && !url.username && !url.password && !url.port ? url.hostname : '';
  } catch { return ''; }
}

const download = /\b(?:curl|wget)\b[^|\r\n]{0,300}\|[ \t]*(?:(?:[A-Za-z0-9_./-]+\/)?(?:ba|da|z|k)?sh|node|python3?)(?=$|[\s;&])/i;
const decode = /\b(?:base64\s+(?:-d|--decode)\b|atob\s*\(|FromBase64String\s*\()/i;
const sensitive = /\bprocess\s*(?:\.\s*env|\[\s*['"]env['"]\s*\])|(?:\.npmrc|\.ssh[/\\]|\.aws[/\\]credentials|credentials\.json)/i;
const egress = /\b(?:curl|wget|fetch|XMLHttpRequest|https?\.(?:request|get))\b/i;
const semver = /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;
function belowVersion(value, minimum) {
  if (!semver.test(value) || !semver.test(minimum)) return false;
  const split = v => {
    const [core, ...suffix] = v.split('+')[0].split('-');
    return [core.split('.').map(BigInt), suffix.join('-').split('.').filter(Boolean)];
  };
  const [a, preA] = split(value);
  const [b, preB] = split(minimum);
  for (let i = 0; i < 3; i++) if (a[i] !== b[i]) return a[i] < b[i];
  if (!preA.length || !preB.length) return preA.length > 0 && !preB.length;
  for (let i = 0; i < Math.max(preA.length, preB.length); i++) {
    if (preA[i] === preB[i]) continue;
    if (preA[i] === undefined || preB[i] === undefined) return preA[i] === undefined;
    const numericA = /^\d+$/.test(preA[i]);
    const numericB = /^\d+$/.test(preB[i]);
    if (numericA && numericB) return BigInt(preA[i]) < BigInt(preB[i]);
    if (numericA !== numericB) return numericA;
    return preA[i] < preB[i];
  }
  return false;
}

function isPinned(edge, node) {
  if (node.ecosystem === 'npm') {
    const spec = edge.spec.startsWith('npm:') ? edge.spec.slice(edge.spec.lastIndexOf('@') + 1) : edge.spec;
    return semver.test(spec);
  }
  if (node.ecosystem === 'pypi') return Boolean(node.version && /^={2,3}\s*[^,\s]+$/.test(edge.spec));
  return true;
}

export function analyze(model) {
  const active = model.nodes.filter(node => !node.quarantined);
  const ids = new Set(active.map(node => node.id));
  const edges = model.edges.filter(edge => ids.has(edge.from) && ids.has(edge.to));
  const { byId, outgoing, incoming } = indexGraph(active, edges);
  const { depths, predecessor } = breadthFirst(model.rootId, outgoing);
  const paths = new Map();
  const findings = [];
  const affectedBy = new Map();
  const affectedUnion = new Set();
  const flagged = new Set();
  const versions = new Map();
  const declared = new Map();
  for (const edge of edges) {
    if (!declared.has(edge.to)) declared.set(edge.to, []);
    declared.get(edge.to).push(edge);
  }
  for (const node of active) {
    if (node.root || node.unresolved || !node.version || node.marker || !node.ecosystem) continue;
    const key = `${node.ecosystem}:${canonicalName(node.name, node.ecosystem)}`;
    if (!versions.has(key)) versions.set(key, new Set());
    versions.get(key).add(node.version);
  }
  for (const node of active) {
    const path = trace(node.id, predecessor);
    if (path) paths.set(node.id, path);
    function add(ruleId, evidence) {
      const [title, severity, weight, recommendation] = RULES[ruleId];
      if (!affectedBy.has(node.id)) {
        const affected = [...breadthFirst(node.id, incoming).depths.keys()]
          .filter(id => id !== node.id && id !== model.rootId && !byId.get(id).unresolved).sort(compare);
        affectedBy.set(node.id, affected);
        if (path) for (const id of affected) affectedUnion.add(id);
      }
      findings.push({
        ruleId, nodeId: node.id, severity, title, evidence, recommendation, weight,
        points: path ? weight : 0, path, depth: depths.get(node.id) ?? null,
        affected: affectedBy.get(node.id), reachable: Boolean(path),
      });
      flagged.add(node.id);
    }
    if (node.root) {
      if (model.format === 'npm' && model.lockfileVersion === 2) {
        add('SG011', 'npm lockfile format 2 was supplied; format 3 is the workbench baseline, not a security requirement.');
      }
      continue;
    }
    if (node.unresolved) { add('SG014', 'The declared reference has no matching component record in this input.'); continue; }
    const lookalike = node.local ? null : typo(node);
    if (lookalike) add(...lookalike);
    if (node.hasInstallScript || node.hooks.length) {
      const names = [...new Set(node.hooks.map(hook => hook.name))].sort(compare);
      add('SG003', names.length ? `Recorded lifecycle phases: ${names.join(', ')}. Script text was not executed.` :
        'The lockfile sets hasInstallScript; it does not supply the script body.');
      if (node.hooks.some(hook => download.test(hook.text))) add('SG004', 'A hook contains a downloader token followed by a pipe into an interpreter token.');
      if (node.hooks.some(hook => decode.test(hook.text))) add('SG005', 'A hook contains a decoding token. Its content was not decoded or executed.');
      if (node.hooks.some(hook => sensitive.test(hook.text) && egress.test(hook.text))) {
        add('SG006', 'Credential-related and egress-related text occur in the same hook. No data flow was verified.');
      }
    }
    const host = sourceHost(node.resolved);
    if (model.format === 'npm' && !node.local && !node.bundled && !hasSHA512(node.integrity)) {
      add('SG007', 'No syntactically valid SHA-512 SRI digest is recorded. No artifact bytes were verified.');
    }
    if ((model.format === 'npm' && !node.local && node.resolved && host !== 'registry.npmjs.org') ||
        (model.format === 'cargo' && node.resolved && !['github.com', 'index.crates.io'].includes(host)) ||
        (model.format === 'cargo' && host === 'github.com' && node.resolved !== 'registry+https://github.com/rust-lang/crates.io-index') ||
        (model.format === 'cargo' && host === 'index.crates.io' && node.resolved !== 'sparse+https://index.crates.io/')) {
      add('SG008', `The recorded source is outside the default registry${host ? ` (${host})` : ''}.`);
    }
    if (model.format === 'cargo' && /^(?:registry|sparse)\+/.test(node.resolved) && !node.hashes.length) {
      add('SG015', 'A registry package has no recorded SHA-256 checksum.');
    }
    if (model.format === 'pypi' && node.resolved) add('SG016', 'The requirement names a direct reference instead of a package release.');
    const unpinned = (declared.get(node.id) ?? []).filter(edge => !isPinned(edge, node) && (
      (model.format === 'npm' && edge.spec && !/^(?:file:|workspace:|link:)/.test(edge.spec)) ||
      (model.format === 'pypi' && !node.resolved)
    ));
    if (unpinned.length) add('SG009', `${unpinned.length} incoming ${unpinned.length === 1 ? 'declaration is' : 'declarations are'} not an exact version pin.`);
    const list = versions.get(`${node.ecosystem}:${canonicalName(node.name, node.ecosystem)}`);
    if (list?.size > 1 && !node.marker) add('SG010', `This inventory records ${list.size} distinct versions of this package name.`);
    if (node.expectedHost && host !== node.expectedHost) {
      add('SG013', `The comparison policy expects ${node.expectedHost}; this record has ${host || 'no recognized HTTPS registry host'}.`);
    }
    if (node.expectedIntegrity) {
      const expected = sriHashes(node.expectedIntegrity);
      const recorded = sriHashes(node.integrity);
      const comparable = expected.filter(hash => recorded.some(item => item.alg === hash.alg));
      if (comparable.length && !comparable.some(hash => recorded.some(item => item.alg === hash.alg && item.content === hash.content))) {
        add('SG012', 'Recorded and expected digests for a common algorithm differ. No artifact bytes were verified.');
      }
    }
    if (node.minimumVersion && belowVersion(node.version, node.minimumVersion)) {
      add('SG017', `The resolved version ${node.version} precedes the comparison minimum ${node.minimumVersion}.`);
    }
  }
  findings.sort((a, b) => b.points - a.points || b.weight - a.weight || compare(a.nodeId, b.nodeId) || compare(a.ruleId, b.ruleId));
  const contributions = findings.filter(finding => finding.points > 0)
    .map(({ ruleId, nodeId, points }) => ({ ruleId, nodeId, points }));
  const score = Math.min(100, contributions.reduce((sum, item) => sum + item.points, 0));
  return { score, findings, paths, depths, contributions, model, metrics: {
    nodes: active.length - 1, edges: edges.length, flagged: flagged.size, affected: affectedUnion.size,
    reachable: [...depths.keys()].filter(id => id !== model.rootId && !byId.get(id).unresolved).length,
    maxDepth: Math.max(0, ...depths.values()),
  } };
}

export function simulate(original, changes) {
  const byId = new Map(original.nodes.map(node => [node.id, node]));
  const pins = new Map();
  const nodes = new Map();
  for (const [id, change] of changes) {
    const node = byId.get(id);
    if (!node || node.root || !['pin', 'upgrade', 'quarantine'].includes(change?.action)) throw new Error('Invalid remediation target or action.');
    if (change.action === 'quarantine') { nodes.set(id, { ...node, quarantined: true }); continue; }
    if (node.unresolved) throw new Error('An unresolved reference cannot be pinned or upgraded.');
    if (change.action === 'pin' && !['npm', 'pypi'].includes(original.format)) {
      throw new Error('This input does not expose editable version declarations.');
    }
    const version = change.action === 'pin' ? node.version : change.version?.trim();
    const supported = node.ecosystem === 'pypi' ? /^[A-Za-z0-9][A-Za-z0-9.!+_-]{0,199}$/ : semver;
    if (!version || version.length > 200 || !supported.test(version)) throw new Error('Enter a concrete version from a verified source.');
    if (change.action === 'upgrade') {
      if (node.ecosystem !== 'npm') throw new Error('Candidate artifact upgrades are supported for npm. Use quarantine for other inventories.');
      if (version === node.version) throw new Error('Enter a different candidate version.');
      const integrity = change.integrity?.trim() ?? '';
      if (integrity && !hasSHA512(integrity)) throw new Error('Enter a valid SHA-512 SRI digest or leave it empty.');
      nodes.set(id, { ...node, version, integrity, hasInstallScript: false, hooks: [], expectedIntegrity: '',
        hashes: [], simulatedArtifact: true });
    }
    pins.set(id, node.ecosystem === 'pypi' ? `==${version}` : version);
  }
  return {
    ...original,
    nodes: original.nodes.map(node => nodes.get(node.id) ?? node),
    edges: original.edges.map(edge => {
      if (!pins.has(edge.to) || (original.format === 'npm' && (!edge.spec || /^(?:file:|workspace:|link:)/.test(edge.spec)))) return edge;
      const alias = /^npm:(?:@[^/]+\/)?[^@]+@/.exec(edge.spec)?.[0] ?? '';
      return { ...edge, spec: alias + pins.get(edge.to) };
    }),
    notes: [
      ...original.notes,
      ...(changes.size ? ['Counterfactual only. No manifest, resolver, package, or artifact was changed.'] : []),
      ...([...nodes.values()].some(node => node.simulatedArtifact) ?
        ['Candidate versions lack verified hook and dependency metadata. Cleared rules reflect missing evidence, not safety. Prior topology and source are retained for comparison.'] : []),
    ],
  };
}
