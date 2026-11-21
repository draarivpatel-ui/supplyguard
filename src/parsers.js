import { compare, inferredEntries } from './graph.js';

export const MAX_BYTES = 2 * 1024 * 1024;
const MAX_NODES = 3000;
const MAX_EDGES = 18000;
const RESERVED = new Set(['__proto__', 'constructor', 'prototype']);
const bad = message => { throw new Error(message); };
const own = (object, key) => Object.hasOwn(object, key);
const sorted = object => Object.keys(object).sort(compare);

export function strictJson(text) {
  let i = 0;
  const whitespace = /[\x20\t\r\n]*/y;
  const string = /"(?:[^"\\\x00-\x1f]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*"/y;
  const literal = /(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/y;
  function take(regex) {
    regex.lastIndex = i;
    const match = regex.exec(text);
    if (match) i = regex.lastIndex;
    return match?.[0];
  }
  function value(depth) {
    if (depth > 70) bad('JSON nesting exceeds the limit.');
    take(whitespace);
    if (text[i] === '{' || text[i] === '[') {
      const record = text[i++] === '{';
      const close = record ? '}' : ']';
      const result = record ? Object.create(null) : [];
      take(whitespace);
      if (text[i] === close) { i++; return result; }
      for (;;) {
        if (record) {
          const raw = take(string);
          if (!raw) bad(`Expected a JSON key at offset ${i}.`);
          const key = JSON.parse(raw);
          if (RESERVED.has(key)) bad('Reserved key in JSON input.');
          if (own(result, key)) bad('Duplicate key in JSON input.');
          take(whitespace);
          if (text[i++] !== ':') bad('Expected a colon after a JSON key.');
          result[key] = value(depth + 1);
        } else result.push(value(depth + 1));
        take(whitespace);
        if (text[i] === close) { i++; return result; }
        if (text[i++] !== ',') bad('Expected a comma or the end of a JSON collection.');
        take(whitespace);
      }
    }
    const token = take(string) ?? take(literal);
    if (token === undefined) bad(`Malformed JSON at offset ${i}.`);
    const result = JSON.parse(token);
    if (typeof result === 'number' && !Number.isFinite(result)) bad('Non-finite JSON number.');
    return result;
  }
  const result = value(0);
  take(whitespace);
  if (i !== text.length) bad('Unexpected data after JSON value.');
  return result;
}

function object(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) bad(`${label} must be an object.`);
  return value;
}
function array(value, label) {
  if (!Array.isArray(value)) bad(`${label} must be an array.`);
  return value;
}
const items = (value, label) => value === undefined ? [] : array(value, label);
function string(value, label, max = 4096) {
  if (typeof value !== 'string' || !value.trim() || value.length > max || !value.isWellFormed() || /[\u0000-\u001f\u007f]/u.test(value)) {
    bad(`Invalid text in ${label}.`);
  }
  return value;
}
const optional = (value, label, max) => value === undefined ? '' : string(value, label, max);
const fields = (value, label) => value === undefined ? Object.create(null) : object(value, label);

function packageName(value, label) {
  const name = string(value, label, 150);
  if (!/^(?:@[\p{L}\p{N}\p{M}._~-]+\/)?[\p{L}\p{N}\p{M}._~-]+$/u.test(name) ||
      name.split('/').some(part => part === '.' || part === '..' || RESERVED.has(part.replace(/^@/, '')))) {
    bad(`Invalid package name in ${label}.`);
  }
  return name;
}

function modelBuilder(format, source, rootName, rootVersion = '') {
  const model = { format, source, rootId: 'root', nodes: [], edges: [], notes: [], sourceKind: 'input' };
  const byId = new Map();
  const edgeKeys = new Set();
  const missingIds = new Map();
  function node(id, details) {
    if (model.nodes.length >= MAX_NODES) bad(`Component limit exceeded (${MAX_NODES}).`);
    if (byId.has(id)) bad('Duplicate component identity.');
    const item = {
      id, name: '', version: '', ecosystem: '', location: '', resolved: '', integrity: '', hashes: [], hooks: [],
      ...details,
    };
    byId.set(id, item);
    model.nodes.push(item);
    return item;
  }
  function edge(from, to, name, spec = '', kind = 'dependency') {
    const key = JSON.stringify([from, to, name, spec, kind]);
    if (edgeKeys.has(key)) return;
    if (model.edges.length >= MAX_EDGES) bad(`Dependency edge limit exceeded (${MAX_EDGES}).`);
    edgeKeys.add(key);
    model.edges.push({ from, to, name, spec, kind });
  }
  function unresolved(from, name, spec, ecosystem, location, kind) {
    const key = JSON.stringify([ecosystem, name, spec]);
    if (!missingIds.has(key)) {
      const id = `missing:${missingIds.size}`;
      missingIds.set(key, id);
      node(id, { name, ecosystem, location, unresolved: true });
    }
    const id = missingIds.get(key);
    edge(from, id, name, spec, kind);
  }
  function infer() {
    const entries = inferredEntries(model.nodes.filter(item => item.id !== model.rootId), model.edges);
    for (const id of entries) if (!byId.get(id).unresolved) edge(model.rootId, id, byId.get(id).name, '', 'inferred');
    if (entries.length) model.notes.push('Root edges are inferred from source components. Paths include the virtual root.');
  }
  node(model.rootId, { name: rootName, version: rootVersion, location: source, root: true });
  return { model, node, edge, unresolved, byId, infer };
}

function parseNpm(doc, source) {
  if (![2, 3].includes(doc.lockfileVersion)) bad('Only npm package-lock versions 2 and 3 are supported.');
  const packages = object(doc.packages, 'npm packages');
  const root = object(packages[''], 'npm root record');
  const rootName = optional(root.name === undefined ? doc.name : root.name, 'root name', 150) || 'npm project';
  const builder = modelBuilder('npm', source, rootName, optional(root.version === undefined ? doc.version : root.version, 'root version', 200));
  const { model, node, edge, unresolved } = builder;
  model.lockfileVersion = doc.lockfileVersion;
  model.bySpec = true;
  model.notes.push('npm lockfiles normally expose only a lifecycle flag, not hook bodies or artifact bytes.');
  const records = new Map();
  const links = new Map();
  for (const path of sorted(packages)) {
    const record = object(packages[path], 'npm package record');
    if (path && (path.length > 1024 || /[\\:\u0000-\u0020\u007f]/u.test(path) ||
        path.split('/').some(part => !part || ['.', '..'].includes(part) || RESERVED.has(part)))) {
      bad('Invalid npm installation path.');
    }
    for (const flag of ['link', 'hasInstallScript', 'inBundle']) {
      if (record[flag] !== undefined && typeof record[flag] !== 'boolean') bad(`Invalid npm ${flag} flag.`);
    }
    const resolved = optional(record.resolved, 'npm resolved');
    if (record.link) {
      if (!path || !resolved || !own(packages, resolved) || resolved === path) bad('Invalid npm workspace link.');
      links.set(path, resolved);
      continue;
    }
    records.set(path, record);
    if (!path) continue;
    const segments = path.split('/');
    const lastModules = segments.lastIndexOf('node_modules');
    const installed = packageName(lastModules < 0 ? segments.at(-1) : segments.slice(lastModules + 1).join('/'), 'npm installation path');
    const name = record.name === undefined ? installed : packageName(record.name, 'npm package');
    node(`npm:${path}`, {
      name,
      version: optional(record.version, 'npm version', 200), ecosystem: 'npm',
      location: `packages[${JSON.stringify(path)}]`, resolved, integrity: optional(record.integrity, 'npm integrity'),
      hasInstallScript: record.hasInstallScript === true, bundled: record.inBundle === true,
      local: lastModules < 0,
    });
  }
  for (const target of links.values()) if (!records.has(target) || !target) bad('Unsupported npm workspace link target.');
  function lookup(path, name) {
    let scope = path ? path.split('/') : [];
    while (true) {
      const candidate = [...scope, 'node_modules', name].join('/');
      if (links.has(candidate)) return `npm:${links.get(candidate)}`;
      if (records.has(candidate)) return `npm:${candidate}`;
      if (!scope.length) return null;
      const modules = scope.lastIndexOf('node_modules');
      scope = scope.slice(0, modules < 0 ? -1 : modules);
    }
  }
  let missingOptional = 0;
  for (const [path, record] of records) {
    const from = path ? `npm:${path}` : model.rootId;
    const depMaps = ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']
      .map(kind => [kind, fields(record[kind], kind)]);
    const peerMeta = fields(record.peerDependenciesMeta, 'peer metadata');
    for (const [kind, deps] of depMaps) {
      for (const name of sorted(deps)) {
        packageName(name, kind);
        const spec = string(deps[name], 'npm dependency specification');
        if (kind === 'dependencies' && own(depMaps[3][1], name)) continue;
        const meta = peerMeta[name];
        if (meta !== undefined) object(meta, 'peer metadata entry');
        if (meta?.optional !== undefined && typeof meta.optional !== 'boolean') bad('Invalid optional peer flag.');
        const to = lookup(path, name);
        if (to) edge(from, to, name, spec, kind);
        else if (kind === 'optionalDependencies' || (kind === 'peerDependencies' && meta?.optional)) missingOptional++;
        else unresolved(from, name, spec, 'npm', `packages[${JSON.stringify(path)}]`, kind);
      }
    }
  }
  const rootTargets = new Set(model.edges.filter(item => item.from === model.rootId).map(item => item.to));
  for (const target of new Set(links.values())) {
    if (!rootTargets.has(`npm:${target}`)) edge(model.rootId, `npm:${target}`, builder.byId.get(`npm:${target}`).name, '', 'workspace');
  }
  if (missingOptional) model.notes.push(`${missingOptional} optional references have no installed component.`);
  return model;
}

const PEP_VERSION = /^(?:v)?(?:\d+!)?\d+(?:\.\d+)*(?:[-_.]?(?:a|b|c|rc|alpha|beta|pre|preview)[-_.]?\d*)?(?:(?:-\d+)|(?:[-_.]?(?:post|rev|r)[-_.]?\d*))?(?:[-_.]?dev[-_.]?\d*)?(?:\+[a-z0-9]+(?:[-_.][a-z0-9]+)*)?$/i;
const MARKER_KEYS = new Set('python_version python_full_version os_name sys_platform platform_release platform_system platform_version platform_machine platform_python_implementation implementation_name implementation_version extra'.split(' '));

function markerSyntax(text) {
  const re = /\s*(?:"[^"\\\r\n]*"|'[^'\\\r\n]*'|not\s+in\b|===|~=|==|!=|<=|>=|[<>()]|[a-z_]+)\s*/gy;
  const tokens = [];
  let offset = 0;
  while (offset < text.length) {
    const match = re.exec(text);
    if (!match) return false;
    tokens.push(match[0].trim());
    offset = re.lastIndex;
  }
  let i = 0;
  const operand = token => token && (MARKER_KEYS.has(token) || /^['"]/.test(token));
  function expression(depth) {
    if (depth > 24) return false;
    do {
      if (tokens[i] === '(') {
        i++;
        if (!expression(depth + 1) || tokens[i++] !== ')') return false;
      } else if (!operand(tokens[i++]) || !/^(?:===|~=|==|!=|<=|>=|[<>]|in|not\s+in)$/.test(tokens[i++] ?? '') ||
                 !operand(tokens[i++])) return false;
      if (!['and', 'or'].includes(tokens[i])) break;
      i++;
    } while (true);
    return true;
  }
  return tokens.length > 0 && expression(0) && i === tokens.length;
}

function parseRequirements(text, source) {
  const { model, node, edge } = modelBuilder('pypi', source, 'Python requirements');
  model.notes.push('Requirements lists show declared entries only. Transitive edges and marker environments are not inferred.');
  const lines = text.split(/\r?\n/);
  const pending = [];
  let start = 1;
  for (let i = 0; i < lines.length; i++) {
    if (!pending.length) start = i + 1;
    const strip = lines[i].replace(/(^|\s+)#.*$/, '').trim();
    const continuation = strip.endsWith('\\');
    pending.push(continuation ? strip.slice(0, -1) : strip);
    if (continuation) {
      if (i === lines.length - 1 || (i === lines.length - 2 && !lines[i + 1])) bad('Dangling requirements continuation.');
      continue;
    }
    const line = pending.join(' ').trim();
    pending.length = 0;
    if (!line) continue;
    string(line.replaceAll('\t', ' '), `requirements line ${start}`, 8192);
    const parts = /^(?<name>[\p{L}\p{N}][\p{L}\p{N}\p{M}._-]*)(?:\s*\[(?<extras>[a-z0-9._-]+(?:\s*,\s*[a-z0-9._-]+)*)\])?(?<rest>.*)$/iu.exec(line)?.groups;
    if (!parts) bad(`Unsupported requirements directive or entry on line ${start}.`);
    const name = packageName(parts.name, `requirements line ${start}`);
    const fields = parts.rest.trim().split(/\s+(?=--)/);
    const raw = fields.shift() ?? '';
    const hashes = fields.map(option => {
      const match = /^--hash=sha(256|384|512):([a-fA-F0-9]+)$/.exec(option.trim());
      if (!match || match[2].length !== Number(match[1]) / 4) bad(`Invalid requirements option or hash on line ${start}.`);
      return { alg: `SHA-${match[1]}`, content: match[2].toLowerCase() };
    });
    // Direct URLs can contain semicolons; their marker separator requires whitespace.
    const separator = raw.startsWith('@') ? raw.search(/\s+;/) : raw.indexOf(';');
    let spec = (separator < 0 ? raw : raw.slice(0, separator)).trim();
    const marker = separator < 0 ? '' : raw.slice(raw.indexOf(';', separator) + 1).trim();
    if (separator >= 0 && !markerSyntax(marker)) bad(`Invalid environment marker on line ${start}.`);
    let version = '';
    let resolved = '';
    if (spec.startsWith('@')) {
      resolved = spec.slice(1).trim();
      if (!/^(?:https?|git\+https?|file):[^\s]+$/i.test(resolved)) bad(`Unsupported direct reference on line ${start}.`);
      try { new URL(resolved); } catch { bad(`Invalid direct reference on line ${start}.`); }
    } else if (spec) {
      if (spec.startsWith('(') && spec.endsWith(')')) spec = spec.slice(1, -1).trim();
      const clauses = spec.split(',').map(item => /^(===|==|!=|~=|<=|>=|<|>)\s*(\S+)$/.exec(item.trim()));
      if (clauses.some(clause => !clause || !(PEP_VERSION.test(clause[2]) ||
          (['==', '!='].includes(clause[1]) && /^\d+(?:\.\d+)*\.\*$/.test(clause[2])) ||
          (clause[1] === '===' && /^[A-Za-z0-9._+-]+$/.test(clause[2]))))) bad(`Invalid version specifier on line ${start}.`);
      if (clauses.length === 1 && ['==', '==='].includes(clauses[0][1]) && !clauses[0][2].endsWith('.*')) {
        version = clauses[0][2];
      }
    }
    const id = `pypi:${start}`;
    node(id, { name, version, ecosystem: 'pypi', location: `line ${start}`, line: start, resolved, hashes, marker });
    edge(model.rootId, id, name, spec, 'declared');
  }
  return model;
}

// Cargo.lock uses a small TOML subset. Reject constructs outside it rather than guessing.
function cargoString(token) {
  if (token[0] === "'") return token.slice(1, -1);
  const decoded = token.slice(1, -1).replace(/\\(?:["\\btnfr]|u[0-9a-fA-F]{4}|U[0-9a-fA-F]{8})/g, escape => {
    if (escape[1] === 'u' || escape[1] === 'U') {
      const code = Number.parseInt(escape.slice(2), 16);
      if (code > 0x10ffff || (code >= 0xd800 && code <= 0xdfff)) bad('Invalid TOML code point.');
      return String.fromCodePoint(code);
    }
    return { '"': '"', '\\': '\\', b: '\b', t: '\t', n: '\n', f: '\f', r: '\r' }[escape[1]];
  });
  return decoded;
}

function cargoTokens(text) {
  const re = /[ \t]+|#[^\r\n]*|\r?\n|"(?:[^"\\\x00-\x08\x0a-\x1f\x7f]|\\(?:["\\btnfr]|u[0-9a-fA-F]{4}|U[0-9a-fA-F]{8}))*"|'[^'\x00-\x08\x0a-\x1f\x7f]*'|[A-Za-z0-9_-]+|\[\[|\]\]|[\[\]=,]/gy;
  const tokens = [];
  let offset = 0;
  while (offset < text.length) {
    const match = re.exec(text);
    if (!match) bad(`Invalid or unsupported Cargo TOML at offset ${offset}.`);
    const token = match[0];
    if (token[0] === '\n' || token[0] === '\r') tokens.push('\n');
    else if (!/^[ \t#]/.test(token)) tokens.push(token);
    offset = re.lastIndex;
  }
  return tokens;
}

function parseCargo(text, source) {
  const tokens = cargoTokens(text);
  let i = 0;
  const top = Object.create(null);
  const packages = [];
  let table = top;
  let metadata;
  const key = token => {
    if (!token || !/^(?:[A-Za-z0-9_-]+|['"])/.test(token)) bad('Expected Cargo TOML key.');
    const result = /^['"]/.test(token) ? cargoString(token) : token;
    if (RESERVED.has(result)) bad('Reserved key in Cargo input.');
    return result;
  };
  const quoted = token => {
    if (!token || !/^['"]/.test(token)) bad('Expected quoted Cargo TOML string.');
    return cargoString(token);
  };
  function expect(token) {
    if (tokens[i++] !== token) bad('Unexpected token in Cargo TOML.');
  }
  function newlines() { while (tokens[i] === '\n') i++; }
  while (i < tokens.length) {
    newlines();
    if (i === tokens.length) break;
    if (tokens[i] === '[[') {
      i++;
      expect('package');
      expect(']]');
      if (packages.length >= MAX_NODES - 1) bad('Cargo component limit exceeded.');
      table = Object.create(null);
      packages.push(table);
    } else if (tokens[i] === '[') {
      i++;
      expect('metadata');
      expect(']');
      if (metadata) bad('Duplicate Cargo metadata table.');
      metadata = table = Object.create(null);
    } else {
      const name = key(tokens[i++]);
      if (own(table, name)) bad('Duplicate Cargo TOML key.');
      expect('=');
      if (table === top && name === 'version' && /^(?:[1-4])$/.test(tokens[i] ?? '')) table[name] = Number(tokens[i++]);
      else if (tokens[i] === '[' && table !== top && table !== metadata && name === 'dependencies') {
        i++;
        newlines();
        const list = [];
        while (tokens[i] !== ']') {
          list.push(quoted(tokens[i++]));
          newlines();
          if (tokens[i] === ']') break;
          expect(',');
          newlines();
        }
        expect(']');
        table[name] = list;
      } else if (table === metadata ||
          (table !== top && ['name', 'version', 'source', 'checksum'].includes(name))) table[name] = quoted(tokens[i++]);
      else bad('Unsupported Cargo.lock field.');
    }
    if (i < tokens.length) expect('\n');
  }
  if (!packages.length) bad('Cargo.lock contains no package records.');
  const { model, node, edge, infer, unresolved } = modelBuilder('cargo', source, 'Cargo workspace');
  model.lockfileVersion = top.version ?? 1;
  const byName = new Map();
  const identities = new Set();
  for (let j = 0; j < packages.length; j++) {
    const record = packages[j];
    const name = packageName(record.name, 'Cargo package');
    const version = string(record.version, 'Cargo package version', 200);
    if (!/^\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?(?:\+[A-Za-z0-9.-]+)?$/.test(version)) bad('Invalid Cargo package version.');
    const resolved = optional(record.source, 'Cargo source');
    const checksum = record.checksum ?? metadata?.[`checksum ${name} ${version} (${resolved})`];
    if (checksum !== undefined && checksum !== '<none>' && !/^[a-fA-F0-9]{64}$/.test(checksum)) bad('Invalid Cargo checksum.');
    const identity = JSON.stringify([name, version, resolved]);
    if (identities.has(identity)) bad('Duplicate Cargo package identity.');
    identities.add(identity);
    const id = `cargo:${j + 1}`;
    const item = node(id, { name, version, ecosystem: 'cargo', location: `package record ${j + 1}`, resolved, local: !resolved,
      hashes: checksum && checksum !== '<none>' ? [{ alg: 'SHA-256', content: checksum.toLowerCase() }] : [] });
    if (!byName.has(name)) byName.set(name, []);
    byName.get(name).push(item);
    record.id = id;
  }
  for (const record of packages) {
    for (const entry of record.dependencies ?? []) {
      const match = /^([\p{L}\p{N}\p{M}._~-]+)(?: ([^\s()]+)(?: \(([^()\s]+)\))?)?$/u.exec(entry);
      if (!match) bad('Invalid Cargo dependency reference.');
      const [, name, version, resolved] = match;
      packageName(name, 'Cargo dependency');
      const candidates = (byName.get(name) ?? []).filter(item => (!version || item.version === version) &&
        (!resolved || item.resolved === resolved));
      if (candidates.length > 1) bad('Ambiguous Cargo dependency reference.');
      if (candidates.length === 1) edge(record.id, candidates[0].id, name, version, 'dependency');
      else unresolved(record.id, name, entry, 'cargo', 'Cargo.lock dependency', 'dependency');
    }
  }
  infer();
  return model;
}

const HASH_LENGTH = new Map([
  ['MD5', 32], ['SHA-1', 40], ['SHA-256', 64], ['SHA-384', 96], ['SHA-512', 128],
  ['SHA3-256', 64], ['SHA3-384', 96], ['SHA3-512', 128], ['BLAKE2b-256', 64],
  ['BLAKE2b-384', 96], ['BLAKE2b-512', 128], ['BLAKE3', 64],
]);

function parseCyclone(doc, source) {
  if (doc.bomFormat !== 'CycloneDX' || doc.specVersion !== '1.5') bad('Only CycloneDX 1.5 JSON is supported.');
  if (!Number.isSafeInteger(doc.version) || doc.version < 1) bad('Invalid CycloneDX document version.');
  const metadata = fields(doc.metadata, 'CycloneDX metadata');
  const root = metadata.component === undefined ? null : object(metadata.component, 'CycloneDX root component');
  const { model, node, edge, infer, byId, unresolved } = modelBuilder('cyclonedx', source,
    root ? string(root.name, 'CycloneDX root name', 250) : 'SBOM inventory', optional(root?.version, 'CycloneDX root version', 200));
  const refs = new Map();
  const links = [];
  let count = 0;
  const types = new Set(['application', 'framework', 'library', 'container', 'platform', 'operating-system', 'device',
    'device-driver', 'firmware', 'file', 'machine-learning-model', 'data']);
  function component(value, parent, isRoot = false) {
    const record = object(value, 'CycloneDX component');
    const name = string(record.name, 'CycloneDX component name', 250);
    if (!types.has(record.type)) bad('Invalid CycloneDX component type.');
    const ref = optional(record['bom-ref'], 'CycloneDX bom-ref', 1024);
    const purl = optional(record.purl, 'CycloneDX purl');
    if (ref && refs.has(ref)) bad('Duplicate CycloneDX bom-ref.');
    const ecosystem = /^pkg:(npm|pypi|cargo)\//.exec(purl)?.[1] ?? '';
    const hashes = items(record.hashes, 'CycloneDX hashes').map(item => {
      object(item, 'CycloneDX hash');
      if (!HASH_LENGTH.has(item.alg) || typeof item.content !== 'string' ||
          item.content.length !== HASH_LENGTH.get(item.alg) || !/^[a-fA-F0-9]+$/.test(item.content)) {
        bad('Invalid CycloneDX hash.');
      }
      return { alg: item.alg, content: item.content.toLowerCase() };
    });
    const id = isRoot ? model.rootId : ref ? `sbom:${ref}` : `sbom-inventory:${++count}`;
    const group = optional(record.group, 'CycloneDX component group', 200);
    const details = {
      name: ecosystem === 'npm' && group.startsWith('@') && !name.startsWith('@') ? `${group}/${name}` : name,
      version: optional(record.version, 'CycloneDX component version', 200), ecosystem,
      location: ref ? `bom-ref ${ref}` : 'CycloneDX component', purl, hashes, componentType: record.type,
    };
    if (isRoot) Object.assign(byId.get(id), details);
    else node(id, details);
    if (ref) refs.set(ref, id);
    if (parent) links.push([parent, id]);
    for (const nested of items(record.components, 'CycloneDX nested components')) component(nested, id);
  }
  if (root) component(root, null, true);
  for (const value of items(doc.components, 'CycloneDX components')) component(value, null);
  const rows = new Set();
  for (const value of items(doc.dependencies, 'CycloneDX dependencies')) {
    const row = object(value, 'CycloneDX dependency');
    const ref = string(row.ref, 'CycloneDX dependency ref', 1024);
    if (!refs.has(ref) || rows.has(ref)) bad('Unknown or duplicate CycloneDX dependency record.');
    rows.add(ref);
    for (const target of items(row.dependsOn, 'CycloneDX dependsOn')) {
      string(target, 'CycloneDX dependency target', 1024);
      if (refs.has(target)) edge(refs.get(ref), refs.get(target), byId.get(refs.get(target)).name);
      else unresolved(refs.get(ref), target, 'bom-ref', '', `bom-ref ${ref}`, 'dependency');
    }
  }
  if (!root || !root['bom-ref']) infer();
  if (links.length) model.notes.push('Nested SBOM components describe containment, not dependency edges.');
  if (!rows.size) model.notes.push('This SBOM provides no explicit dependency rows.');
  if (doc.services !== undefined) model.notes.push('CycloneDX services are not supported as dependency components.');
  return model;
}

export function parseInput(text, filename = '') {
  if (typeof text !== 'string' || text.length > MAX_BYTES || new TextEncoder().encode(text).length > MAX_BYTES) {
    bad('Input exceeds the 2 MiB limit or is not text.');
  }
  const data = text.replace(/^\uFEFF/, '');
  const source = filename ? string(string(filename, 'file name', 1024).split(/[\\/]/).at(-1), 'file name', 250) : 'Imported file';
  const lower = source.toLowerCase();
  if (lower === 'cargo.lock') return parseCargo(data, source);
  if (lower.endsWith('.txt')) return parseRequirements(data, source);
  if (lower.endsWith('.json') || data.trimStart().startsWith('{')) {
    const doc = object(strictJson(data), 'JSON file');
    if (own(doc, 'bomFormat')) return parseCyclone(doc, source);
    if (own(doc, 'lockfileVersion')) return parseNpm(doc, source);
    bad('Unrecognized JSON inventory. Use npm package-lock or CycloneDX 1.5 JSON.');
  }
  bad('Unrecognized file. Use package-lock.json, requirements.txt, Cargo.lock, or a CycloneDX JSON SBOM.');
}
