import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import test from 'node:test';
import { parseInput, strictJson, MAX_BYTES } from '../src/parsers.js';
import { breadthFirst, inferredEntries, indexGraph, trace } from '../src/graph.js';
import { analyze, damerauLevenshtein, keyboardAdjacent, simulate, skeleton, sourceHost, sriHashes } from '../src/detectors.js';
import { canonicalJson, csvCell, makeExport, sha256 } from '../src/exports.js';
import { loadPreset } from '../src/presets.js';

const npm = (packages, version = 3) => JSON.stringify({ lockfileVersion: version, packages: { '': {}, ...packages } });
const lock = (text, name = 'package-lock.json') => parseInput(text, name);
const py = text => parseInput(text, 'requirements.txt');
const cargo = text => parseInput(text, 'Cargo.lock');
const cdx = (components, dependencies, metadata) => JSON.stringify({
  bomFormat: 'CycloneDX', specVersion: '1.5', version: 1, metadata, components, dependencies,
});
const sbom = text => parseInput(text, 'sbom.json');
const component = (name, attrs = {}) => ({ name, type: 'library', 'bom-ref': name, ...attrs });
const sri = (byte = 1, size = 64, algorithm = 'sha512') => `${algorithm}-${Buffer.alloc(size, byte).toString('base64')}`;
const scores = { lifecycle: 72, lookalikes: 59, scope: 89, baseline: 0 };

for (const [label, text] of [
  ['duplicate', '{"a":1,"a":2}'], ['escaped duplicate', '{"a":1,"\\u0061":2}'],
  ['prototype', '{"__proto__":{}}'], ['nested constructor', '{"list":[{"constructor":1}]}'],
  ['escaped prototype', '{"\\u005f_proto__":0}'], ['prototype member', '{"prototype":{}}'],
  ['trailing object comma', '{"a":1,}'], ['trailing array comma', '[true,]'], ['double comma', '[1,,2]'],
  ['unquoted key', '{x:1}'], ['missing colon', '{"x" 1}'], ['missing comma', '{"a":1 "b":2}'],
  ['trailing data', '{}true'], ['octal number', '012'], ['overflow', '1e400'], ['floating dot', '1.'],
  ['non-JSON whitespace', '\u00a0[]'], ['raw control', '"a\nb"'], ['bad escape', '"\\q"'], ['bad unicode', '"\\u00xx"'],
  ['deep arrays', '['.repeat(72) + '0' + ']'.repeat(72)], ['unfinished array', '['],
]) test(`strict JSON rejects ${label}`, () => assert.throws(() => strictJson(text)));

for (const [label, text, expected] of [
  ['record', '{"a":{"b":0}}', '{"a":{"b":0}}'],
  ['mixed array', '[null,false,-1.25e+2,"a b",{}]', '[null,false,-125,"a b",{}]'],
  ['escaped keys and quotes', '{"foo\\"bar":"\\u0061"}', '{"foo\\"bar":"a"}'],
  ['prototype-like name as a value', '{"field":"__proto__"}', '{"field":"__proto__"}'],
  ['scalar with JSON whitespace', '\r\n\t -1.25 \t', '-1.25'],
]) test(`strict JSON accepts ${label}`, () => assert.equal(JSON.stringify(strictJson(text)), expected));

for (const [label, packages, version] of [
  ['v1', {}, 1], ['v4', {}, 4], ['string version', {}, '3'], ['absent root', { '': undefined }, 3],
  ['null root name', { '': { name: null } }, 3], ['invalid record', { 'node_modules/x': [] }, 3],
  ['null dependencies', { '': { dependencies: null } }, 3], ['non-string specification', { '': { dependencies: { x: 1 } } }, 3],
  ['invalid package path segments', { 'lib/../foo': {} }, 3], ['invalid version type', { 'node_modules/x': { version: 1 } }, 3],
  ['invalid flag', { 'node_modules/x': { hasInstallScript: 'true' } }, 3],
  ['link to absent record', { 'node_modules/x': { link: true, resolved: 'packages/x' } }, 3],
  ['chained link', { 'node_modules/x': { link: true, resolved: 'packages/x' },
    'packages/x': { link: true, resolved: 'node_modules/x' } }, 3],
]) test(`npm rejects ${label}`, () => assert.throws(() => lock(npm(packages, version))));

test('npm validates both supported versions and accepts a leading file BOM', () => {
  assert.equal(lock(`\uFEFF${npm({}, 2)}`).lockfileVersion, 2);
  assert.equal(lock(npm({})).lockfileVersion, 3);
});
test('npm nested, hoisted and scoped packages resolve by placement', () => {
  const parsed = lock(npm({
    '': { dependencies: { '@local/one': '1.0.0' } },
    'node_modules/@local/one': { version: '1.0.0', dependencies: { local: '1.0.0', hoisted: '1.0.0' } },
    'node_modules/@local/one/node_modules/local': { version: '1.0.0', dependencies: { sibling: '1.0.0' } },
    'node_modules/@local/one/node_modules/sibling': { version: '1.0.0' },
    'node_modules/local': { version: '2.0.0' },
    'node_modules/hoisted': { version: '1.0.0' },
  }));
  assert.deepEqual(analyze(parsed).paths.get('npm:node_modules/@local/one/node_modules/sibling'), [
    'root', 'npm:node_modules/@local/one', 'npm:node_modules/@local/one/node_modules/local',
    'npm:node_modules/@local/one/node_modules/sibling',
  ]);
  assert.equal(analyze(parsed).paths.has('npm:node_modules/local'), false);
  assert.equal(analyze(parsed).depths.get('npm:node_modules/hoisted'), 2);
});
test('npm workspace aliases resolve to the local package record', () => {
  const parsed = lock(npm({
    '': { dependencies: { project: 'file:packages/x' } },
    'node_modules/project': { link: true, resolved: 'packages/x' },
    'packages/x': { name: 'project', version: '1.0.0', dependencies: { subdep: '^1.0.0' } },
    'node_modules/subdep': { version: '1.0.0' },
  }));
  assert.equal(parsed.nodes.length, 3);
  assert.equal(parsed.edges[0].to, 'npm:packages/x');
  assert.equal(analyze(parsed).depths.get('npm:node_modules/subdep'), 2);
});
test('npm preserves a missing required package, not absent optional dependencies', () => {
  const parsed = lock(npm({ '': {
    dependencies: { required: '1.0.0', optional: '1.0.0' },
    optionalDependencies: { optional: '1.0.0' }, peerDependencies: { peer: '*' },
    peerDependenciesMeta: { peer: { optional: true } },
  } }));
  assert.deepEqual(parsed.nodes.filter(node => node.unresolved).map(node => node.name), ['required']);
  assert.match(parsed.notes.at(-1), /^2 optional/);
  assert.equal(analyze(parsed).metrics.reachable, 0);
});
test('npm retains a genuine self-cycle', () => {
  const parsed = lock(npm({ '': { dependencies: { loop: '1.0.0' } },
    'node_modules/loop': { version: '1.0.0', dependencies: { loop: '1.0.0' } } }));
  const result = analyze(parsed);
  assert.equal(result.metrics.edges, 2);
  assert.deepEqual(result.findings[0].affected, []);
});
test('npm reports metadata only, even when an unrecognized field carries script text', () => {
  const parsed = lock(npm({ '': { dependencies: { x: '1.0.0' } }, 'node_modules/x': { hasInstallScript: true,
    version: '1.0.0', integrity: sri(), scripts: { postinstall: 'INERT TEXT: <omitted>' } } }));
  assert.deepEqual(analyze(parsed).findings.map(finding => finding.ruleId), ['SG003']);
});
test('input rejects a boundary breach in UTF-8 bytes, not just UTF-16 units', () => {
  assert.throws(() => lock('\u00e9'.repeat(MAX_BYTES / 2 + 1)), /2 MiB/);
});
test('mislabeled and unknown documents are not treated as clean inputs', () => {
  assert.throws(() => lock('{}'), /Unrecognized/);
  assert.throws(() => parseInput('not a lockfile', 'x.lock'), /Unrecognized/);
  assert.throws(() => lock('null'), /object/);
});

for (const [label, text, version] of [
  ['exact release', 'numpy==2.1.0', '2.1.0'], ['extras', 'requests [http] == 2.32.3', '2.32.3'],
  ['epoch and local suffix', 'numpy==1!2.0+cpu.1', '1!2.0+cpu.1'],
  ['pre-release', 'pandas==2.2.0rc1', '2.2.0rc1'], ['post release', 'pip==24.0-2', '24.0-2'],
  ['compound range', 'urllib3 >= 2.0, < 3', ''], ['wildcard equality', 'scipy==1.16.*', ''],
  ['arbitrary exact release', 'numpy===foobar', 'foobar'],
  ['marker with boolean grouping', 'pandas==2.1; (python_version >= "3.10" and sys_platform == "darwin") or os_name != "nt"', '2.1'],
  ['quoted markers', "scipy==1.2 ; extra not in 'work'", '1.2'],
  ['bare declaration', 'urllib3', ''], ['boundary comment', 'urllib3==1.2 # test', '1.2'],
  ['direct URL', 'pandas @ https://artifact.example.invalid/wheel#fragment', ''],
  ['continued digest', `urllib3==1.2 \\\n  --hash=sha256:${'af'.repeat(32)}`, '1.2'],
]) test(`requirements accepts ${label}`, () => {
  const parsed = py(text);
  assert.equal(parsed.nodes.length, 2);
  assert.equal(parsed.nodes[1].version, version);
  assert.equal(parsed.nodes[1].line, 1);
});
for (const [label, text] of [
  ['include', '-r other.txt'], ['editable', '-e .'], ['option', '--extra-index-url=https://example.invalid/'],
  ['bad hash', 'x==1 --hash=sha256:fa'], ['unknown hash', `x==1 --hash=sha1:${'00'.repeat(20)}`],
  ['invalid version operator', 'x=>2.0'], ['invalid trailing comma', 'x>=2,'], ['invalid wildcard', 'x>=2.*'],
  ['invalid extra list', 'x[,fast]==1'], ['unknown marker variable', 'x==2; release == "new"'],
  ['incomplete marker', 'x==2; (python_version >= "3.11"'], ['missing marker expression', 'x==2;'],
  ['unsupported bare URL', 'https://example.invalid/wheel.whl'], ['unsupported URL protocol', 'x @ ftp://example.invalid/'],
  ['unterminated continuation', 'x==1 \\'], ['reserved name', 'constructor==1'],
]) test(`requirements rejects ${label}`, () => assert.throws(() => py(text)));

const crate = (name, value = '1.0.0', tail = '') => `[[package]]\nname = "${name}"\nversion = "${value}"${tail ? `\n${tail}` : ''}\n`;
for (const [label, text] of [
  ['broken quote', '[[package]]\nname = "abc\n'], ['broken array', `${crate('a')}dependencies = ["b",`],
  ['extra table', '[other]\nname="x"'], ['invalid version format', 'version=4.0\n' + crate('a')],
  ['duplicate field', `${crate('a')}name = "b"`], ['duplicate table declaration', crate('a') + crate('a')],
  ['duplicate metadata', `${crate('a')}[metadata]\n[metadata]\n`],
  ['reserved key', `${crate('a')}[metadata]\n"__proto__" = "x"\n`],
  ['escaped reserved key', `${crate('a')}[metadata]\n"\\u0063onstructor" = "x"\n`],
  ['missing name', '[[package]]\nversion="1.0.0"'], ['invalid checksum', crate('a', '1.0.0', 'checksum = "ab"')],
  ['invalid Unicode codepoint', '[[package]]\nname = "\\uD800"\nversion="1.0.0"'],
  ['broken table delimiters', '[ [ package ] ]\nname="a"\nversion="1.0.0"'],
  ['unseparated statements', '[[package]] name="a"\nversion="1.0.0"'],
  ['ambiguous dependency', crate('a', '1.0.0', 'dependencies = ["b"]') + crate('b') + crate('b', '2.0.0')],
]) test(`Cargo rejects ${label}`, () => assert.throws(() => cargo(text)));
test('Cargo supports multiline dependency arrays, literal strings, exact version disambiguation and inferred paths', () => {
  const parsed = cargo(`version = 4\n${crate('app', '1.0.0', `dependencies = [\n  'serde 2.0.0', # choice\n]`)}${crate('serde')}${crate('serde', '2.0.0')}`);
  assert.equal(parsed.lockfileVersion, 4);
  assert.equal(analyze(parsed).depths.get('cargo:3'), 2);
  assert.equal(analyze(parsed).depths.get('cargo:2'), 1);
});
test('Cargo reads a legacy metadata checksum', () => {
  const url = 'registry+https://github.com/rust-lang/crates.io-index';
  const hex = '1a'.repeat(32);
  const parsed = cargo(`${crate('serde', '1.0.0', `source = "${url}"`)}[metadata]\n"checksum serde 1.0.0 (${url})" = "${hex}"`);
  assert.deepEqual(parsed.nodes[1].hashes, [{ alg: 'SHA-256', content: hex }]);
});
test('Cargo infers both source nodes when the entire package graph is cyclic', () => {
  const parsed = cargo(crate('a', '1.0.0', 'dependencies = ["b"]') + crate('b', '1.0.0', 'dependencies = ["a"]'));
  assert.equal(analyze(parsed).metrics.reachable, 2);
  assert.equal(parsed.edges.filter(item => item.kind === 'inferred').length, 2);
});

for (const [label, text] of [
  ['wrong version', cdx([], []).replace('"1.5"', '"1.4"')],
  ['missing document version', cdx([], []).replace('"version":1,', '')],
  ['null document version', cdx([], []).replace('"version":1', '"version":null')],
  ['null components', cdx(null, [])], ['non-array components', cdx({}, [])],
  ['missing component name', cdx([{ type: 'library' }], [])],
  ['missing component type', cdx([{ name: 'a' }], [])],
  ['duplicate bom-ref', cdx([component('a'), component('a')], [])],
  ['invalid hash algorithm', cdx([component('a', { hashes: [{ alg: 'other', content: '00' }] })], [])],
  ['invalid hash length', cdx([component('a', { hashes: [{ alg: 'SHA-256', content: 'ab' }] })], [])],
  ['duplicate dependency rows', cdx([component('a')], [{ ref: 'a' }, { ref: 'a' }])],
  ['unknown dependency row', cdx([component('a')], [{ ref: 'b', dependsOn: ['a'] }])],
  ['null dependency targets', cdx([component('a')], [{ ref: 'a', dependsOn: null }])],
]) test(`CycloneDX rejects ${label}`, () => assert.throws(() => sbom(text)));
test('CycloneDX metadata root uses real refs, preserves disconnected inventory, and marks unresolved targets', () => {
  const parsed = sbom(cdx([component('a'), component('b')], [{ ref: 'work', dependsOn: ['a', 'missing'] }], { component: component('work') }));
  const result = analyze(parsed);
  assert.equal(result.metrics.reachable, 1);
  assert.deepEqual(result.paths.get('sbom:a'), ['root', 'sbom:a']);
  assert.equal(result.paths.has('sbom:b'), false);
  assert.equal(result.findings[0].ruleId, 'SG014');
});
test('CycloneDX preserves nesting without reporting a false dependency edge', () => {
  const parsed = sbom(cdx([component('a', { components: [component('b')] })], []));
  assert.equal(parsed.edges.length, 2);
  assert.ok(parsed.edges.every(item => item.kind === 'inferred'));
});
test('CycloneDX preserves verified digest formatting and purl ecosystem metadata', () => {
  const parsed = sbom(cdx([component('example', { purl: 'pkg:npm/%40sample/example@2.0.0', group: '@sample',
    hashes: [{ alg: 'SHA-256', content: 'AB'.repeat(32) }] })], []));
  assert.deepEqual(parsed.nodes[1].hashes, [{ alg: 'SHA-256', content: 'ab'.repeat(32) }]);
  assert.equal(parsed.nodes[1].name, '@sample/example');
});

// Exhaust all loop-free directed graphs on three vertices. Enumerating simple paths independently
// checks both BFS depths and inferred entries without relying on the production traversal.
const vertices = ['a', 'b', 'c'];
const choices = vertices.flatMap(from => vertices.filter(to => from !== to).map(to => ({ from, to })));
for (let mask = 0; mask < 2 ** choices.length; mask++) test(`three-vertex reachability oracle ${mask}`, () => {
  const edges = choices.filter((_, i) => (mask & 2 ** i) !== 0);
  const { outgoing, incoming } = indexGraph(vertices.map(id => ({ id })), edges);
  const walk = (start, target, candidates) => {
    const paths = [];
    function explore(path) {
      if (path.at(-1) === target) { paths.push(path); return; }
      for (const next of candidates(path.at(-1))) if (!path.includes(next)) explore([...path, next]);
    }
    explore([start]);
    paths.sort((a, b) => a.length - b.length || (a.join() < b.join() ? -1 : 1));
    return paths[0] ?? null;
  };
  for (const start of vertices) {
    const { predecessor } = breadthFirst(start, outgoing);
    const back = breadthFirst(start, incoming).depths;
    for (const target of vertices) {
      assert.deepEqual(trace(target, predecessor), walk(start, target, id => edges.filter(item => item.from === id).map(item => item.to)));
      assert.equal(back.has(target), Boolean(walk(target, start, id => outgoing.get(id))));
    }
  }
  const expectedEntries = vertices.filter(target => !vertices.some(start =>
    walk(start, target, id => outgoing.get(id)) && !walk(target, start, id => outgoing.get(id))));
  assert.deepEqual(inferredEntries(vertices.map(id => ({ id })), edges), expectedEntries);
});

for (const [a, b, distance] of [
  ['', '', 0], ['', 'tool', 4], ['abc', '', 3], ['read', 'read', 0], ['react', 'recat', 1], ['abc', 'adc', 1],
  ['CA', 'ABC', 2], ['ABC', 'CA', 2], ['ab', 'ba', 1], ['abcdef', 'badcfe', 3],
  ['taste', 'state', 2], ['aba', 'baa', 1], ['a\u{1F331}b', 'ab\u{1F331}', 1],
]) test(`exact edit distance ${JSON.stringify([a, b])}`, () => assert.equal(damerauLevenshtein(a, b), distance));
for (const [value, expected] of [
  ['l\u043edash', 'lodash'], ['\u0440\u0435act', 'peact'], ['\uff32\uff25\uff21\uff23\uff34', 'react'],
  ['re\u200bact', 'react'], ['plain', 'plain'], ['caf\u00e9', 'caf\u00e9'],
]) test(`confusable skeleton ${JSON.stringify(value)}`, () => assert.equal(skeleton(value), expected));
for (const [a, b, expected] of [['i','o',true],['q','1',true],['q','p',false],['g','g',false],['p','\u0440',false],['m','n',true]]) {
  test(`QWERTY adjacency ${a}/${b}`, () => assert.equal(keyboardAdjacent(a, b), expected));
}
for (const [value, result] of [
  [sri(), 'SHA-512'], [sri(0, 32, 'sha256'), 'SHA-256'], [sri(0, 48, 'sha384'), 'SHA-384'],
  ['sha512-YQ==', undefined], [sri().replace('sha512-', 'sha513-'), undefined], ['sha512-???', undefined],
  [sri().replace(/=+$/, ''), 'SHA-512'], [`${sri()}?option`, 'SHA-512'],
]) test(`SRI decode ${value.slice(0, 12)} (${value.length})`, () => assert.equal(sriHashes(value)[0]?.alg, result));
for (const [url, result] of [
  ['https://registry.npmjs.org/x', 'registry.npmjs.org'], ['https://registry.npmjs.org.evil.invalid/x', 'registry.npmjs.org.evil.invalid'],
  ['https://registry.npmjs.org@evil.invalid/', ''], ['http://registry.npmjs.org/', ''],
  ['https://registry.npmjs.org:8080/', ''], ['registry+https://index.crates.io/', 'index.crates.io'],
]) test(`strict source host ${url}`, () => assert.equal(sourceHost(url), result));

for (const [key, expected] of Object.entries(scores)) test(`synthetic ${key} risk, graph and repeatability`, () => {
  const scenario = loadPreset(key);
  const result = analyze(scenario);
  assert.equal(scenario.sourceKind, 'synthetic');
  assert.equal(result.score, expected);
  assert.equal(result.metrics.reachable, 11);
  assert.equal(result.metrics.maxDepth, 4);
  assert.deepEqual(result.contributions, analyze(loadPreset(key)).contributions);
  assert.equal(result.score, Math.min(100, result.contributions.reduce((sum, item) => sum + item.points, 0)));
});
test('lifecycle fixture identifies the exact shortest path and reverse impact', () => {
  const { findings } = analyze(loadPreset('lifecycle'));
  const [finding] = findings;
  assert.deepEqual(finding.path, ['root', 'npm:node_modules/ui-gateway', 'npm:node_modules/render-adapter', 'npm:node_modules/snapshot-codec']);
  assert.deepEqual(finding.affected, [
    'npm:node_modules/print-layout', 'npm:node_modules/render-adapter', 'npm:node_modules/report-kit', 'npm:node_modules/ui-gateway',
  ]);
});
test('scope pin clears only unpinned version evidence and leaves original immutable', () => {
  const model = loadPreset('scope');
  const id = 'npm:node_modules/@signaldesk/render';
  const before = JSON.stringify(model);
  const result = analyze(simulate(model, new Map([[id, { action: 'pin' }]])));
  assert.equal(result.score, 85);
  assert.ok(!result.findings.some(item => item.ruleId === 'SG009'));
  assert.equal(JSON.stringify(model), before);
});
test('quarantine changes downstream reachability and does not count the disconnected findings', () => {
  const model = loadPreset('lifecycle');
  const id = 'npm:node_modules/render-adapter';
  const result = analyze(simulate(model, new Map([[id, { action: 'quarantine' }]])));
  assert.equal(result.score, 0);
  assert.equal(result.metrics.affected, 0);
  assert.equal(result.metrics.reachable, 8);
  assert.ok(result.findings.every(f => !f.reachable && f.path === null && f.points === 0));
});
test('upgrade requires a real candidate, never invents new hashes and labels unknown coverage', () => {
  const model = loadPreset('lifecycle');
  const id = 'npm:node_modules/snapshot-codec';
  const change = new Map([[id, { action: 'upgrade', version: '1.7.0' }]]);
  const simulated = simulate(model, change);
  assert.equal(simulated.nodes.find(item => item.id === id).integrity, '');
  assert.equal(simulated.edges.filter(edge => edge.to === id)[0].spec, '1.7.0');
  assert.equal(analyze(simulated).score, 12);
  assert.match(simulated.notes.at(-1), /missing evidence, not safety/);
  assert.throws(() => simulate(model, new Map([[id, { action: 'upgrade', version: 'next' }]])), /concrete/);
  assert.throws(() => simulate(model, new Map([[id, { action: 'upgrade', version: '1.6.0' }]])), /different/);
  assert.throws(() => simulate(model, new Map([[id, { action: 'upgrade', version: '1.7.0', integrity: 'bad' }]])), /valid SHA/);
});
test('simulation does not accept remediation of the graph root or an unknown node', () => {
  const original = loadPreset('scope');
  for (const id of ['root', 'absent']) assert.throws(() => simulate(original, new Map([[id, { action: 'quarantine' }]])));
});
test('risk points cap at 100 while preserving all contributing rows', () => {
  const model = loadPreset('lookalikes');
  for (const item of model.nodes.filter(n => !n.root)) item.integrity = '';
  const result = analyze(model);
  assert.equal(result.score, 100);
  assert.ok(result.contributions.reduce((total, entry) => total + entry.points, 0) > 100);
});

for (const [input, expected] of [
  ['=1+1', '"\'=1+1"'], ['+2', '"\'+2"'], ['-2', '"\'-2"'], ['@sample/pkg', '"\'@sample/pkg"'],
  [' \t=1', '"\' \t=1"'], ['\r\nline', '"\'\r\nline"'], ['\uFF1D1', '"\'\uFF1D1"'],
  ['ordinary "quote", comma', '"ordinary ""quote"", comma"'], ['example.invalid', '"example.invalid"'],
]) test(`CSV formula and field quoting ${JSON.stringify(input)}`, () => assert.equal(csvCell(input), expected));
test('SHA-256 matches known test vectors and accepts raw bytes', async () => {
  assert.equal(await sha256('abc'), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  assert.equal(await sha256(new Uint8Array()), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
});
test('canonical JSON sorts decoded keys, not numeric insertion order, and rejects non-finite numbers', () => {
  assert.equal(canonicalJson({ 2: 'b', 10: 'a', x: { z: null, a: [1] } }), '{"10":"a","2":"b","x":{"a":[1],"z":null}}');
  assert.throws(() => canonicalJson(NaN));
});
test('every format shares one canonical audit fingerprint and returns its byte fingerprint', async () => {
  const analysis = analyze(loadPreset('scope'));
  const [audit, sarif, cdx, csv] = await Promise.all(['audit', 'sarif', 'cyclonedx', 'csv'].map(kind => makeExport(kind, analysis)));
  const parsed = JSON.parse(audit.text);
  assert.equal(await sha256(canonicalJson(parsed.evidence)), parsed.auditSha256);
  assert.equal(JSON.parse(sarif.text).runs[0].properties.auditSha256, parsed.auditSha256);
  assert.equal(JSON.parse(cdx.text).metadata.properties[0].value, parsed.auditSha256);
  assert.ok(csv.text.includes(parsed.auditSha256));
  for (const file of [audit, sarif, cdx, csv]) assert.equal(file.sha256, await sha256(file.text));
});
test('audit omits raw hook contents and source URL credentials', async () => {
  const analysis = analyze(loadPreset('lifecycle'));
  const found = analysis.model.nodes.find(node => node.hasInstallScript);
  found.resolved = 'https://test-login:private-value@example.invalid/path';
  const { text } = await makeExport('audit', analysis);
  for (const raw of ['private-value', 'test-login', 'INERT EVIDENCE', 'process.env']) assert.ok(!text.includes(raw));
});
test('SARIF references known rule indices and preserves actual requirements source lines', async () => {
  const result = analyze(py('# note\nurllib3>=2.0'));
  const report = JSON.parse((await makeExport('sarif', result)).text);
  const run = report.runs[0];
  const entry = run.results[0];
  assert.equal(report.version, '2.1.0');
  assert.equal(run.tool.driver.rules[entry.ruleIndex].id, entry.ruleId);
  assert.equal(entry.locations[0].physicalLocation.region.startLine, 2);
  assert.equal(entry.locations[0].physicalLocation.artifactLocation.uri, 'requirements.txt');
});
test('CycloneDX references a unique root and excludes quarantined packages from dependencies', async () => {
  const result = analyze(simulate(loadPreset('lifecycle'), new Map([['npm:node_modules/snapshot-codec', { action: 'quarantine' }]])));
  const report = JSON.parse((await makeExport('cyclonedx', result)).text);
  assert.equal(report.specVersion, '1.5');
  assert.ok(report.components.every(node => node.name !== 'snapshot-codec'));
  const refs = new Set([report.metadata.component, ...report.components].map(node => node['bom-ref']));
  assert.equal(refs.size, 11);
  for (const dependency of report.dependencies) {
    assert.ok(refs.has(dependency.ref));
    assert.ok(dependency.dependsOn.every(ref => refs.has(ref)));
  }
});
test('SVG and markup are not accepted as input file types or executable expressions', () => {
  assert.throws(() => parseInput('<svg><script>throw 0</script></svg>', 'proof.svg'));
  assert.throws(() => py('<img onerror=placeholder>'));
});
test('index enforces network lockdown and local entry points', () => {
  const markup = readFileSync(new URL('../index.html', import.meta.url), 'utf8');
  assert.match(markup, /connect-src 'none'/);
  assert.match(markup, /script-src 'self'/);
  assert.doesNotMatch(markup, /<(?:script|link)\b[^>]+(?:src|href)=["']https?:/);
  assert.doesNotMatch(markup, /scroll-behavior\s*:\s*smooth/);
});
test('shipped text contains no banned typography, smooth scrolling, or tool attributions', () => {
  const root = new URL('../', import.meta.url);
  const banned = new RegExp(`[${String.fromCharCode(0x2013, 0x2014)}]|scroll-behavior\\s*:\\s*smooth|\\b(?:${['A' + 'I', 'Chat' + 'GPT', 'De' + 'vin'].join('|')})\\b`, 'i');
  assert.match(String.fromCharCode(0x2014), banned);
  for (const dir of ['', 'src/']) for (const name of readdirSync(new URL(dir, root))) {
    if (/\.(?:html|css|js|md|json|svg)$/.test(name)) {
      assert.doesNotMatch(readFileSync(new URL(dir + name, root), 'utf8'), banned, name);
    }
  }
});
