import assert from 'node:assert/strict';
import test from 'node:test';
import { analyze } from '../src/detectors.js';
import { compareVersions, diffAnalyses, diffInputs, diffModels, inventory } from '../src/diff.js';
import { parseInput } from '../src/parsers.js';
import { loadPreset } from '../src/presets.js';

const npm = (packages, version = 3) => JSON.stringify({ lockfileVersion: version, packages: { '': {}, ...packages } });
const lock = text => parseInput(text, 'package-lock.json');
const audit = text => analyze(lock(text));

/* ---------- compareVersions ---------- */

for (const [left, right, expected] of [
  ['1.0.0', '1.0.1', -1], ['2.0.0', '1.9.9', 1], ['1.0.0', '1.0.0', 0],
  ['1.0.0-alpha', '1.0.0', -1], ['1.0.0', '1.0.0-alpha', 1],
  ['1.0.0-alpha', '1.0.0-beta', -1], ['1.0.0-alpha.1', '1.0.0-alpha', 1],
  ['1.0.0-rc.2', '1.0.0-rc.10', -1], ['1.0.0-2', '1.0.0-10', -1],
  ['1.0.0-beta', '1.0.0-1', 1], ['v1.2.3', '1.2.3', 0], ['V2.0', '2.0.0', 0],
  ['1.0', '1.0.0', 0], ['1.0.0+build.7', '1.0.0', 0], ['1.0.0+meta', '1.0.0-alpha', 1],
  ['10.0.0', '9.9.9', 1], ['0.9.0', '0.10.0', -1], ['4.17.20', '4.17.21', -1],
  ['1.2rc1', '1.2', -1], ['1.0.0a1', '1.0.0', -1], ['', '', 0], ['1.0', '', -1],
  ['5.0rc1', '5.0', -1], ['1.2a1', '1.10', -1], ['1.2post1', '1.2', 1], ['1.2dev1', '1.2a1', -1],
  ['1.2.dev1', '1.2', -1], ['1.2.dev1', '1.2.1', -1], ['1.2.rc1', '1.2', -1], ['1.2.3.dev0', '1.2.3a1', -1],
  ['1.2rc1.dev1', '1.3', -1], ['2.0b1.post1', '2.1', -1], ['1.2.3.post1.dev5', '1.2.4', -1], ['1.0.post1.dev2', '1.0.post1', -1],
  ['2.0.post1', '2.0.1', -1], ['1.2.post1', '1.2.1', -1], ['1.0rc1', '1.0.0rc1', 0], ['1.0.post1', '1.0.0.post1', 0],
  ['1.1.1k', '1.1.1l', -1], ['1.0x1', '1.0y1', -1], ['2.0.0.beta.1', '2.0.0', -1], ['2.0.0.beta.1', '2.0.0.beta.2', -1],
  ['2.1.beta.1', '2.1.0.beta.2', -1], ['1.2.beta.1', '1.2.0.beta.2', -1], ['1.2.rc1.1', '1.2.0.rc1.2', -1],
  ['1.2rc1', '1.2.0rc1', 0], ['1.2.dev1', '1.2.0.dev1', 0], ['1.0rc1.x', '1.0rc1.y', -1], ['2.0.0.beta.2', '2.0.0beta1', 1],
  ['1.0_a_1', '1.0a1', 0], ['5.0.0.M1', '5.0.0', -1], ['5.0.0.M1', '5.0.0.RC1', -1], ['5.0.0.milestone2', '5.0.0.rc1', -1],
  ['1.1.1l', '1.1.1m', -1], ['1.1.1m', '1.1.1', 1], ['1.1.1m', '1.1.1m1', 1],
  ['99999999999999999999999.0', '1.0', 1], ['2026.11.20', '2026.11.20', 0],
]) {
  test(`compareVersions(${JSON.stringify(left)}, ${JSON.stringify(right)}) === ${expected}`, () => {
    assert.equal(Math.sign(compareVersions(left, right)), expected);
  });
}

test('compareVersions: a long letter run ending in a non-alnum char stays linear', () => {
  const crafted = '1' + 'a'.repeat(60) + '!';
  const start = Date.now();
  assert.equal(Math.sign(compareVersions(crafted, '2')), 1);
  assert.ok(Date.now() - start < 1000, 'letter-run compare took ' + (Date.now() - start) + 'ms');
});

test('compareVersions is antisymmetric across a spread of inputs', () => {
  for (const pair of [['1.0', '2.0'], ['1.0.0-alpha', '1.0.0'], ['3.1', '3.10'], ['a', 'b']]) {
    assert.equal(Math.sign(compareVersions(...pair)), -Math.sign(compareVersions(pair[1], pair[0])));
  }
});

/* ---------- inventory ---------- */

test('inventory: the synthetic root is excluded', () => {
  const map = inventory(lock(npm({ '': { dependencies: { a: '1.0.0' } }, 'node_modules/a': { version: '1.0.0' } })));
  assert.equal(map.size, 1);
  assert.equal([...map.values()][0].name, 'a');
});

test('inventory: parallel-installed versions group under one key sorted', () => {
  const map = inventory(lock(npm({
    '': { dependencies: { dep: '2.0.0' } },
    'node_modules/dep': { version: '2.0.0' },
    'node_modules/a/node_modules/dep': { version: '1.10.0' },
    'node_modules/b/node_modules/dep': { version: '1.9.0' },
  })));
  assert.equal(map.size, 1);
  assert.deepEqual(map.get('npm:dep').versions, ['1.9.0', '1.10.0', '2.0.0']);
});

test('inventory: npm names fold case; pypi names normalize separators', () => {
  const npmMap = inventory(lock(npm({
    '': { dependencies: { Lodash: '4.0.0', lodash: '4.1.0' } },
    'node_modules/Lodash': { version: '4.0.0' }, 'node_modules/lodash': { version: '4.1.0' },
  })));
  assert.equal(npmMap.size, 1);
  const reqs = parseInput('Foo_Bar==1.0\nfoo-bar==2.0\n', 'requirements.txt');
  const pyMap = inventory(reqs);
  assert.equal(pyMap.size, 1);
  assert.deepEqual(pyMap.get('pypi:foo-bar').versions, ['1.0', '2.0']);
});

test('inventory: unresolved references keep an empty version slot', () => {
  const model = lock(npm({
    '': { dependencies: { app: '1.0.0' } },
    'node_modules/app': { version: '1.0.0', dependencies: { ghost: '1.0.0' } },
  }));
  const map = inventory(model);
  const ghost = map.get('npm:ghost');
  assert.ok(ghost);
  assert.deepEqual(ghost.versions, ['']);
});

test('inventory: missing names fall back to the node id', () => {
  const map = inventory({ rootId: 'root', nodes: [{ id: 'root', root: true }, { id: 'weird-id', version: '3.0.0', ecosystem: 'npm' }] });
  assert.equal(map.get('npm:weird-id').name, 'weird-id');
});

/* ---------- diffModels ---------- */

const simpleLock = (deps, versions) => npm({
  '': { dependencies: deps },
  ...Object.fromEntries(Object.entries(versions).map(([name, ver]) => [`node_modules/${name}`, { version: ver }])),
});

test('diffModels: identical inventories report no changes', () => {
  const text = simpleLock({ a: '1.0.0' }, { a: '1.0.0' });
  const diff = diffModels(lock(text), lock(text));
  assert.deepEqual(diff, { added: [], removed: [], changed: [] });
});

test('diffModels: a new package is added with all its versions', () => {
  const before = lock(simpleLock({}, {}));
  const after = lock(simpleLock({ axios: '1.0.0' }, { axios: '1.0.0' }));
  const diff = diffModels(before, after);
  assert.equal(diff.added.length, 1);
  assert.equal(diff.added[0].name, 'axios');
  assert.deepEqual(diff.added[0].versions, ['1.0.0']);
  assert.equal(diff.removed.length, 0);
});

test('diffModels: a dropped package is removed', () => {
  const before = lock(simpleLock({ axios: '1.0.0' }, { axios: '1.0.0' }));
  const after = lock(simpleLock({}, {}));
  const diff = diffModels(before, after);
  assert.equal(diff.removed.length, 1);
  assert.equal(diff.added.length, 0);
});

test('diffModels: a version raise reports upgraded with both pins', () => {
  const before = lock(simpleLock({ dep: '1.0.0' }, { dep: '1.0.0' }));
  const after = lock(simpleLock({ dep: '2.0.0' }, { dep: '2.0.0' }));
  const [change] = diffModels(before, after).changed;
  assert.equal(change.direction, 'upgraded');
  assert.deepEqual(change.from, ['1.0.0']);
  assert.deepEqual(change.to, ['2.0.0']);
});

test('diffModels: a version drop reports downgraded', () => {
  const before = lock(simpleLock({ dep: '2.0.0' }, { dep: '2.0.0' }));
  const after = lock(simpleLock({ dep: '1.0.0' }, { dep: '1.0.0' }));
  assert.equal(diffModels(before, after).changed[0].direction, 'downgraded');
});

test('diffModels: an equal-order repin reports equivalent', () => {
  const before = lock(simpleLock({ dep: '1.0' }, { dep: '1.0' }));
  const after = lock(simpleLock({ dep: '1.0.0' }, { dep: '1.0.0' }));
  const changed = diffModels(before, after).changed;
  assert.equal(changed.length, 1);
  assert.equal(changed[0].direction, 'equivalent');
});

test('diffModels: pinning an unversioned declaration reports pinned', () => {
  const reqs = text => parseInput(text, 'requirements.txt');
  const before = reqs('requests');
  const after = reqs('requests==2.31.0');
  const [change] = diffModels(before, after).changed;
  assert.equal(change.direction, 'pinned');
  assert.deepEqual(change.from, ['']);
  assert.equal(diffModels(after, before).changed[0].direction, 'unpinned');
});

test('diffModels: a rotated set with a strictly raised pin reports upgraded', () => {
  const two = (v1, v2) => lock(npm({
    '': { dependencies: { dep: v1 } },
    'node_modules/dep': { version: v1 },
    'node_modules/x/node_modules/dep': { version: v2 },
  }));
  const [change] = diffModels(two('1.0.0', '2.0.0'), two('2.0.0', '3.0.0')).changed;
  assert.equal(change.direction, 'upgraded');
  assert.deepEqual(change.from, ['1.0.0']);
  assert.deepEqual(change.to, ['3.0.0']);
});

test('diffModels: overlapping version swaps report mixed', () => {
  const two = (v1, v2) => lock(npm({
    '': { dependencies: { dep: v1 } },
    'node_modules/dep': { version: v1 },
    'node_modules/x/node_modules/dep': { version: v2 },
  }));
  const [change] = diffModels(two('1.0.0', '3.0.0'), two('2.0.0', '2.0.0')).changed;
  assert.equal(change.direction, 'mixed');
  assert.deepEqual(change.from, ['1.0.0', '3.0.0']);
  assert.deepEqual(change.to, ['2.0.0']);
});

test('diffModels: adding a sibling version reports expanded; dropping one reports reduced', () => {
  const one = lock(npm({ '': { dependencies: { dep: '1.0.0' } }, 'node_modules/dep': { version: '1.0.0' } }));
  const two = lock(npm({
    '': { dependencies: { dep: '1.0.0' } },
    'node_modules/dep': { version: '1.0.0' },
    'node_modules/x/node_modules/dep': { version: '2.0.0' },
  }));
  assert.equal(diffModels(one, two).changed[0].direction, 'expanded');
  assert.equal(diffModels(two, one).changed[0].direction, 'reduced');
});

test('diffModels: same name in different ecosystems stays a remove plus add', () => {
  const before = lock(simpleLock({ foo: '1.0.0' }, { foo: '1.0.0' }));
  const after = parseInput('foo==1.0.0\n', 'requirements.txt');
  const diff = diffModels(before, after);
  assert.equal(diff.removed[0].ecosystem, 'npm');
  assert.equal(diff.added[0].ecosystem, 'pypi');
});

test('diffModels: output ordering is sorted by canonical key', () => {
  const before = lock(simpleLock({}, {}));
  const after = lock(simpleLock(
    { zebra: '1.0.0', apple: '1.0.0', mango: '1.0.0' },
    { zebra: '1.0.0', apple: '1.0.0', mango: '1.0.0' },
  ));
  assert.deepEqual(diffModels(before, after).added.map(item => item.name), ['apple', 'mango', 'zebra']);
});

test('diffModels: case-only rename on npm reports no change', () => {
  const before = lock(npm({ '': { dependencies: { Lodash: '4.17.21' } }, 'node_modules/Lodash': { version: '4.17.21' } }));
  const after = lock(npm({ '': { dependencies: { lodash: '4.17.21' } }, 'node_modules/lodash': { version: '4.17.21' } }));
  assert.deepEqual(diffModels(before, after), { added: [], removed: [], changed: [] });
});

/* ---------- diffAnalyses ---------- */

test('diffAnalyses: baseline to lifecycle reports +72 and four introduced signals', () => {
  const diff = diffAnalyses(analyze(loadPreset('baseline')), analyze(loadPreset('lifecycle')));
  assert.equal(diff.score.delta, 72);
  assert.equal(diff.score.before, 0);
  assert.equal(diff.score.after, 72);
  assert.equal(diff.signals.introduced.length, 4);
  assert.equal(diff.signals.resolved.length, 0);
  assert.equal(diff.added.length, 0);
  assert.equal(diff.removed.length, 0);
  assert.equal(diff.changed.length, 0);
});

test('diffAnalyses: reversing a diff flips introduced and resolved', () => {
  const forward = diffAnalyses(analyze(loadPreset('baseline')), analyze(loadPreset('lifecycle')));
  const backward = diffAnalyses(analyze(loadPreset('lifecycle')), analyze(loadPreset('baseline')));
  assert.equal(backward.score.delta, -forward.score.delta);
  assert.equal(backward.signals.introduced.length, forward.signals.resolved.length);
  assert.equal(backward.signals.resolved.length, forward.signals.introduced.length);
  assert.equal(backward.added.length, forward.removed.length);
  assert.equal(backward.removed.length, forward.added.length);
});

test('diffAnalyses: a self-diff is a no-op across every field', () => {
  for (const preset of ['baseline', 'lifecycle', 'lookalikes', 'scope']) {
    const analysis = analyze(loadPreset(preset));
    const diff = diffAnalyses(analysis, analysis);
    assert.equal(diff.score.delta, 0);
    assert.equal(diff.signals.introduced.length, 0);
    assert.equal(diff.signals.resolved.length, 0);
    assert.equal(diff.changed.length, 0);
  }
});

test('diffAnalyses: baseline to lookalikes reports +59 and three signals', () => {
  const diff = diffAnalyses(analyze(loadPreset('baseline')), analyze(loadPreset('lookalikes')));
  assert.equal(diff.score.delta, 59);
  assert.equal(diff.signals.introduced.length, 3);
  assert.ok(diff.signals.introduced.some(item => item.ruleId === 'SG002' && item.severity === 'high'));
});

test('diffAnalyses: a version bump keeps the same signal key', () => {
  const before = audit(simpleLock({ recat: '18.3.0' }, { recat: '18.3.0' }));
  const after = audit(simpleLock({ recat: '18.3.1' }, { recat: '18.3.1' }));
  const diff = diffAnalyses(before, after);
  assert.equal(diff.changed[0].direction, 'upgraded');
  assert.equal(diff.signals.introduced.length, 0);
  assert.equal(diff.signals.resolved.length, 0);
  assert.equal(diff.score.delta, 0);
});

test('diffAnalyses: adding a hooked package introduces its signals', () => {
  const before = audit(simpleLock({}, {}));
  const after = audit(simpleLock({ hooky: '1.0.0' }, { hooky: '1.0.0' }));
  after.model.nodes.find(node => node.name === 'hooky').hasInstallScript = true;
  const diff = diffAnalyses(before, analyze(after.model));
  assert.equal(diff.added.length, 1);
  assert.ok(diff.signals.introduced.some(item => item.ruleId === 'SG003'));
  assert.ok(diff.score.delta > 0);
});

test('diffAnalyses: removing a flagged package resolves its signals', () => {
  const before = audit(simpleLock({ hooky: '1.0.0' }, { hooky: '1.0.0' }));
  before.model.nodes.find(node => node.name === 'hooky').hasInstallScript = true;
  const beforeAnalysis = analyze(before.model);
  const after = audit(simpleLock({}, {}));
  const diff = diffAnalyses(beforeAnalysis, after);
  assert.equal(diff.removed.length, 1);
  assert.ok(diff.signals.resolved.some(item => item.ruleId === 'SG003'));
  assert.ok(diff.score.delta < 0);
});

test('diffAnalyses: findings and reachability counters are echoed', () => {
  const diff = diffAnalyses(analyze(loadPreset('baseline')), analyze(loadPreset('lifecycle')));
  assert.deepEqual(diff.findings, { before: 0, after: 4 });
  assert.deepEqual(diff.reachable, { before: 11, after: 11 });
  assert.equal(diff.affected.before, 0);
  assert.equal(diff.affected.after, 4);
});

test('diffAnalyses: identical inputs produce identical reports', () => {
  const before = analyze(loadPreset('scope'));
  const after = analyze(loadPreset('lifecycle'));
  assert.deepEqual(diffAnalyses(before, after), diffAnalyses(before, after));
});

test('diffAnalyses: empty inputs degrade to zeroed counters', () => {
  const diff = diffAnalyses(undefined, undefined);
  assert.equal(diff.score.delta, 0);
  assert.equal(diff.findings.before, 0);
  assert.deepEqual(diff.added, []);
});

/* ---------- diffInputs ---------- */

test('diffInputs: parses both sides and returns models plus the report', () => {
  const { beforeModel, afterModel, diff } = diffInputs(
    simpleLock({}, {}), 'before.json', simpleLock({ a: '1.0.0' }, { a: '1.0.0' }), 'after.json', parseInput);
  assert.equal(beforeModel.format, 'npm');
  assert.equal(afterModel.format, 'npm');
  assert.equal(diff.added.length, 1);
});

test('diffInputs: parse errors surface with the failing side named', () => {
  assert.throws(() => diffInputs('not json', 'before.json', simpleLock({}, {}), 'after.json', parseInput));
  assert.throws(() => diffInputs(simpleLock({}, {}), 'before.json', 'not json', 'after.json', parseInput));
});

test('diffModels: many versions on both sides resolves direction from endpoints, fast', () => {
  const packs = versions => Object.fromEntries(versions.map((v, i) => [`p${i}/node_modules/x`, { version: v }]));
  const left = lock(npm({ '': {}, ...packs(Array.from({ length: 400 }, (_, i) => `1.0.${i}`)) }));
  const right = lock(npm({ '': {}, ...packs(Array.from({ length: 400 }, (_, i) => `2.0.${i}`)) }));
  const start = Date.now();
  const diff = diffModels(left, right);
  assert.equal(diff.changed[0].direction, 'upgraded');
  assert.equal(diff.changed[0].from.length, 400);
  assert.ok(Date.now() - start < 2000, 'multi-version diff took ' + (Date.now() - start) + 'ms');
});

test('diffModels: multi-version sets that interleave still read mixed', () => {
  const packs = versions => Object.fromEntries(versions.map((v, i) => [`p${i}/node_modules/x`, { version: v }]));
  const left = lock(npm({ '': {}, ...packs(['1.0.0', '3.0.0']) }));
  const right = lock(npm({ '': {}, ...packs(['2.0.0', '4.0.0']) }));
  const diff = diffModels(left, right);
  assert.equal(diff.changed[0].direction, 'mixed');
});
