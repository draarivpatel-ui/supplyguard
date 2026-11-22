import assert from 'node:assert/strict';
import test from 'node:test';
import { analyze, simulate } from '../src/detectors.js';
import { canonicalJson } from '../src/exports.js';
import { parseInput } from '../src/parsers.js';
import { loadPreset } from '../src/presets.js';
import {
  blastRadius, dependents, exposurePaths, policyGate, sanitizePolicy, whatIf,
  DEFAULT_POLICY, GATE_LEVELS, CEILINGS,
} from '../src/policy.js';

const npm = (packages, version = 3) => JSON.stringify({ lockfileVersion: version, packages: { '': {}, ...packages } });
const lock = text => parseInput(text, 'package-lock.json');
const cdx = (components, dependencies = [], metadata) => JSON.stringify({
  bomFormat: 'CycloneDX', specVersion: '1.5', version: 1, metadata, components, dependencies,
});
const sbom = text => parseInput(text, 'sbom.json');

/* Hand-built model: a root plus plain component nodes and directed edges. */
const hand = (ids, edges, extras = {}) => ({
  rootId: 'root', format: 'npm', source: 'hand-built', notes: [],
  nodes: [{ id: 'root', name: 'root', root: true }, ...ids.map(id => ({ id, name: id, version: '1.0.0', ecosystem: 'npm', ...(extras[id] ?? {}) }))],
  edges: edges.map(([from, to]) => ({ from, to, name: to, spec: '1.0.0', kind: 'dependency' })),
});

/* ---------- exposurePaths ---------- */

test('exposure paths: a single chain yields one shortest path', () => {
  const paths = exposurePaths(hand(['a', 'b', 't'], [['root', 'a'], ['a', 'b'], ['b', 't']]), 't');
  assert.deepEqual(paths, [['root', 'a', 'b', 't']]);
});

test('exposure paths: a diamond yields both equal-length paths', () => {
  const paths = exposurePaths(hand(['a', 'b', 't'], [['root', 'a'], ['root', 'b'], ['a', 't'], ['b', 't']]), 't');
  assert.deepEqual(paths, [['root', 'a', 't'], ['root', 'b', 't']]);
});

for (const middles of [1, 2, 3, 5]) {
  test(`exposure paths: ${middles} parallel middles yield ${middles} paths`, () => {
    const ids = Array.from({ length: middles }, (_, i) => 'm' + i);
    const edges = [...ids.map(id => ['root', id]), ...ids.map(id => [id, 't'])];
    const paths = exposurePaths(hand([...ids, 't'], edges), 't');
    assert.equal(paths.length, middles);
    assert.ok(paths.every(path => path.length === 3 && path.at(-1) === 't'));
  });
}

test('exposure paths: a direct edge wins over a longer route', () => {
  const paths = exposurePaths(hand(['a', 't'], [['root', 'a'], ['a', 't'], ['root', 't']]), 't');
  assert.deepEqual(paths, [['root', 't']]);
});

test('exposure paths: a dependency cycle does not loop or drop the target', () => {
  const model = hand(['a', 'b', 't'], [['root', 'a'], ['a', 'b'], ['b', 'a'], ['b', 't']]);
  assert.deepEqual(exposurePaths(model, 't'), [['root', 'a', 'b', 't']]);
});

test('exposure paths: unreachable target and unknown id return empty', () => {
  const model = hand(['a', 't'], [['root', 'a']]);
  assert.deepEqual(exposurePaths(model, 't'), []);
  assert.deepEqual(exposurePaths(model, 'missing'), []);
});

test('exposure paths: the root itself is a trivial path', () => {
  assert.deepEqual(exposurePaths(hand(['a'], [['root', 'a']]), 'root'), [['root']]);
});

test('exposure paths: quarantined intermediates leave no path', () => {
  const model = hand(['a', 't'], [['root', 'a'], ['a', 't']], { a: { quarantined: true } });
  assert.deepEqual(exposurePaths(model, 't'), []);
});

test('exposure paths: the cap limits enumeration without reordering', () => {
  const ids = Array.from({ length: 8 }, (_, i) => 'm' + i);
  const edges = [...ids.map(id => ['root', id]), ...ids.map(id => [id, 't'])];
  const paths = exposurePaths(hand([...ids, 't'], edges), 't', 3);
  assert.equal(paths.length, 3);
  assert.deepEqual(paths[0], ['root', 'm0', 't']);
});

test('exposure paths: the 64/65 boundary distinguishes the cap from the count', () => {
  const middles = n => Array.from({ length: n }, (_, i) => 'm' + i);
  const edges = ids => [...ids.map(id => ['root', id]), ...ids.map(id => [id, 't'])];
  const at64 = middles(64);
  assert.equal(exposurePaths(hand([...at64, 't'], edges(at64)), 't', 65).length, 64);
  const at65 = middles(65);
  assert.equal(exposurePaths(hand([...at65, 't'], edges(at65)), 't', 65).length, 65);
});

test('exposure paths: enumeration is deterministic across runs', () => {
  const model = hand(['a', 'b', 'c', 't'], [['root', 'a'], ['root', 'b'], ['a', 'c'], ['b', 'c'], ['c', 't'], ['a', 't'], ['b', 't']]);
  assert.deepEqual(exposurePaths(model, 't'), exposurePaths(model, 't'));
});

test('exposure paths: duplicated edges do not duplicate paths', () => {
  const edges = [['root', 'a'], ['root', 'a'], ['a', 't'], ['a', 't']];
  assert.deepEqual(exposurePaths(hand(['a', 't'], edges), 't'), [['root', 'a', 't']]);
});

test('exposure paths: a dead-branch combinatorial graph stays linear', () => {
  // 40-layer ladder (each layer fully linked to the next) plus the target on
  // its own chain: dead prefixes used to multiply without bound.
  const layers = 40;
  const ids = [];
  const edges = [];
  const lvls = [['root']];
  for (let l = 0; l < layers; l++) {
    const lvl = [0, 1, 2].map(i => `n${l}-${i}`);
    lvls.push(lvl);
    ids.push(...lvl);
  }
  for (let l = 0; l < layers; l++) {
    for (const a of lvls[l]) for (const b of lvls[l + 1]) edges.push([a, b]);
  }
  ids.push('mid', 't');
  edges.push(['root', 'mid'], ['mid', 't']);
  const paths = exposurePaths(hand(ids, edges), 't');
  assert.deepEqual(paths, [['root', 'mid', 't']]);
});

test('exposure paths: every path strictly descends one depth level per step', () => {
  const model = hand(['a', 'b', 'c', 't'], [['root', 'a'], ['root', 'b'], ['a', 'c'], ['b', 'c'], ['c', 't'], ['a', 't'], ['b', 't']]);
  for (const path of exposurePaths(model, 't')) {
    for (let i = 0; i < path.length; i++) {
      assert.equal(analyze(model).depths.get(path[i]), i, `${path} step ${i}`);
    }
  }
});

/* ---------- dependents ---------- */

test('dependents: lifecycle snapshot-codec direct and transitive sets', () => {
  const { direct, transitive } = dependents(loadPreset('lifecycle'), 'npm:node_modules/snapshot-codec');
  assert.deepEqual(direct.map(item => item.id), ['npm:node_modules/render-adapter']);
  assert.equal(transitive.length, 4);
  assert.deepEqual(transitive.map(item => item.id), [
    'npm:node_modules/print-layout', 'npm:node_modules/render-adapter',
    'npm:node_modules/report-kit', 'npm:node_modules/ui-gateway',
  ]);
});

test('dependents: a leaf has one direct dependent chain upward', () => {
  const { direct, transitive } = dependents(loadPreset('lifecycle'), 'npm:node_modules/text-frame');
  assert.deepEqual(direct.map(item => item.id), ['npm:node_modules/snapshot-codec']);
  assert.equal(transitive.length, 5);
});

test('dependents: the virtual root is excluded from both sets', () => {
  const { direct, transitive } = dependents(loadPreset('baseline'), 'npm:node_modules/ui-gateway');
  assert.ok(!direct.some(item => item.id === 'root'));
  assert.ok(!transitive.some(item => item.id === 'root'));
});

test('dependents: unresolved references are excluded from transitive', () => {
  const model = lock(npm({
    '': { dependencies: { app: '1.0.0' } },
    'node_modules/app': { version: '1.0.0', dependencies: { ghost: '1.0.0' } },
  }));
  const missing = model.nodes.find(node => node.unresolved);
  const { transitive } = dependents(model, missing.id);
  assert.ok(transitive.every(item => !item.id.startsWith('missing:')));
});

/* ---------- blastRadius ---------- */

test('blast radius: quarantining snapshot-codec clears the whole lifecycle score', () => {
  const report = blastRadius(loadPreset('lifecycle'), 'npm:node_modules/snapshot-codec');
  assert.equal(report.score.before, 72);
  assert.equal(report.score.after, 0);
  assert.equal(report.score.delta, 72);
  assert.deepEqual(report.orphaned.map(item => item.id), ['npm:node_modules/text-frame']);
  assert.equal(report.directDependents.length, 1);
  assert.equal(report.transitiveDependents.length, 4);
  assert.equal(report.findings.cleared, 4);
  assert.ok(report.cleared.some(item => item.ruleId === 'SG004'));
});

test('blast radius: quarantining render-adapter orphans the whole subtree', () => {
  const report = blastRadius(loadPreset('lifecycle'), 'npm:node_modules/render-adapter');
  const orphans = report.orphaned.map(item => item.id);
  assert.ok(orphans.includes('npm:node_modules/snapshot-codec'));
  assert.ok(orphans.includes('npm:node_modules/text-frame'));
  assert.equal(report.score.after, 0);
});

test('blast radius: scope adapter quarantine clears all high findings', () => {
  const report = blastRadius(loadPreset('scope'), 'npm:node_modules/@signaldesk/render');
  assert.equal(report.score.before, 89);
  assert.equal(report.score.after, 0);
  assert.ok(report.cleared.some(item => item.ruleId === 'SG012' && item.severity === 'high'));
});

test('blast radius: a root-level entry has no dependents; orphans are exclusive to it', () => {
  // snapshot-codec stays reachable via report-kit, so the score does not move;
  // only react, whose sole path ran through ui-gateway, is orphaned.
  const report = blastRadius(loadPreset('lifecycle'), 'npm:node_modules/ui-gateway');
  assert.equal(report.directDependents.length, 0);
  assert.equal(report.transitiveDependents.length, 0);
  assert.equal(report.score.delta, 0);
  assert.deepEqual(report.orphaned.map(item => item.name), ['react']);
});

test('blast radius: baseline quarantine changes nothing', () => {
  const report = blastRadius(loadPreset('baseline'), 'npm:node_modules/lodash');
  assert.equal(report.score.delta, 0);
  assert.equal(report.findings.cleared, 0);
});

test('blast radius: report exposes named exposure paths', () => {
  const report = blastRadius(loadPreset('lifecycle'), 'npm:node_modules/snapshot-codec');
  assert.equal(report.paths.length, 1);
  assert.deepEqual(report.paths[0].map(item => item.name), ['Signal Desk', 'ui-gateway', 'render-adapter', 'snapshot-codec']);
});

test('blast radius: rejects root, unknown, and already-quarantined targets', () => {
  const model = loadPreset('lifecycle');
  assert.throws(() => blastRadius(model, 'root'), /root/);
  assert.throws(() => blastRadius(model, 'npm:node_modules/ghost'), /Unknown/);
  const quar = simulate(model, new Map([['npm:node_modules/snapshot-codec', { action: 'quarantine' }]]));
  assert.throws(() => blastRadius(quar, 'npm:node_modules/snapshot-codec'), /already quarantined/);
});

test('blast radius: extra staged changes compose with the target quarantine', () => {
  const model = loadPreset('lifecycle');
  const report = blastRadius(model, 'npm:node_modules/text-frame',
    new Map([['npm:node_modules/snapshot-codec', { action: 'quarantine' }]]));
  assert.equal(report.score.after, 0);
});

test('blast radius: repeated runs on the same model agree', () => {
  const model = loadPreset('scope');
  const a = blastRadius(model, 'npm:node_modules/@signaldesk/render');
  const b = blastRadius(model, 'npm:node_modules/@signaldesk/render');
  assert.equal(a.score.after, b.score.after);
  assert.deepEqual(a.orphaned, b.orphaned);
});

/* ---------- whatIf ---------- */

test('whatIf: pinning the scope adapter reports the exact score delta', () => {
  const model = loadPreset('scope');
  const { base, simulated, delta } = whatIf(model, new Map([['npm:node_modules/@signaldesk/render', { action: 'pin' }]]));
  assert.equal(base.score, 89);
  assert.equal(simulated.score, 85);
  assert.equal(delta.score, -4);
  assert.equal(delta.findings, -1);
});

test('whatIf: an empty change set is a zero delta', () => {
  const { delta } = whatIf(loadPreset('lifecycle'), new Map());
  assert.equal(delta.score, 0);
  assert.equal(delta.reachable, 0);
});

test('whatIf: invalid change requests propagate the simulator error', () => {
  assert.throws(() => whatIf(loadPreset('baseline'), new Map([['root', { action: 'quarantine' }]])));
});

/* ---------- sanitizePolicy ---------- */

test('sanitizePolicy: absent input yields the defaults', () => {
  assert.deepEqual(sanitizePolicy(), DEFAULT_POLICY);
  assert.deepEqual(sanitizePolicy(null), DEFAULT_POLICY);
  assert.deepEqual(sanitizePolicy('junk'), DEFAULT_POLICY);
});

for (const [key, bad, fallback] of [
  ['installScripts', 'nope', 'block'], ['installScripts', 5, 'block'],
  ['typosquat', 'blocker', 'warn'], ['unpinned', null, 'warn'],
  ['severityCeiling', 'extreme', 'high'], ['severityCeiling', 0, 'high'],
]) {
  test(`sanitizePolicy: invalid ${key} ${JSON.stringify(bad)} falls back to ${fallback}`, () => {
    assert.equal(sanitizePolicy({ [key]: bad })[key], fallback);
  });
}

for (const [input, expected] of [[-3, 0], ['2', 0], [7, 7], [Number.MAX_SAFE_INTEGER + 1, 0], [0, 0], [100001, 100000], [250000, 100000]]) {
  test(`sanitizePolicy: typosquatMax ${input} becomes ${expected}`, () => {
    assert.equal(sanitizePolicy({ typosquatMax: input }).typosquatMax, expected);
  });
}

test('sanitizePolicy: license denylist is deduped, lowercased, and sorted', () => {
  const { licenseDeny } = sanitizePolicy({ licenseDeny: ['MIT', 'mit', 'GPL-3.0', 5, '', ' Apache-2.0 '] });
  assert.deepEqual(licenseDeny, ['apache-2.0', 'gpl-3.0', 'mit']);
});

test('constants: gate levels and ceilings stay fixed', () => {
  assert.deepEqual(GATE_LEVELS, ['off', 'warn', 'block']);
  assert.deepEqual(CEILINGS, ['off', 'high', 'medium', 'low']);
});

/* ---------- policyGate verdicts ---------- */

for (const [preset, expected] of [['lifecycle', 'BLOCK'], ['lookalikes', 'BLOCK'], ['scope', 'BLOCK'], ['baseline', 'PASS']]) {
  test(`policy gate: default verdict on ${preset} is ${expected}`, () => {
    assert.equal(policyGate(analyze(loadPreset(preset)), DEFAULT_POLICY).verdict, expected);
  });
}

test('policy gate: emits five checks in a stable order', () => {
  const { checks } = policyGate(analyze(loadPreset('lifecycle')), DEFAULT_POLICY);
  assert.deepEqual(checks.map(check => check.id),
    ['install-scripts', 'typosquat', 'unpinned', 'severity-ceiling', 'license-deny']);
});

test('policy gate: lifecycle install hooks trigger the block level', () => {
  const check = policyGate(analyze(loadPreset('lifecycle')), DEFAULT_POLICY).checks[0];
  assert.equal(check.id, 'install-scripts');
  assert.equal(check.triggered, true);
  assert.equal(check.level, 'block');
  assert.equal(check.count, 4);
});

test('policy gate: lookalikes trigger the typosquat warn level', () => {
  const check = policyGate(analyze(loadPreset('lookalikes')), DEFAULT_POLICY).checks[1];
  assert.equal(check.id, 'typosquat');
  assert.equal(check.triggered, true);
  assert.equal(check.level, 'warn');
  assert.equal(check.count, 3);
});

test('policy gate: quarantining the flagged subtree restores a PASS', () => {
  const model = simulate(loadPreset('lifecycle'),
    new Map([['npm:node_modules/render-adapter', { action: 'quarantine' }]]));
  const gate = policyGate(analyze(model), DEFAULT_POLICY);
  assert.equal(gate.verdict, 'PASS');
  assert.ok(gate.checks.every(check => !check.triggered));
});

test('policy gate: an all-off policy passes even the scope scenario', () => {
  const gate = policyGate(analyze(loadPreset('scope')), {
    installScripts: 'off', typosquat: 'off', unpinned: 'off', severityCeiling: 'off', licenseDeny: [],
  });
  assert.equal(gate.verdict, 'PASS');
});

const hookModel = () => {
  const model = lock(npm({
    '': { dependencies: { hooky: '1.0.0' } },
    'node_modules/hooky': { version: '1.0.0', hasInstallScript: true },
  }));
  return analyze(model);
};

for (const [level, expected] of [['warn', 'WARN'], ['block', 'BLOCK'], ['off', 'PASS']]) {
  test(`policy gate: install scripts at ${level} yields ${expected}`, () => {
    const gate = policyGate(hookModel(), { ...DEFAULT_POLICY, installScripts: level, severityCeiling: 'off' });
    assert.equal(gate.verdict, expected);
  });
}

test('policy gate: a low hook finding respects ceilings while a medium one blocks', () => {
  // SG003 is low and SG007 is medium in this fixture.
  assert.equal(policyGate(hookModel(), { ...DEFAULT_POLICY, installScripts: 'off', severityCeiling: 'high' }).verdict, 'PASS');
  assert.equal(policyGate(hookModel(), { ...DEFAULT_POLICY, installScripts: 'off', severityCeiling: 'low' }).verdict, 'BLOCK');
  assert.equal(policyGate(hookModel(), { ...DEFAULT_POLICY, installScripts: 'off', severityCeiling: 'medium' }).verdict, 'BLOCK');
});

test('policy gate: a medium finding crosses a medium ceiling', () => {
  const analysis = analyze(lock(npm({
    '': { dependencies: { recat: '18.3.1' } },
    'node_modules/recat': { version: '18.3.1' },
  })));
  assert.equal(analysis.findings.some(f => f.ruleId === 'SG001' && f.severity === 'medium'), true);
  assert.equal(policyGate(analysis, { ...DEFAULT_POLICY, severityCeiling: 'medium' }).verdict, 'BLOCK');
  assert.equal(policyGate(analysis, { ...DEFAULT_POLICY, severityCeiling: 'high' }).verdict, 'WARN');
});

for (const [max, expected] of [[0, true], [1, true], [2, false], [5, false]]) {
  test(`policy gate: typosquat ceiling ${max} against 2 findings triggers=${expected}`, () => {
    const analysis = analyze(lock(npm({
      '': { dependencies: { recat: '1.0.0', axips: '1.0.0' } },
      'node_modules/recat': { version: '1.0.0' }, 'node_modules/axips': { version: '1.0.0' },
    })));
    const gate = policyGate(analysis, { ...DEFAULT_POLICY, typosquat: 'warn', typosquatMax: max, severityCeiling: 'off' });
    const check = gate.checks.find(item => item.id === 'typosquat');
    assert.equal(check.count, 2);
    assert.equal(check.triggered, expected);
    assert.equal(gate.verdict, expected ? 'WARN' : 'PASS');
  });
}

test('policy gate: unpinned declarations honor the configured level and ceiling', () => {
  const analysis = analyze(lock(npm({
    '': { dependencies: { lodash: '^4.0.0' } },
    'node_modules/lodash': { version: '4.17.21' },
  })));
  assert.equal(analysis.findings.filter(f => f.ruleId === 'SG009').length, 1);
  assert.equal(policyGate(analysis, { ...DEFAULT_POLICY, unpinned: 'warn', unpinnedMax: 0, severityCeiling: 'off' }).verdict, 'WARN');
  assert.equal(policyGate(analysis, { ...DEFAULT_POLICY, unpinned: 'block', unpinnedMax: 0, severityCeiling: 'off' }).verdict, 'BLOCK');
  assert.equal(policyGate(analysis, { ...DEFAULT_POLICY, unpinned: 'warn', unpinnedMax: 3, severityCeiling: 'off' }).verdict, 'PASS');
});

test('policy gate: license denylist blocks matching SBOM components', () => {
  const analysis = analyze(sbom(cdx([
    { name: 'left-pad', type: 'library', 'bom-ref': 'a', licenses: [{ license: { id: 'GPL-3.0-only' } }] },
    { name: 'right-pad', type: 'library', 'bom-ref': 'b', licenses: [{ license: { id: 'MIT' } }] },
  ])));
  const gate = policyGate(analysis, { ...DEFAULT_POLICY, licenseDeny: ['gpl-3.0-only'] });
  const check = gate.checks.find(item => item.id === 'license-deny');
  assert.equal(check.triggered, true);
  assert.deepEqual(check.matches.map(item => item.name), ['left-pad']);
  assert.equal(check.coverage.recorded, 2);
  assert.equal(gate.verdict, 'BLOCK');
});

test('policy gate: license denylist is case-insensitive and passes clean sets', () => {
  const analysis = analyze(sbom(cdx([
    { name: 'left-pad', type: 'library', 'bom-ref': 'a', licenses: [{ license: { name: 'MIT' } }] },
  ])));
  assert.equal(policyGate(analysis, { ...DEFAULT_POLICY, licenseDeny: ['MIT'] }).verdict, 'BLOCK');
  assert.equal(policyGate(analysis, { ...DEFAULT_POLICY, licenseDeny: ['Apache-2.0'] }).verdict, 'PASS');
});

test('policy gate: a deny entry matches a license token inside an SPDX expression', () => {
  const analysis = analyze(sbom(cdx([
    { name: 'dual', type: 'library', 'bom-ref': 'a', licenses: [{ expression: 'MIT OR Apache-2.0' }] },
  ])));
  assert.equal(analysis.model.nodes[1].licenses[0], 'MIT OR Apache-2.0');
  const hit = policyGate(analysis, { ...DEFAULT_POLICY, licenseDeny: ['apache-2.0'] });
  assert.equal(hit.checks.find(item => item.id === 'license-deny').triggered, true);
  assert.equal(hit.verdict, 'BLOCK');
  const miss = policyGate(analysis, { ...DEFAULT_POLICY, licenseDeny: ['gpl-3.0-only'] });
  assert.equal(miss.checks.find(item => item.id === 'license-deny').triggered, false);
});

test('policy gate: hyphenated SPDX ids like -or-later match the denylist whole', () => {
  const analysis = analyze(sbom(cdx([
    { name: 'late', type: 'library', 'bom-ref': 'a', licenses: [{ license: { id: 'GPL-3.0-or-later' } }] },
    { name: 'exc', type: 'library', 'bom-ref': 'b', licenses: [{ license: { id: 'GPL-2.0-with-classpath-exception' } }] },
  ])));
  const gate = policyGate(analysis, { ...DEFAULT_POLICY, licenseDeny: ['gpl-3.0-or-later', 'gpl-2.0-with-classpath-exception'] });
  const check = gate.checks.find(item => item.id === 'license-deny');
  assert.equal(check.triggered, true);
  assert.equal(check.count, 2);
});

test('policy gate: SPDX exceptions and parenthesized expressions are tokenized', () => {
  const analysis = analyze(sbom(cdx([
    { name: 'exc', type: 'library', 'bom-ref': 'a', licenses: [{ expression: 'Apache-2.0 WITH LLVM-exception' }] },
    { name: 'grp', type: 'library', 'bom-ref': 'b', licenses: [{ expression: '(MIT OR GPL-3.0-only) AND BSD-2-Clause' }] },
  ])));
  const gate = policyGate(analysis, { ...DEFAULT_POLICY, licenseDeny: ['llvm-exception', 'gpl-3.0-only'] });
  const check = gate.checks.find(item => item.id === 'license-deny');
  assert.equal(check.triggered, true);
  assert.equal(check.count, 2);
});

test('policy gate: an operator glued to a parenthesis still tokenizes', () => {
  const analysis = analyze(sbom(cdx([
    { name: 'glued', type: 'library', 'bom-ref': 'a', licenses: [{ expression: 'GPL-3.0-only OR(MIT)' }] },
  ])));
  const gate = policyGate(analysis, { ...DEFAULT_POLICY, licenseDeny: ['gpl-3.0-only'] });
  assert.equal(gate.checks.find(item => item.id === 'license-deny').triggered, true);
});

test('CycloneDX: malformed license entries sanitize instead of rejecting the file', () => {
  const analysis = analyze(sbom(cdx([
    { name: 'soft', type: 'library', 'bom-ref': 'a', licenses: [
      { license: { name: 'Custom\nLicense\tName' } },
      { license: { name: 'x'.repeat(500) } },
      { license: { url: 'https://example.com/license' } },
      'bare-string',
      { license: { id: 'GPL-3.0-only' } },
    ] },
  ])));
  const licenses = analysis.model.nodes[1].licenses;
  assert.equal(licenses.includes('GPL-3.0-only'), true);
  assert.equal(licenses.some(v => v.includes('\n')), false);
});

test('policy gate: a denied id at the end of a long license expression still blocks', () => {
  const long = `MIT OR ${'Apache-2.0 OR '.repeat(300)}GPL-3.0-only`;
  assert.ok(long.length > 4096);
  const analysis = analyze(sbom(cdx([
    { name: 'soft', type: 'library', 'bom-ref': 'a', licenses: [{ expression: long }] },
  ])));
  const gate = policyGate(analysis, { ...DEFAULT_POLICY, licenseDeny: ['gpl-3.0-only'] });
  assert.equal(gate.verdict, 'BLOCK');
});

test('CycloneDX: a license object with a null id falls back to the name', () => {
  const analysis = analyze(sbom(cdx([
    { name: 'soft', type: 'library', 'bom-ref': 'a', licenses: [{ license: { id: null, name: 'GPL-3.0-only' } }] },
  ])));
  assert.deepEqual(analysis.model.nodes[1].licenses, ['GPL-3.0-only']);
});

test('policy gate: a ~1MB license expression with heavy space runs stays fast and still blocks', () => {
  const long = 'MIT ' + ' '.repeat(500) + 'OR ' + 'x'.repeat(1200000) + ' AND GPL-3.0-only';
  assert.ok(long.length > 1000000);
  const start = Date.now();
  const analysis = analyze(sbom(cdx([
    { name: 'soft', type: 'library', 'bom-ref': 'a', licenses: [{ expression: long }] },
  ])));
  const gate = policyGate(analysis, { ...DEFAULT_POLICY, licenseDeny: ['gpl-3.0-only'] });
  assert.equal(gate.verdict, 'BLOCK');
  assert.ok(Date.now() - start < 5000, 'parse + gate over 1MB license took ' + (Date.now() - start) + 'ms');
});

test('policy gate: a license expression of paren runs stays linear and still blocks', () => {
  const long = '('.repeat(100000) + 'GPL-3.0-only' + ')'.repeat(100000);
  const analysis = analyze(sbom(cdx([
    { name: 'soft', type: 'library', 'bom-ref': 'a', licenses: [{ expression: long }] },
  ])));
  const start = Date.now();
  const gate = policyGate(analysis, { ...DEFAULT_POLICY, licenseDeny: ['gpl-3.0-only'] });
  assert.equal(gate.verdict, 'BLOCK');
  assert.ok(Date.now() - start < 1000, 'paren-run gate took ' + (Date.now() - start) + 'ms');
});

test('requirements: lines padded with huge space runs stay linear', () => {
  const padded = 'requests ==' + ' '.repeat(8000) + '2.0';
  const text = (padded + '\n').repeat(200) + 'flask==3.0\n';
  const start = Date.now();
  const analysis = analyze(parseInput(text, 'requirements.txt'));
  assert.equal(analysis.model.nodes.length, 202);
  assert.ok(Date.now() - start < 5000, 'space-run import took ' + (Date.now() - start) + 'ms');
});

test('CycloneDX: a null expression falls back to the license object', () => {
  const analysis = analyze(sbom(cdx([
    { name: 'soft', type: 'library', 'bom-ref': 'a', licenses: [{ expression: null, license: { id: 'GPL-3.0-only' } }] },
  ])));
  assert.deepEqual(analysis.model.nodes[1].licenses, ['GPL-3.0-only']);
});

test('policy gate: license check reports zero coverage on npm inputs', () => {
  const gate = policyGate(analyze(loadPreset('lifecycle')), { ...DEFAULT_POLICY, licenseDeny: ['mit'] });
  const check = gate.checks.find(item => item.id === 'license-deny');
  assert.equal(check.coverage.recorded, 0);
  assert.equal(check.triggered, false);
});

test('policy gate: unreachable findings do not count', () => {
  const model = hand(['a'], [['root', 'a']], { a: { hasInstallScript: true } });
  model.edges = [];
  const gate = policyGate(analyze(model), DEFAULT_POLICY);
  assert.equal(gate.scope, 'reachable findings only');
  assert.equal(gate.checks[0].triggered, false);
});

test('policy gate: same analysis and policy always produce the same verdict', () => {
  const analysis = analyze(loadPreset('scope'));
  const first = policyGate(analysis, DEFAULT_POLICY);
  const second = policyGate(analysis, DEFAULT_POLICY);
  assert.equal(first.verdict, second.verdict);
  assert.equal(canonicalJson(first.checks), canonicalJson(second.checks));
});

test('policy gate: a warn and a block together still resolve to BLOCK', () => {
  const analysis = analyze(loadPreset('lifecycle'));
  const gate = policyGate(analysis, { ...DEFAULT_POLICY, typosquat: 'warn', typosquatMax: 0, installScripts: 'block' });
  assert.equal(gate.verdict, 'BLOCK');
});

/* ---------- CycloneDX license parsing ---------- */

test('CycloneDX license records parse ids, names, and expressions', () => {
  const parsed = sbom(cdx([
    { name: 'a', type: 'library', 'bom-ref': 'a', licenses: [{ license: { id: 'MIT' } }, { license: { name: 'Apache 2' } }, { expression: 'MIT OR X' }] },
  ]));
  assert.deepEqual(parsed.nodes[1].licenses, ['MIT', 'Apache 2', 'MIT OR X']);
});

for (const [label, licenses] of [
  ['a bare string', ['MIT']],
  ['a null license object', [{ license: null }]],
  ['an empty license record', [{}]],
  ['a non-array value', 'MIT'],
]) {
  test(`CycloneDX skips malformed license entry: ${label}`, () => {
    const parsed = sbom(cdx([
      { name: 'a', type: 'library', 'bom-ref': 'a', licenses },
      { name: 'b', type: 'library', 'bom-ref': 'b', licenses: [{ license: { id: 'MIT' } }] },
    ]));
    assert.deepEqual(parsed.nodes.find(item => item.name === 'a').licenses, []);
    assert.deepEqual(parsed.nodes.find(item => item.name === 'b').licenses, ['MIT']);
  });
}

test('CycloneDX keeps license data through export-facing model fields', () => {
  const parsed = sbom(cdx([
    { name: 'a', type: 'library', 'bom-ref': 'a', licenses: [{ license: { id: 'MIT' } }] },
  ]));
  const node = parsed.nodes.find(item => item.name === 'a');
  assert.ok(Array.isArray(node.licenses) && node.licenses.length === 1);
});
