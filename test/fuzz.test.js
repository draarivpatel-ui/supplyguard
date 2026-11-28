import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import fc from 'fast-check';
import { strictJson } from '../src/parsers.js';
import { sha256hex } from '../src/sha256.js';
import { breadthFirst, indexGraph, trace } from '../src/graph.js';
import { DEFAULT_POLICY, policyGate } from '../src/policy.js';

const key = fc.string({ minLength: 0, maxLength: 10 }).filter((value) => value !== '__proto__');
const leaf = fc.oneof(
  fc.constant(null),
  fc.boolean(),
  fc.integer({ min: -100000, max: 100000 }),
  fc.string({ maxLength: 20 })
);
const level1 = fc.oneof(leaf, fc.array(leaf, { maxLength: 3 }), fc.dictionary(key, leaf, { maxKeys: 3 }));
const level2 = fc.oneof(leaf, fc.array(level1, { maxLength: 3 }), fc.dictionary(key, level1, { maxKeys: 3 }));
const jsonValue = fc.oneof(leaf, level1, level2);

test('fast-check strictJson round-trips generated JSON and rejects reserved keys', () => {
  fc.assert(fc.property(jsonValue, (value) => {
    const text = JSON.stringify(value);
    const parsed = strictJson(text);
    assert.equal(JSON.stringify(parsed), JSON.stringify(JSON.parse(text)));
  }), { seed: 0x51E5A1, numRuns: 140 });

  fc.assert(fc.property(fc.integer({ min: 0, max: 5 }), (depth) => {
    let hostile = '{"__proto__":true}';
    for (let i = 0; i < depth; i += 1) {
      hostile = i % 2 ? `{"x":${hostile}}` : `[${hostile}]`;
    }
    assert.throws(() => strictJson(hostile), /Reserved key/);
  }), { seed: 0x51E5A2, numRuns: 40 });
});

test('fast-check SHA-256 implementation matches the Node platform digest', () => {
  const bytes = fc.array(fc.integer({ min: 0, max: 255 }), { maxLength: 512 });
  fc.assert(fc.property(bytes, (values) => {
    const input = Uint8Array.from(values);
    assert.equal(sha256hex(input), createHash('sha256').update(input).digest('hex'));
  }), { seed: 220505, numRuns: 120 });
});

test('fast-check breadth-first paths are valid and distances are tight', () => {
  const graphCase = fc.integer({ min: 2, max: 8 }).chain((n) => fc.tuple(
    fc.constant(n),
    fc.array(
      fc.tuple(fc.integer({ min: 0, max: n - 1 }), fc.integer({ min: 0, max: n - 1 })),
      { maxLength: 16 }
    )
  ));
  fc.assert(fc.property(graphCase, ([n, rawEdges]) => {
    const nodes = Array.from({ length: n }, (_, i) => ({ id: `n${i}` }));
    const edges = rawEdges.map(([from, to]) => ({ from: `n${from}`, to: `n${to}` }));
    const { outgoing } = indexGraph(nodes, edges);
    const start = 'n0';
    const { predecessor, depths } = breadthFirst(start, outgoing);
    const edgeSet = new Set(edges.map((edge) => JSON.stringify([edge.from, edge.to])));
    for (const node of nodes) {
      if (!depths.has(node.id)) continue;
      const path = trace(node.id, predecessor);
      assert.equal(path[0], start);
      assert.equal(path.at(-1), node.id);
      assert.equal(path.length, depths.get(node.id) + 1);
      for (let i = 1; i < path.length; i += 1) {
        assert.ok(edgeSet.has(JSON.stringify([path[i - 1], path[i]])), `path uses non-edge ${path[i - 1]}->${path[i]}`);
      }
    }
    for (const edge of edges) {
      if (!depths.has(edge.from)) continue;
      assert.ok(depths.has(edge.to), `target of ${edge.from}->${edge.to} was not reached`);
      assert.ok(depths.get(edge.to) <= depths.get(edge.from) + 1, 'BFS distance is not minimal');
    }
  }), { seed: 0xBFE57, numRuns: 130 });
});

test('fast-check policy gate ignores unreachable hook findings', () => {
  fc.assert(fc.property(
    fc.integer({ min: 0, max: 4 }),
    fc.integer({ min: 0, max: 4 }),
    (reachableCount, unreachableCount) => {
      const findings = [];
      for (let i = 0; i < reachableCount; i += 1) findings.push({ ruleId: 'SG003', severity: 'low', reachable: true });
      for (let i = 0; i < unreachableCount; i += 1) findings.push({ ruleId: 'SG003', severity: 'low', reachable: false });
      const gate = policyGate(
        { findings, model: { nodes: [] } },
        { ...DEFAULT_POLICY, installScripts: 'block', severityCeiling: 'off' }
      );
      const check = gate.checks.find((item) => item.id === 'install-scripts');
      assert.equal(check.count, reachableCount);
      assert.equal(check.triggered, reachableCount > 0);
      assert.equal(gate.verdict, reachableCount > 0 ? 'BLOCK' : 'PASS');
    }
  ), { seed: 0x6A7E, numRuns: 100 });
});
