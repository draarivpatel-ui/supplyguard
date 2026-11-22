import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import {
  attestationPayload, decodeBookmark, encodeBookmark, makeAttestation,
  runSelfTests, verifyAttestation, SELF_TEST_COUNT,
} from '../src/attest.js';
import { analyze } from '../src/detectors.js';
import { canonicalJson, csvCell, evidenceBundle, makeExport } from '../src/exports.js';
import { parseInput } from '../src/parsers.js';
import { DEFAULT_POLICY } from '../src/policy.js';
import { loadPreset } from '../src/presets.js';
import { sha256hex } from '../src/sha256.js';

const ref = data => createHash('sha256').update(data).digest('hex');
const npm = (packages, version = 3) => JSON.stringify({ lockfileVersion: version, packages: { '': {}, ...packages } });
const lifecycle = () => analyze(loadPreset('lifecycle'));

/* ---------- sha256hex: FIPS 180-4 known-answer vectors ---------- */

for (const [label, input, expected] of [
  ['abc', 'abc', 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'],
  ['empty string', '', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'],
  ['two-block NIST message', 'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq',
    '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1'],
  ['one million a characters', 'a'.repeat(1_000_000),
    'cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0'],
  ['quick brown fox', 'The quick brown fox jumps over the lazy dog',
    'd7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592'],
  ['quick brown fox with period', 'The quick brown fox jumps over the lazy dog.',
    'ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c'],
]) {
  test(`sha256hex FIPS vector: ${label}`, () => {
    assert.equal(sha256hex(input), expected);
  });
}

for (const length of [1, 55, 56, 63, 64, 65, 119, 128, 129, 1000, 8192]) {
  test(`sha256hex agrees with the reference at ${length} bytes`, () => {
    const input = 'x'.repeat(length);
    assert.equal(sha256hex(input), ref(input));
  });
}

test('sha256hex: UTF-8 strings hash their byte encoding', () => {
  for (const text of ['héllo wörld', '日本語のテキスト', 'emoji \u{1f512} inside', 'mixed ñ\u0303 sequences']) {
    assert.equal(sha256hex(text), ref(new TextEncoder().encode(text)));
  }
});

test('sha256hex: byte arrays match the string path', () => {
  const bytes = new TextEncoder().encode('attest me');
  assert.equal(sha256hex(bytes), sha256hex('attest me'));
  assert.equal(sha256hex(new Uint8Array([0, 1, 2, 255])), ref(new Uint8Array([0, 1, 2, 255])));
});

test('sha256hex: deterministic and hex-shaped', () => {
  assert.equal(sha256hex('repeat'), sha256hex('repeat'));
  assert.match(sha256hex('shape'), /^[0-9a-f]{64}$/);
});

/* ---------- canonicalJson ---------- */

test('canonicalJson: sorts object keys recursively, keeps array order', () => {
  assert.equal(canonicalJson({ b: 1, a: { d: 2, c: 3 } }), '{"a":{"c":3,"d":2},"b":1}');
  assert.equal(canonicalJson({ list: [{ z: 1, y: 2 }] }), '{"list":[{"y":2,"z":1}]}');
});

test('canonicalJson: serializes primitives like JSON.stringify', () => {
  assert.equal(canonicalJson(null), 'null');
  assert.equal(canonicalJson('x'), '"x"');
  assert.equal(canonicalJson(true), 'true');
  assert.equal(canonicalJson(4.5), '4.5');
  assert.equal(canonicalJson([1, 'a', null]), '[1,"a",null]');
});

test('canonicalJson: rejects values JSON cannot canonicalize', () => {
  for (const value of [undefined, Number.NaN, Infinity, () => {}, Symbol('s')]) {
    assert.throws(() => canonicalJson(value), /Cannot canonicalize|TypeError/);
  }
});

/* ---------- csvCell ---------- */

for (const [label, input, check] of [
  ['plain text', 'hello', '"hello"'],
  ['a formula = prefix', '=1+1', '"\'=1+1"'],
  ['a + prefix', '+cmd', '"\'+cmd"'],
  ['a - prefix', '-10', '"\'-10"'],
  ['an @ prefix', '@SUM(A1)', '"\'@SUM(A1)"'],
  ['a fullwidth formula char', '＝1+1', '"\'＝1+1"'],
  ['a leading space then =', ' =1', '"\' =1"'],
  ['a leading tab', '\tcell', '"\'\tcell"'],
  ['a leading newline', '\ncell', '"\'\ncell"'],
  ['a BOM then =', '﻿=1', '"\'﻿=1"'],
]) {
  test(`csvCell neutralizes ${label}`, () => {
    assert.equal(csvCell(input), check);
  });
}

for (const value of ['＋1', '－1', '＠x']) {
  test(`csvCell neutralizes fullwidth ${JSON.stringify(value)}`, () => {
    assert.ok(csvCell(value).startsWith('"\''));
  });
}

test('csvCell: embedded quotes are doubled and wrapped', () => {
  assert.equal(csvCell('say "hi"'), '"say ""hi"""');
  assert.equal(csvCell('"quoted"'), '"""quoted"""');
});

test('csvCell: numbers, null and undefined serialize safely', () => {
  assert.equal(csvCell(5), '"5"');
  assert.equal(csvCell(null), '""');
  assert.equal(csvCell(undefined), '""');
});

/* ---------- attestation ---------- */

test('attestationPayload: carries marker, version, tool mode, and disclaimer', () => {
  const payload = attestationPayload(lifecycle());
  assert.equal(payload.attestation, 'supplyguard-attestation');
  assert.equal(payload.version, 1);
  assert.equal(payload.tool.mode, 'offline static analysis');
  assert.match(payload.disclaimer, /not an identity signature/);
});

test('attestationPayload: embeds the evidence bundle and sanitized policy', () => {
  const payload = attestationPayload(lifecycle(), { policy: { installScripts: 'junk' } });
  assert.equal(payload.policy.installScripts, 'block');
  assert.equal(payload.evidence.version, 1);
  assert.equal(payload.evidence.score, 72);
  assert.equal(payload.gate.verdict, 'BLOCK');
  assert.equal(payload.gate.checks.length, 5);
});

test('makeAttestation: emits a digest-bearing JSON document', () => {
  const { text, filename, mime, digest, verdict } = makeAttestation(lifecycle());
  assert.equal(filename, 'supplyguard.attestation.json');
  assert.equal(mime, 'application/json');
  assert.match(digest, /^[0-9a-f]{64}$/);
  assert.equal(verdict, 'BLOCK');
  const doc = JSON.parse(text);
  assert.equal(doc.sha256, digest);
  assert.equal(doc.attestation, 'supplyguard-attestation');
});

test('makeAttestation: identical analyses produce identical digests', () => {
  assert.equal(makeAttestation(lifecycle()).digest, makeAttestation(lifecycle()).digest);
});

test('makeAttestation: a different policy changes the digest', () => {
  const base = makeAttestation(lifecycle());
  const shifted = makeAttestation(lifecycle(), { policy: { ...DEFAULT_POLICY, installScripts: 'warn' } });
  assert.notEqual(base.digest, shifted.digest);
});

test('verifyAttestation: a fresh attestation round-trips ok', () => {
  const { text, digest } = makeAttestation(lifecycle());
  const result = verifyAttestation(text);
  assert.equal(result.ok, true);
  assert.equal(result.claimed, digest);
  assert.equal(result.computed, digest);
  assert.equal(result.attestation, 'supplyguard-attestation');
  assert.equal(result.verdict, 'BLOCK');
});

for (const [label, mutate] of [
  ['the score', text => text.replace('"score":72', '"score":1')],
  ['the verdict', text => text.replace('"BLOCK"', '"PASS"')],
  ['a finding rule id', text => text.replace('SG003', 'SG999')],
]) {
  test(`verifyAttestation: tampering ${label} fails verification`, () => {
    const { text, digest } = makeAttestation(lifecycle());
    const result = verifyAttestation(mutate(text));
    assert.equal(result.ok, false);
    assert.equal(result.claimed, digest);
    assert.notEqual(result.computed, digest);
  });
}

const HEAD = '{"attestation":"supplyguard-attestation","version":1';
for (const [label, input, error] of [
  ['non-JSON text', 'not json', 'Not a JSON document.'],
  ['an array', '[1,2]', 'Not an attestation object.'],
  ['a foreign digest doc', '{"sha256":"' + '0'.repeat(64) + '"}', 'Not a SupplyGuard attestation.'],
  ['a wrong version', '{"attestation":"supplyguard-attestation","version":2}', 'Unsupported attestation version.'],
  ['a missing digest', HEAD + '}', 'No well-formed sha256 field.'],
  ['an uppercase digest', HEAD + ',"sha256":"' + 'A'.repeat(64) + '"}', 'No well-formed sha256 field.'],
  ['a short digest', HEAD + ',"sha256":"abc"}', 'No well-formed sha256 field.'],
]) {
  test(`verifyAttestation rejects ${label}`, () => {
    const result = verifyAttestation(input);
    assert.equal(result.ok, false);
    assert.equal(result.error, error);
  });
}

test('verifyAttestation: a swapped digest fails against the recomputed one', () => {
  const { text, digest } = makeAttestation(lifecycle());
  const result = verifyAttestation(text.replace(digest, 'f'.repeat(64)));
  assert.equal(result.ok, false);
  assert.equal(result.claimed, 'f'.repeat(64));
  assert.equal(result.computed, digest);
});

test('verifyAttestation: extra trailing fields still verify under canonicalization', () => {
  const { text } = makeAttestation(lifecycle());
  const doc = JSON.parse(text);
  const rebuilt = JSON.stringify({ ...doc, zz: 'extra' });
  assert.equal(verifyAttestation(rebuilt).ok, false);
});

/* ---------- bookmarks ---------- */

test('encodeBookmark/decodeBookmark round-trips every field', () => {
  const changes = new Map([
    ['npm:node_modules/snapshot-codec', { action: 'upgrade', version: '2.0.0', integrity: 'sha512-abc' }],
    ['npm:node_modules/react', { action: 'quarantine' }],
  ]);
  const encoded = encodeBookmark({
    presetId: 'lifecycle', tab: 'diff', changes,
    policy: { ...DEFAULT_POLICY, unpinned: 'block' },
    diff: { left: 'preset:baseline', right: 'preset:lifecycle' },
  });
  const decoded = decodeBookmark(`#${encoded}`);
  assert.equal(decoded.presetId, 'lifecycle');
  assert.equal(decoded.tab, 'diff');
  assert.equal(decoded.changes.size, 2);
  assert.equal(decoded.changes.get('npm:node_modules/snapshot-codec').action, 'upgrade');
  assert.equal(decoded.changes.get('npm:node_modules/snapshot-codec').version, '2.0.0');
  assert.equal(decoded.changes.get('npm:node_modules/snapshot-codec').integrity, 'sha512-abc');
  assert.equal(decoded.changes.get('npm:node_modules/react').action, 'quarantine');
  assert.equal(decoded.policy.unpinned, 'block');
  assert.deepEqual(decoded.diff, { left: 'preset:baseline', right: 'preset:lifecycle' });
});

test('encodeBookmark: a default policy is omitted from the hash', () => {
  const encoded = encodeBookmark({ presetId: 'baseline', policy: DEFAULT_POLICY });
  assert.equal(encoded.includes('pol'), false);
});

test('encodeBookmark: the default tab and empty inputs stay minimal', () => {
  const encoded = encodeBookmark({ presetId: 'scope', tab: 'policy' });
  const decoded = decodeBookmark(`#${encoded}`);
  assert.equal(decoded.presetId, 'scope');
  assert.equal(decoded.tab, undefined);
  assert.equal(decoded.changes, undefined);
  assert.equal(decoded.policy, undefined);
  assert.equal(decoded.diff, undefined);
});

test('encodeBookmark: unicode survives the round trip', () => {
  const decoded = decodeBookmark(`#${encodeBookmark({
    changes: new Map([['npm:node_modules/ünïcode', { action: 'pin', version: '1.0.0-café' }]]),
  })}`);
  assert.equal(decoded.changes.get('npm:node_modules/ünïcode').version, '1.0.0-café');
});

for (const [label, input] of [
  ['an empty hash', ''],
  ['a different fragment', '#other=abc'],
  ['a non-base64url body', '#audit=!!!'],
  ['a truncated body', '#audit=eyJ2I'],
  ['valid base64 of non-json', '#audit=' + btoa('not json').replaceAll('+', '-').replaceAll('/', '_')],
  ['base64 of a version-2 doc', '#audit=' + btoa('{"v":2}')],
  ['base64 of an array', '#audit=' + btoa('[1]')],
  ['base64 of a malformed change', '#audit=' + btoa('{"v":1,"c":[["x"]]}')],
]) {
  test(`decodeBookmark returns null for ${label}`, () => {
    assert.equal(decodeBookmark(input), null);
  });
}

test('decodeBookmark accepts the hash with or without the #', () => {
  const encoded = encodeBookmark({ presetId: 'lookalikes' });
  assert.equal(decodeBookmark(`#${encoded}`).presetId, 'lookalikes');
  assert.equal(decodeBookmark(encoded).presetId, 'lookalikes');
});

const b64url = text => btoa(text).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');

test('decodeBookmark: an overlong preset id is dropped, not fatal', () => {
  const decoded = decodeBookmark('#audit=' + b64url(JSON.stringify({ v: 1, p: 'x'.repeat(200) })));
  assert.ok(decoded);
  assert.equal(decoded.presetId, undefined);
});

test('decodeBookmark: a change entry missing an action is rejected', () => {
  const encoded = '#audit=' + b64url(JSON.stringify({ v: 1, c: [['id', { version: '1.0.0' }]] }));
  assert.equal(decodeBookmark(encoded), null);
});

/* ---------- self-tests ---------- */

test('runSelfTests: every check passes', () => {
  const results = runSelfTests();
  assert.equal(results.length, SELF_TEST_COUNT);
  const failed = results.filter(item => !item.ok);
  assert.deepEqual(failed, [], failed.map(item => `${item.id}: ${item.detail}`).join('; '));
});

test('runSelfTests: results carry unique ids and a detail line', () => {
  const results = runSelfTests();
  assert.equal(new Set(results.map(item => item.id)).size, results.length);
  for (const item of results) {
    assert.ok(item.name.length > 4 && item.detail.length > 0);
  }
});

test('runSelfTests: repeated runs return the same verdicts', () => {
  assert.deepEqual(runSelfTests().map(item => item.ok), runSelfTests().map(item => item.ok));
});

test('self-test catalog covers the required proof surface', () => {
  const ids = runSelfTests().map(item => item.id);
  for (const required of ['sha256-abc', 'sha256-empty', 'typosquat', 'bfs-cycle',
    'diff-antisymmetry', 'gate-determinism', 'csv-escape', 'attest-tamper', 'bookmark-roundtrip']) {
    assert.ok(ids.includes(required), `missing ${required}`);
  }
});

/* ---------- markdown + bundle exports ---------- */

test('markdown export: headings, verdict, metrics, and findings render', async () => {
  const analysis = lifecycle();
  const { text, filename, mime } = await makeExport('md', analysis, { gate: 'BLOCK' });
  assert.equal(filename, 'supplyguard.report.md');
  assert.equal(mime, 'text/markdown;charset=utf-8');
  assert.match(text, /^# SupplyGuard audit report/);
  assert.match(text, /Policy gate: BLOCK/);
  assert.match(text, /\| metric \| value \|/);
  assert.match(text, /SG003/);
});

test('markdown export: pipes in names are escaped; no em or en dashes ship', async () => {
  const analysis = lifecycle();
  const { text } = await makeExport('md', analysis, { gate: 'WARN' });
  assert.doesNotMatch(text, /[—–]/);
  assert.match(text, /Static inventory signals/);
  assert.match(text, /No registry, advisory feed, or network lookup/);
});

test('markdown export: gate line is omitted when no gate is passed', async () => {
  const { text } = await makeExport('md', analyze(loadPreset('baseline')), {});
  assert.equal(text.includes('Policy gate:'), false);
});

test('evidenceBundle: direct-source specs are redacted', () => {
  const model = parseInput(npm({
    '': { dependencies: { a: 'git+https://example.test/a.git' } },
    'node_modules/a': { version: '1.0.0' },
  }), 'package-lock.json');
  const bundle = evidenceBundle(analyze(model));
  const edge = bundle.edges.find(item => item.to === 'npm:node_modules/a');
  assert.equal(edge.spec, '[direct source omitted]');
});

test('evidenceBundle: nodes are sorted by id and carry reachability fields', () => {
  const bundle = evidenceBundle(analyze(loadPreset('scope')));
  const ids = bundle.nodes.map(node => node.id);
  assert.deepEqual([...ids].sort(), ids);
  assert.ok(bundle.nodes.every(node => 'quarantined' in node && 'unresolved' in node));
});

test('evidenceBundle: a malformed fingerprint records null', () => {
  const bundle = evidenceBundle(analyze(loadPreset('baseline')), 'not-a-digest');
  assert.equal(bundle.inputSha256, null);
  const good = evidenceBundle(analyze(loadPreset('baseline')), 'a'.repeat(64));
  assert.equal(good.inputSha256, 'a'.repeat(64));
});
