import { compare } from './graph.js';
import { RULES, sourceHost, sriHashes } from './detectors.js';

export const sha256 = async text => Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',
  typeof text === 'string' ? new TextEncoder().encode(text) : text)), byte => byte.toString(16).padStart(2, '0')).join('');

export function canonicalJson(value) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean' ||
      (typeof value === 'number' && Number.isFinite(value))) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort(compare).map(key => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  throw new TypeError('Cannot canonicalize this value.');
}

export function csvCell(value) {
  let text = String(value ?? '');
  if (/^[\s\uFEFF\p{Cf}]*[=+\-@＝＋－＠]/u.test(text) || /^[\t\r\n]/.test(text)) text = `'${text}`;
  return `"${text.replaceAll('"', '""')}"`;
}

const json = value => `${JSON.stringify(value, null, 2)}\n`;
const validDigest = value => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value) ? value : null;
const reportNote = 'Static inventory signals for review, not verified vulnerabilities or evidence of compromise.';

function hashesFor(node) {
  const found = new Map();
  for (const item of [...node.hashes, ...sriHashes(node.integrity)]) found.set(`${item.alg}:${item.content}`, item);
  return [...found.entries()].sort((a, b) => compare(a[0], b[0])).map(([, hash]) => hash);
}

function evidenceBundle(analysis, inputFingerprint, changes) {
  const { model, score, metrics, findings, contributions } = analysis;
  const byId = new Map((Array.isArray(model.nodes) ? model.nodes : []).map(node => [node.id, node]));
  const nodes = (Array.isArray(model.nodes) ? model.nodes : []).map(node => ({
    id: node.id, name: node.name, version: node.version, ecosystem: node.ecosystem, location: node.location,
    recordedHost: sourceHost(node.resolved), hashes: hashesFor(node), root: Boolean(node.root),
    unresolved: Boolean(node.unresolved), quarantined: Boolean(node.quarantined),
    ...(node.marker ? { marker: node.marker } : {}),
  })).sort((a, b) => compare(a.id, b.id));
  const edges = (Array.isArray(model.edges) ? model.edges : []).map(({ from, to, name, spec, kind }) =>
    ({ from, to, name, spec: /:\/\/|^(?:git(?:\+|@)|file:|link:)/i.test(spec) ? '[direct source omitted]' : spec, kind }))
    .sort((a, b) => compare(canonicalJson(a), canonicalJson(b)));
  return {
    version: 1, format: model.format, source: model.source, sourceKind: model.sourceKind,
    scenario: model.scenario ?? null, rootId: model.rootId,
    inputSha256: validDigest(inputFingerprint),
    notes: [reportNote, ...(Array.isArray(model.notes) ? model.notes : [])],
    score, metrics, findings, contributions, nodes, edges,
    changes: [...(changes ?? [])].flatMap(([nodeId, change]) => {
      if (!change || typeof change !== 'object' || typeof change.action !== 'string') return [];
      const version = typeof change.version === 'string' && change.version ? change.version
        : change.action === 'pin' ? byId.get(nodeId)?.version : undefined;
      return [{
        nodeId, action: change.action, ...(version ? { version } : {}),
        ...(typeof change.integrity === 'string' && change.integrity ? { hashes: sriHashes(change.integrity) } : {}),
      }];
    }).sort((a, b) => compare(a.nodeId, b.nodeId)),
  };
}

function sarif(analysis, bundle, fingerprint) {
  const { model, findings } = analysis;
  const byId = new Map(model.nodes.map(node => [node.id, node]));
  const ids = Object.keys(RULES).sort(compare);
  const results = findings.map(finding => {
    const node = byId.get(finding.nodeId);
    return {
      ruleId: finding.ruleId, ruleIndex: ids.indexOf(finding.ruleId), level: { high: 'error', medium: 'warning', low: 'note' }[finding.severity],
      message: { text: `${finding.title}. ${finding.evidence}` },
      locations: [{
        physicalLocation: {
          artifactLocation: { uri: encodeURIComponent(model.source) },
          ...(node.line ? { region: { startLine: node.line } } : {}),
        },
        logicalLocations: [{ name: node.name, fullyQualifiedName: node.id, kind: 'package' }],
      }],
      properties: {
        evidenceLocation: node.location, version: node.version, affected: finding.affected,
        path: finding.path ?? [], scorePoints: finding.points, reachable: finding.reachable,
        recommendation: finding.recommendation,
      },
    };
  });
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json', version: '2.1.0',
    runs: [{
      tool: { driver: {
        name: 'SupplyGuard', semanticVersion: '1.0.0',
        rules: ids.map(id => {
          const [title, severity, weight, help] = RULES[id];
          return {
            id, name: title.replace(/[^a-zA-Z0-9 ]/g, '').split(' ').map(word => word.charAt(0).toUpperCase() + word.slice(1)).join(''),
            shortDescription: { text: title }, help: { text: help }, properties: { severity, weight },
          };
        }),
      } },
      results,
      properties: {
        reportDescription: reportNote, auditSha256: fingerprint, score: bundle.score,
        sourceKind: bundle.sourceKind, ...(bundle.inputSha256 ? { inputSha256: bundle.inputSha256 } : {}),
      },
    }],
  };
}

function cyclonedx(analysis, bundle, fingerprint) {
  const { model } = analysis;
  const active = model.nodes.filter(node => !node.quarantined && !node.unresolved);
  const ref = new Map(active.map((node, i) => [node.id, `supplyguard:${i}`]));
  const root = active.find(node => node.id === model.rootId);
  const property = (name, value) => ({ name: `supplyguard:${name}`, value: String(value) });
  function component(node) {
    const hashes = hashesFor(node);
    const name = node.ecosystem === 'pypi' ? node.name.toLowerCase().replace(/[-_.]+/g, '-') : node.name;
    const purlName = node.ecosystem === 'npm' ? name.toLowerCase() : name;
    const purl = /^(?:npm|cargo|pypi)$/.test(node.ecosystem) && node.version && /^(?:@[a-z0-9._-]+\/)?[a-z0-9._-]+$/i.test(purlName)
      ? `pkg:${node.ecosystem}/${purlName.split('/').map(encodeURIComponent).join('/')}@${encodeURIComponent(node.version)}` : '';
    return {
      type: node.componentType ?? (node.root ? 'application' : 'library'), 'bom-ref': ref.get(node.id), name: node.name,
      ...(node.version ? { version: node.version } : {}), ...(hashes.length ? { hashes } : {}),
      ...(purl ? { purl } : {}),
    };
  }
  const outbound = new Map(active.map(node => [node.id, new Set()]));
  for (const { from, to } of model.edges) {
    if (ref.has(from) && ref.has(to)) outbound.get(from).add(ref.get(to));
  }
  return {
    $schema: 'http://cyclonedx.org/schema/bom-1.5.schema.json', bomFormat: 'CycloneDX', specVersion: '1.5', version: 1,
    metadata: {
      component: component(root),
      tools: [{ name: 'SupplyGuard', version: '1.0.0' }],
      properties: [
        property('audit-sha256', fingerprint), property('source-kind', bundle.sourceKind), property('disclaimer', reportNote),
        ...(bundle.inputSha256 ? [property('input-sha256', bundle.inputSha256)] : []),
      ],
    },
    components: active.filter(node => node !== root).map(component),
    dependencies: active.map(node => ({ ref: ref.get(node.id), dependsOn: [...outbound.get(node.id)].sort(compare) })),
    vulnerabilities: analysis.findings.filter(finding => ref.has(finding.nodeId)).map((finding, index) => ({
      'bom-ref': `supplyguard:annotation:${index}`,
      id: finding.ruleId, source: { name: 'SupplyGuard local static rule' },
      ratings: [{ severity: finding.severity }],
      description: `${finding.title}. ${finding.evidence} ${reportNote}`,
      recommendation: finding.recommendation,
      analysis: { state: 'in_triage' },
      affects: [{ ref: ref.get(finding.nodeId) }],
    })),
  };
}

function csv(bundle, fingerprint) {
  const byId = new Map(bundle.nodes.map(node => [node.id, node]));
  const rows = [
    ['rule', 'severity', 'component', 'version', 'depth', 'reachable', 'affected_dependents', 'risk_points', 'path', 'evidence',
      'input_sha256', 'audit_sha256'],
    ...bundle.findings.map(item => [
      item.ruleId, item.severity, byId.get(item.nodeId).name, byId.get(item.nodeId).version, item.depth,
      item.reachable, item.affected.length, item.points, item.path?.map(id => byId.get(id).name).join(' > '), item.evidence,
      bundle.inputSha256, fingerprint,
    ]),
  ];
  return `${rows.map(row => row.map(csvCell).join(',')).join('\r\n')}\r\n`;
}

export async function makeExport(kind, analysis, { inputFingerprint, changes } = {}) {
  if (!['sarif', 'cyclonedx', 'csv', 'audit'].includes(kind)) throw new Error('Unknown export kind.');
  // Capture the entire export synchronously before waiting for its digest.
  const bundle = evidenceBundle(analysis, inputFingerprint, changes);
  const fingerprint = await sha256(canonicalJson(bundle));
  const [text, filename, mime] = {
    sarif: () => [json(sarif(analysis, bundle, fingerprint)), 'supplyguard.sarif', 'application/sarif+json'],
    cyclonedx: () => [json(cyclonedx(analysis, bundle, fingerprint)), 'supplyguard.cdx.json', 'application/vnd.cyclonedx+json'],
    csv: () => [csv(bundle, fingerprint), 'supplyguard.csv', 'text/csv;charset=utf-8'],
    audit: () => [`${canonicalJson({ auditSha256: fingerprint, evidence: bundle })}\n`, 'supplyguard.audit.json', 'application/json'],
  }[kind]();
  return { text, filename, mime, fingerprint, sha256: await sha256(text) };
}
