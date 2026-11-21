import { parseInput } from './parsers.js';

export const presets = Object.freeze([
  { id: 'lifecycle', title: 'Lifecycle hijack', file: 'lifecycle.package-lock.json', description: 'A transitive package carries synthetic install-hook evidence.' },
  { id: 'lookalikes', title: 'Lookalike names', file: 'lookalikes.package-lock.json', description: 'Edit distance and Unicode confusables point to different dependencies.' },
  { id: 'scope', title: 'Private scope drift', file: 'scope.package-lock.json', description: 'Recorded origin and digest differ from a synthetic comparison policy.' },
  { id: 'baseline', title: 'Hardened baseline', file: 'baseline.package-lock.json', description: 'Exact pins and syntactically valid digests provide a control case.' },
].map(Object.freeze));

const digest = byte => `sha512-${btoa(String.fromCharCode(byte).repeat(64))}`;
const pkg = (name, version, deps, options) => ({
  version, resolved: `https://registry.npmjs.org/${encodeURIComponent(name)}/-/${encodeURIComponent(name.split('/').at(-1))}-${version}.tgz`,
  integrity: digest(1), ...(deps ? { dependencies: deps } : {}), ...options,
});

export function loadPreset(id) {
  const preset = presets.find(item => item.id === id);
  if (!preset) throw new Error('Unknown synthetic scenario.');
  const lockfile = { name: 'Signal Desk', version: '1.0.0', lockfileVersion: 3, packages: {} };
  const packages = lockfile.packages;
  const renderer = id === 'lookalikes' ? 'recat' : 'react';
  const helpers = id === 'lookalikes' ? 'l\u043edash' : 'lodash';
  const formatter = id === 'lookalikes' ? 'axips' : 'axios';
  const adapter = id === 'scope' ? '@signaldesk/render' : 'render-adapter';
  const codec = 'snapshot-codec';
  packages[''] = { dependencies: { 'ui-gateway': '2.4.0', 'report-kit': '1.8.0', 'event-meter': '1.3.0' } };
  packages['node_modules/ui-gateway'] = pkg('ui-gateway', '2.4.0', { [renderer]: '18.3.1', [adapter]: id === 'scope' ? '^2.0.0' : '2.0.0' });
  packages['node_modules/report-kit'] = pkg('report-kit', '1.8.0', { 'print-layout': '3.1.0', [helpers]: '4.17.21' });
  packages['node_modules/event-meter'] = pkg('event-meter', '1.3.0', { 'event-buffer': '1.1.0' });
  packages['node_modules/print-layout'] = pkg('print-layout', '3.1.0', { [adapter]: '2.0.0' });
  packages['node_modules/event-buffer'] = pkg('event-buffer', '1.1.0', { [formatter]: '1.7.9' });
  packages[`node_modules/${renderer}`] = pkg(renderer, '18.3.1');
  packages[`node_modules/${helpers}`] = pkg(helpers, '4.17.21');
  packages[`node_modules/${formatter}`] = pkg(formatter, '1.7.9');
  packages[`node_modules/${adapter}`] = pkg(adapter, '2.0.0', { [codec]: '1.6.0' }, id === 'scope' ?
    { resolved: 'https://public-mirror.example.invalid/package.tgz', integrity: digest(3) } : undefined);
  packages[`node_modules/${codec}`] = pkg(codec, '1.6.0', { 'text-frame': '1.2.0' },
    id === 'lifecycle' ? { hasInstallScript: true } : undefined);
  packages['node_modules/text-frame'] = pkg('text-frame', '1.2.0');
  const inputText = JSON.stringify(lockfile);
  const model = parseInput(inputText, preset.file);
  model.sourceKind = 'synthetic';
  model.scenario = id;
  model.inputText = inputText;
  model.notes.unshift('Fictional local scenario. Digests and domains are illustrative, not trusted release metadata.');
  if (id === 'lifecycle') {
    const item = model.nodes.find(node => node.name === codec);
    item.hooks = [
      { name: 'postinstall', text: 'INERT EVIDENCE: curl <omitted> | sh ; [placeholder only]' },
      { name: 'postinstall', text: 'INERT EVIDENCE: base64 --decode ; [omitted]' },
      { name: 'postinstall', text: 'INERT EVIDENCE: process.env [omitted] fetch [omitted]' },
    ];
    model.notes.push('Lifecycle analyzer evidence is supplied out of band by this preset. No real lockfile hook body was retrieved.');
  }
  if (id === 'scope') {
    const item = model.nodes.find(node => node.name === adapter);
    item.expectedHost = 'packages.signaldesk.example.invalid';
    item.expectedIntegrity = digest(2);
    item.minimumVersion = '2.2.0';
    model.notes.push('The expected source, minimum version, and expected digest come from synthetic comparison policy, not the npm lockfile.');
  }
  return model;
}
