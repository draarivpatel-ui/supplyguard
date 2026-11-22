import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { copyFile, mkdtemp, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { SELF_TEST_COUNT } from '../src/attest.js';
import { sha256 } from '../src/exports.js';

let checks = 0;
for (const name of ['equal', 'ok', 'match', 'deepEqual', 'notEqual', 'doesNotMatch', 'strictEqual', 'notStrictEqual']) {
  const fn = assert[name];
  if (typeof fn === 'function') assert[name] = (...args) => { checks++; return fn(...args); };
}

const root = new URL('../', import.meta.url);
const assets = new Map([
  ['index.html', 'text/html'], ['favicon.svg', 'image/svg+xml'], ['styles.css', 'text/css'],
  ...['parsers', 'graph', 'detectors', 'exports', 'presets', 'viz', 'policy', 'diff', 'attest', 'sha256', 'app']
    .map(name => [`src/${name}.js`, 'text/javascript']),
]);
const server = createServer(async (req, res) => {
  const path = new URL(req.url, 'http://127.0.0.1').pathname;
  const name = path === '/supplyguard/' ? 'index.html' : path.slice('/supplyguard/'.length);
  if (!path.startsWith('/supplyguard/') || !assets.has(name)) { res.writeHead(404).end(); return; }
  try {
    const file = await readFile(new URL(name, root));
    res.writeHead(200, { 'Content-Type': assets.get(name), 'Cache-Control': 'no-store' }).end(file);
  } catch { res.writeHead(500).end(); }
});

async function until(fn, description, iterations = 100) {
  for (let i = 0; i < iterations; i++) {
    const value = await fn();
    if (value) return value;
    await delay(50);
  }
  throw new Error(`Timed out: ${description}`);
}

const scratch = await mkdtemp(join(tmpdir(), 'supplyguard-browser-'));
let chrome;
let socket;
try {
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const profile = join(scratch, 'profile');
  const binary = process.env.CHROME_PATH || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
  chrome = spawn(binary, ['--headless=new', '--mute-audio', '--no-first-run', '--disable-background-networking',
    '--disable-component-update', '--disable-extensions', '--disable-gpu', '--remote-debugging-port=0',
    `--user-data-dir=${profile}`, 'about:blank'], { stdio: 'ignore' });
  let startupError;
  chrome.on('error', error => { startupError = error; });
  const port = await until(async () => {
    if (startupError) throw startupError;
    try { return Number((await readFile(join(profile, 'DevToolsActivePort'), 'utf8')).split('\n')[0]); } catch { return 0; }
  }, 'Chrome startup', 200);
  const targets = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
  socket = new WebSocket(targets.find(item => item.type === 'page').webSocketDebuggerUrl);
  await new Promise((resolve, reject) => {
    socket.addEventListener('open', resolve, { once: true });
    socket.addEventListener('error', reject, { once: true });
  });
  const pending = new Map();
  const events = [];
  let id = 0;
  socket.addEventListener('message', event => {
    const data = JSON.parse(event.data);
    if (!data.id) { events.push(data); return; }
    const done = pending.get(data.id);
    if (done) { pending.delete(data.id); done(data); }
  });
  function call(method, params = {}) {
    return new Promise((resolve, reject) => {
      const next = ++id;
      const timeout = setTimeout(() => { pending.delete(next); reject(new Error(`CDP timed out: ${method}`)); }, 12000);
      pending.set(next, data => {
        clearTimeout(timeout);
        if (data.error) reject(new Error(`${method}: ${data.error.message}`));
        else resolve(data.result);
      });
      socket.send(JSON.stringify({ id: next, method, params }));
    });
  }
  const evaluate = async expression => {
    const reply = await call('Runtime.evaluate', { expression, returnByValue: true });
    if (reply.exceptionDetails) throw new Error(reply.exceptionDetails.exception?.description ?? reply.exceptionDetails.text);
    return reply.result.value;
  };
  const waitFor = (expression, description) => until(() => evaluate(expression), description);
  const score = expected => waitFor(`document.querySelector('#risk-score')?.textContent === '${expected}'`, `score ${expected}`);
  const dom = async (selector, action) => evaluate(`(() => { const el = document.querySelector(${JSON.stringify(selector)}); if (!el) throw new Error('Missing element'); return (${action})(el); })()`);
  async function click(selector) {
    const { x, y, hit } = await dom(selector, `el => {
      el.scrollIntoView({ block: 'nearest', inline: 'nearest' });
      const r = el.getBoundingClientRect();
      const x = (Math.max(r.left, 0) + Math.min(r.right, innerWidth)) / 2;
      const y = (Math.max(r.top, 0) + Math.min(r.bottom, innerHeight)) / 2;
      const hit = el.contains(document.elementFromPoint(x, y));
      return { x, y, hit };
    }`);
    assert.ok(hit, `Pointer cannot hit ${selector} at ${x},${y}`);
    await call('Input.dispatchMouseEvent', { type: 'mousePressed', x, y, button: 'left', clickCount: 1 });
    await call('Input.dispatchMouseEvent', { type: 'mouseReleased', x, y, button: 'left', clickCount: 1 });
  }
  async function key(value) {
    const printable = value.length === 1;
    await call('Input.dispatchKeyEvent', { type: 'keyDown', key: value, ...(printable ? { text: value } : {}) });
    await call('Input.dispatchKeyEvent', { type: 'keyUp', key: value });
  }
  const getFile = name => until(async () => {
    try { return await readFile(join(scratch, name), 'utf8'); } catch { return false; }
  }, `download ${name}`);
  async function screenshot(file) {
    if (!process.argv.includes('--capture')) return;
    await evaluate('window.scrollTo(0, 0); document.querySelector(".graph-scroll").scrollLeft = 0; document.querySelector("#inspector").scrollTop = 0;');
    await delay(260);
    const result = await call('Page.captureScreenshot', { format: 'png', captureBeyondViewport: false });
    await writeFile(join(scratch, file), Buffer.from(result.data, 'base64'));
  }
  async function importFile(file, content) {
    const path = join(scratch, file);
    await writeFile(path, content);
    const { root: documentNode } = await call('DOM.getDocument');
    const { nodeId } = await call('DOM.querySelector', { nodeId: documentNode.nodeId, selector: '#file-input' });
    await call('DOM.setFileInputFiles', { nodeId, files: [path] });
  }

  for (const method of ['Runtime.enable', 'Page.enable', 'Log.enable', 'Network.enable', 'DOM.enable']) await call(method);
  await call('Browser.setDownloadBehavior', { behavior: 'allow', downloadPath: scratch });
  await call('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-color-scheme', value: 'dark' }] });
  const presets = [['lifecycle', 72], ['lookalikes', 59], ['scope', 89], ['baseline', 0]];
  for (const [width, height, mobile] of [[1440, 900, false], [390, 844, true]]) {
    await call('Emulation.setDeviceMetricsOverride', { width, height, deviceScaleFactor: 1, mobile });
    await call('Page.navigate', { url: `${origin}/supplyguard/` });
    await score(72);
    for (const [name, expected] of presets) {
      await click(`[data-preset="${name}"]`);
      await score(expected);
      assert.ok(await evaluate('document.querySelectorAll("#graph svg [data-node]").length >= 12'), `${name} graph renders`);
      assert.equal(await evaluate('document.documentElement.scrollWidth'), width, `${name} fits at ${width}px`);
      assert.equal(await dom(`[data-preset="${name}"]`, 'el => el.getAttribute("aria-pressed")'), 'true');
    }
    if (!mobile) {
      await click('[data-preset="lifecycle"]');
      await score(72);
      await screenshot('desktop.png');
      await call('Network.emulateNetworkConditions', { offline: true, latency: 0, downloadThroughput: 0, uploadThroughput: 0 });
      const codec = '#graph [data-node="npm:node_modules/snapshot-codec"]';
      await click(codec);
      assert.match(await dom('#inspector .node-name', 'el => el.textContent'), /snapshot-codec/);
      await click('[data-remediation="quarantine"]');
      await score(0);
      assert.match(await dom('#baseline-compare', 'el => el.textContent'), /affected 4 . 0/);
      await screenshot('remediation.png');
      await click('#reset-remediation');
      await score(72);

      assert.equal(await dom('#shortcuts', 'el => el.getAttribute("aria-pressed")'), 'false');
      await evaluate('document.activeElement.blur()');
      await key('g');
      assert.notEqual(await evaluate('document.activeElement.id'), 'component-select');
      await click('#shortcuts');
      await evaluate('document.activeElement.blur()');
      await key('g');
      assert.equal(await evaluate('document.activeElement.id'), 'component-select');
      await dom('#rem-version', 'el => el.focus()');
      await key('g');
      assert.equal(await evaluate('document.activeElement.id'), 'rem-version');
      assert.equal(await dom('#rem-version', 'el => el.value'), 'g');
      await evaluate('document.activeElement.blur()');
      await key('f');
      assert.equal(await evaluate('document.activeElement.dataset.filter'), 'all');
      await click('[data-filter="high"]');
      assert.equal(await evaluate('document.querySelectorAll("#findings tbody tr").length'), 2);
      await click('[data-filter="all"]');
      await click('#findings th:nth-of-type(2) button');
      assert.equal(await dom('#findings th:nth-of-type(2)', 'el => el.getAttribute("aria-sort")'), 'ascending');

      // Accessibility regressions: visible disable reasons, roving tabindex,
      // live count, cycle-button naming, scenario labels, skip target, deselect.
      await click('#graph [data-node="root"]');
      const reasons = await evaluate('[...document.querySelectorAll("#inspector .rem-reason")].map(p => p.textContent)');
      assert.ok(reasons.length >= 3 && reasons.every(text => /root component cannot be remediated/i.test(text)),
        'disabled remediation actions show their reasons as text');
      assert.ok(await evaluate('[...document.querySelectorAll("#inspector .rem-btn:disabled[data-remediation]")].every(b => { const ref = b.getAttribute("aria-describedby"); return ref && document.getElementById(ref); })'),
        'disabled buttons reference their reason');
      assert.equal(await evaluate('document.querySelectorAll("#graph svg [data-node][tabindex=\'0\']").length'), 1,
        'graph exposes a single roving tab stop');
      await key('ArrowRight');
      assert.notEqual(await evaluate('document.activeElement.getAttribute("data-node")'), 'root',
        'arrow key moves graph focus');
      assert.equal(await evaluate('document.activeElement.tagName'), 'g');
      assert.equal(await evaluate('document.querySelectorAll("#graph svg [data-node][tabindex=\'0\']").length'), 1,
        'roving tabindex stays single');
      assert.equal(await dom('#findings-count', 'el => el.getAttribute("aria-live")'), 'polite');
      assert.equal(await dom('#theme-toggle', 'el => el.getAttribute("aria-pressed")'), null,
        'theme cycle is not announced as a binary toggle');
      assert.match(await dom('[data-preset="lifecycle"]', 'el => el.getAttribute("aria-label")'), /install-hook/);
      await evaluate('document.querySelector(".skip").click()');
      assert.equal(await evaluate('document.activeElement.id'), 'findings-heading', 'skip link lands focus');
      await evaluate('const sel = document.querySelector("#component-select"); sel.value = ""; sel.dispatchEvent(new Event("change"))');
      assert.equal(await evaluate('document.querySelectorAll("#graph svg .selected").length'), 0,
        'placeholder option clears the selection');

      for (const kind of ['sarif', 'cyclonedx', 'csv', 'audit']) await click(`[data-export="${kind}"]`);
      const audit = JSON.parse(await getFile('supplyguard.audit.json'));
      assert.match(audit.evidence.inputSha256, /^[a-f0-9]{64}$/);
      assert.equal(audit.evidence.score, 72);
      assert.ok((await getFile('supplyguard.csv')).includes(audit.auditSha256));
      assert.equal(JSON.parse(await getFile('supplyguard.sarif')).runs[0].properties.auditSha256, audit.auditSha256);
      assert.equal(JSON.parse(await getFile('supplyguard.cdx.json')).metadata.properties[0].value, audit.auditSha256);
      await rename(join(scratch, 'supplyguard.audit.json'), join(scratch, 'desktop.audit.json'));
      const pdf = await call('Page.printToPDF', { printBackground: true, preferCSSPageSize: true });
      const pages = Buffer.from(pdf.data, 'base64').toString('latin1').match(/\/Type\s*\/Page\b/g);
      assert.equal(pages?.length, 1, 'executive brief fits one page');

      // Workbench: blast-radius preview, policy gate arc, lockfile diff,
      // self-tests, signed attestation, and bookmark reload (all offline).
      await click(codec);
      await until(async () => (await evaluate('document.querySelector(".blast-stats")?.textContent ?? ""'))
        .includes('transitive dependents'), 'blast stats render');
      assert.match(await dom('.blast-stats', 'el => el.textContent'), /exposure paths1 . depth 3direct dependents1transitive dependents4/);
      await click('#blast-preview');
      await until(async () => (await evaluate('document.querySelector(".blast-delta")?.textContent ?? ""'))
        .includes('score'), 'blast report renders');
      const blast = await dom('.blast-delta', 'el => el.textContent');
      assert.match(blast, /72 . 0/, 'quarantine preview reports 72 to 0');
      assert.match(blast, /4 contributing findings cleared . 1 orphaned/);

      await click('[data-tab="policy"]');
      assert.equal(await dom('.gate-verdict', 'el => el.textContent'), 'BLOCK', 'lifecycle gate blocks');
      assert.equal(await evaluate('document.querySelectorAll("#panel-policy tr[data-check]").length'), 5, 'five gate checks');
      const gateSelect = async (id, value) => evaluate(`(() => { const s = document.querySelector('tr[data-check="${id}"] .gate-select'); if (!s) throw new Error('no gate select ${id}'); s.value = ${JSON.stringify(value)}; s.dispatchEvent(new Event('change')); return s.value; })()`);
      assert.equal(await gateSelect('severity-ceiling', 'off'), 'off');
      assert.equal(await dom('.gate-verdict', 'el => el.textContent'), 'BLOCK', 'install-script rule still blocks');
      await gateSelect('install-scripts', 'warn');
      assert.equal(await dom('.gate-verdict', 'el => el.textContent'), 'WARN', 'warned hook rule downgrades to warn');
      await gateSelect('install-scripts', 'off');
      assert.equal(await dom('.gate-verdict', 'el => el.textContent'), 'PASS', 'all-off rules pass');
      await gateSelect('install-scripts', 'block');
      assert.equal(await dom('.gate-verdict', 'el => el.textContent'), 'BLOCK', 'restored block level blocks');
      assert.equal(await dom('.gate-chip', 'el => el.textContent'), 'gate BLOCK', 'status strip mirrors the gate');

      await click('[data-tab="diff"]');
      await click('#diff-run');
      await until(async () => (await evaluate('document.querySelector(".diff-sum")?.textContent ?? ""'))
        .includes('net risk delta +72'), 'diff delta renders');
      assert.match(await dom('.diff-sum', 'el => el.textContent'), /findings 0 . 4 . reachable 11 . 11/);
      const groups = await evaluate('[...document.querySelectorAll(".diff-group h3")].map(h => h.textContent)');
      assert.deepEqual(groups, ['Added (0)', 'Removed (0)', 'Changed (0)', 'Newly introduced risk signals (4)', 'Resolved signals (0)']);
      await click('#diff-swap');
      await click('#diff-run');
      await until(async () => (await evaluate('document.querySelector(".diff-sum")?.textContent ?? ""'))
        .includes('net risk delta -72'), 'swapped diff inverts the delta');
      await click('#diff-swap');

      await click('[data-tab="verify"]');
      await click('#run-selftests');
      await until(async () => /self-tests pass/.test(await evaluate('document.querySelector(".st-count")?.textContent ?? ""')),
        'self-test summary renders');
      assert.match(await dom('.st-count', 'el => el.textContent'), new RegExp(`${SELF_TEST_COUNT} of ${SELF_TEST_COUNT} self-tests pass`));
      assert.equal(await evaluate('document.querySelectorAll(".selftest-list li").length'), SELF_TEST_COUNT);
      assert.equal(await evaluate('document.querySelectorAll(".selftest-list .st-fail").length'), 0, 'no failing self-tests');

      await click('[data-export="sign"]');
      const attestText = await getFile('supplyguard.attestation.json');
      const attestDoc = JSON.parse(attestText);
      assert.match(attestDoc.sha256, /^[0-9a-f]{64}$/);
      assert.equal(attestDoc.attestation, 'supplyguard-attestation');
      assert.equal(attestDoc.gate.verdict, 'BLOCK');
      await evaluate(`(() => { const a = document.querySelector('#attest-input'); a.value = ${JSON.stringify(attestText)}; a.dispatchEvent(new Event('input')); })()`);
      await click('#verify-attest');
      assert.match(await dom('.attest-result', 'el => el.textContent'), /^verified . gate BLOCK . sha256/, 'fresh attestation verifies in page');
      const tampered = attestText.replace('"version":1', '"version":2');
      await evaluate(`(() => { const a = document.querySelector('#attest-input'); a.value = ${JSON.stringify(tampered)}; a.dispatchEvent(new Event('input')); })()`);
      await click('#verify-attest');
      assert.match(await dom('.attest-result', 'el => el.textContent'), /^not verified:/, 'tampered attestation rejected');

      await call('Network.emulateNetworkConditions', { offline: false, latency: 0, downloadThroughput: -1, uploadThroughput: -1 });
      const hash = await evaluate('location.hash');
      assert.match(hash, /^#audit=[A-Za-z0-9_-]{4,}$/, 'bookmark hash is synced');
      await call('Page.navigate', { url: `${origin}/supplyguard/${hash}` });
      await score(72);
      assert.equal(await evaluate('location.hash.startsWith("#audit=")'), true, 'hash survives reload');
      assert.equal(await dom('[data-tab="verify"]', 'el => el.getAttribute("aria-selected")'), 'true', 'bookmark restores the verify tab');
      assert.equal(await evaluate('document.querySelector(\'tr[data-check="severity-ceiling"] .gate-select\')?.value'), 'off',
        'bookmark restores the configured policy');
      await click('[data-export="md"]');
      const report = await getFile('supplyguard.report.md');
      assert.match(report, /# SupplyGuard audit report/);
      assert.match(report, /Policy gate: BLOCK/);
    } else {
      const requirements = '\uFEFF# sample\nnumpy==2.1.0\nurllib3>=2\n';
      await importFile('requirements.txt', requirements);
      await score(4);
      assert.equal(await evaluate('document.querySelectorAll("[data-preset][aria-pressed=true]").length'), 0);
      await importFile('package-lock.json', '{"__proto__":{"field":"value"}}');
      await waitFor('document.querySelector("#status").textContent.includes("Reserved key")', 'hostile file rejected');
      await score(4);
      await importFile('yarn.lock', '# yarn lockfile v1\n"dep@1":\n  version "1"\n');
      await waitFor('document.querySelector("#status").textContent.includes("Cargo TOML")', 'unsupported lockfile rejected with a Cargo message');
      await score(4);
      await importFile('requirements', requirements);
      await score(4);
      await until(async () => (await evaluate('document.querySelector("#provenance").textContent')).includes('requirements'),
        'extensionless requirements file imported');
      await click('[data-export="audit"]');
      await until(async () => JSON.parse(await getFile('supplyguard.audit.json')).evidence.format === 'pypi', 'new audit download');
      assert.equal(JSON.parse(await getFile('supplyguard.audit.json')).evidence.inputSha256, await sha256(requirements));
      const literal = '<asset class="probe">';
      await importFile('sbom.json', JSON.stringify({
        bomFormat: 'CycloneDX', specVersion: '1.5', version: 1, components: [{ type: 'library', name: literal }],
      }));
      await waitFor(`document.querySelector("#graph svg").textContent.includes(${JSON.stringify(literal)})`, 'hostile markup rendered as text');
      assert.equal(await evaluate('document.querySelector(".probe")'), null);
      await click('[data-tab="diff"]');
      await evaluate(`(() => {
        for (const [id, v] of [['#diff-left', 'preset:baseline'], ['#diff-right', 'preset:lifecycle']]) {
          const s = document.querySelector(id); s.value = v; s.dispatchEvent(new Event('change'));
        }
      })()`);
      await click('#diff-run');
      await until(async () => (await evaluate('document.querySelector(".diff-sum")?.textContent ?? ""'))
        .includes('net risk delta +72'), 'mobile diff renders');
      await click('[data-tab="verify"]');
      await click('#run-selftests');
      await until(async () => /self-tests pass/.test(await evaluate('document.querySelector(".st-count")?.textContent ?? ""')),
        'mobile self-tests render');
      assert.equal(await evaluate('document.querySelectorAll(".selftest-list .st-fail").length'), 0);
      assert.match(await dom('.gate-chip', 'el => el.textContent'), /gate (PASS|WARN|BLOCK)/);
      assert.equal(await evaluate('document.documentElement.scrollWidth'), 390, 'workbench panels fit mobile width');
      if (process.argv.includes('--capture')) {
        await click('[data-preset="lifecycle"]');
        await score(72);
        await screenshot('mobile.png');
      }
    }
    console.log(`${width}x${height}: presets, pointer hit tests, graph and layout verified`);
  }
  // ERR_INTERNET_DISCONNECTED is the harness's own offline emulation, not an app fault.
  const uncaught = events.filter(event => {
    if (event.method === 'Runtime.exceptionThrown') return true;
    if (event.method === 'Runtime.consoleAPICalled' && event.params.type === 'error' &&
        !/ERR_INTERNET_DISCONNECTED/.test(JSON.stringify(event.params.args ?? []))) return true;
    if (event.method === 'Log.entryAdded' && event.params.entry.level === 'error' &&
        !/ERR_INTERNET_DISCONNECTED/.test(event.params.entry.text)) return true;
    return event.method === 'Network.loadingFailed' && !event.params.canceled &&
      event.params.errorText !== 'net::ERR_INTERNET_DISCONNECTED';
  });
  assert.deepEqual(uncaught.map(event => event.params), [], 'zero browser errors');
  const requests = events.filter(event => event.method === 'Network.requestWillBeSent').map(event => event.params.request.url);
  assert.ok(requests.every(url => url.startsWith(`${origin}/supplyguard/`) || url.startsWith(`blob:${origin}/`)),
    'no server requests outside local app origin');
  if (process.argv.includes('--capture')) {
    for (const file of ['desktop.png', 'remediation.png', 'mobile.png']) {
      await copyFile(join(scratch, file), new URL(`../docs/${file}`, import.meta.url));
    }
  }
  console.log(`Remediation, filter/sort, shortcut guards, import rejection, downloads, one-page print, policy gate, lockfile diff, self-tests, attestation verify/tamper, and bookmark reload verified; zero browser errors. ${checks} checks passed.`);
} finally {
  socket?.close();
  server.close();
  if (chrome?.pid && chrome.exitCode === null && chrome.signalCode === null) {
    chrome.kill('SIGTERM');
    await Promise.race([once(chrome, 'exit'), delay(2000)]);
  }
  await rm(scratch, { recursive: true, force: true });
}
