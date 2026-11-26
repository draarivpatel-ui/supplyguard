import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const css = readFileSync(new URL('../styles.css', import.meta.url), 'utf8');
const app = readFileSync(new URL('../src/app.js', import.meta.url), 'utf8');

test('license denylist input has a programmatic accessible name', () => {
  assert.match(app, /deny\.setAttribute\('aria-label', 'License denylist'\)/);
});

test('interactive controls keep a 44 pixel minimum target height', () => {
  assert.match(css, /button\{\s*min-height:\s*44px;\s*min-width:\s*44px;\s*\}/);
  assert.match(css, /input\[type="text"\], select, #file-input\{\s*min-height:\s*44px;\s*\}/);
});

test('placeholders use verified theme ink at full opacity', () => {
  assert.match(css, /input::placeholder, textarea::placeholder\{\s*color:\s*var\(--ink-dim\);\s*opacity:\s*1;\s*\}/);
});

test('control borders meet non-text contrast in dark and light themes', () => {
  assert.match(css, /--line-strong:\s*#6a9b77;/);
  assert.match(css, /--line-strong:\s*#746a45;/);
  assert.match(css, /\.comp-btn\{[\s\S]*border:\s*1px solid var\(--line-strong\);/);
});

test('high severity ink keeps AA contrast over its translucent badge', () => {
  assert.match(css, /--coral:\s*#f08a75;/);
});
