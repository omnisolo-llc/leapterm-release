import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import test from 'node:test';

const manifest = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8'));
const lock = JSON.parse(await readFile(new URL('../package-lock.json', import.meta.url), 'utf8'));

test('the relay development runtime uses patched compatible Wrangler dependencies', () => {
  const wranglerVersion = '4.145.0';
  const miniflareVersion = '5.20260930.0-alpha';
  const undiciVersion = '7.29.1';

  assert.equal(manifest.devDependencies.wrangler, wranglerVersion);
  assert.equal(manifest.devDependencies.miniflare, miniflareVersion);
  assert.equal(lock.packages[''].devDependencies.wrangler, wranglerVersion);
  assert.equal(lock.packages[''].devDependencies.miniflare, miniflareVersion);
  assert.equal(lock.packages['node_modules/wrangler'].version, wranglerVersion);
  assert.equal(lock.packages['node_modules/wrangler'].dependencies.miniflare, miniflareVersion);
  assert.equal(lock.packages['node_modules/miniflare'].version, miniflareVersion);
  assert.equal(lock.packages['node_modules/miniflare'].dependencies.undici, undiciVersion);
  assert.equal(lock.packages['node_modules/undici'].version, undiciVersion);
});

test('the Worker compatibility date remains pinned for production and local runtime tests', async () => {
  const wrangler = await readFile(new URL('../wrangler.toml', import.meta.url), 'utf8');
  const runtime = await readFile(new URL('./relay-runtime.mjs', import.meta.url), 'utf8');

  assert.match(wrangler, /^compatibility_date = "2026-09-18"$/m);
  assert.equal((runtime.match(/compatibilityDate: '2026-09-18'/g) ?? []).length, 2);
});
