import assert from 'node:assert/strict';
import test from 'node:test';
import {
  parseTag,
  buildDispatchArguments,
  dispatchTagFlow,
} from './tag-flow-dispatch.mjs';

test('parseTag correctly resolves version and track from diverse tag formats', () => {
  // General release tag
  const all1 = parseTag('v0.1.1');
  assert.equal(all1.version, '0.1.1');
  assert.equal(all1.track, 'all');
  assert.equal(all1.buildOnly, true);

  // Platform suffix tags
  const macos1 = parseTag('v0.1.1-macos');
  assert.equal(macos1.version, '0.1.1');
  assert.equal(macos1.track, 'macos');

  const windows1 = parseTag('v0.1.1-windows');
  assert.equal(windows1.version, '0.1.1');
  assert.equal(windows1.track, 'windows');

  const ios1 = parseTag('v0.1.1-ios');
  assert.equal(ios1.version, '0.1.1');
  assert.equal(ios1.track, 'ios');

  const linux1 = parseTag('v0.1.1-linux');
  assert.equal(linux1.version, '0.1.1');
  assert.equal(linux1.track, 'linux');

  const android1 = parseTag('v0.1.1-android');
  assert.equal(android1.version, '0.1.1');
  assert.equal(android1.track, 'android');

  const web1 = parseTag('v0.1.1-web');
  assert.equal(web1.version, '0.1.1');
  assert.equal(web1.track, 'web');

  // Track prefix tags
  const macos2 = parseTag('track-macos-v0.1.2');
  assert.equal(macos2.version, '0.1.2');
  assert.equal(macos2.track, 'macos');

  const windows2 = parseTag('windows-v0.1.3');
  assert.equal(windows2.version, '0.1.3');
  assert.equal(windows2.track, 'windows');

  // Production or promotion tags
  const prod = parseTag('v0.1.1-prod');
  assert.equal(prod.buildOnly, false);

  const promote = parseTag('v0.1.1-promote');
  assert.equal(promote.autoPromote, true);
});

test('parseTag rejects invalid tags missing semver', () => {
  assert.throws(() => parseTag('invalid'), /valid semver/);
  assert.throws(() => parseTag(''), /non-empty/);
});

test('buildDispatchArguments formats gh workflow run args properly', () => {
  const parsed = parseTag('v0.1.1-macos');
  const args = buildDispatchArguments({ parsed, buildNumber: '42' });
  assert.ok(args.includes('verify_target=macos'));
  assert.ok(args.includes('version=0.1.1'));
  assert.ok(args.includes('build_number=42'));
  assert.ok(args.includes('release_route=option1'));
});

test('dispatchTagFlow executes gh workflow run with correct token', async () => {
  let executedCmd = null;
  let executedArgs = null;
  let executedEnv = null;

  const fakeExec = (cmd, args, opts) => {
    executedCmd = cmd;
    executedArgs = args;
    executedEnv = opts.env;
  };

  const res = await dispatchTagFlow({
    tag: 'v0.1.1-windows',
    buildNumber: '99',
    token: 'test-token-123',
    execFileImpl: fakeExec,
  });

  assert.equal(res.track, 'windows');
  assert.equal(executedCmd, 'gh');
  assert.ok(executedArgs.includes('verify_target=windows'));
  assert.equal(executedEnv.GH_TOKEN, 'test-token-123');
});
