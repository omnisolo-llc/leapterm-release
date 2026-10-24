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
  assert.equal(prod.autoPromote, false);

  const promote = parseTag('v0.1.1-promote');
  assert.equal(promote.autoPromote, true);
  assert.equal(promote.buildOnly, false);

  const publish = parseTag('v0.1.1-b27-publish');
  assert.equal(publish.buildOnly, false);
  assert.equal(publish.autoPromote, false);
  assert.equal(publish.buildNumber, '27');

  // Single track never publishes or auto-promotes even with keyword
  const singleTrackPromote = parseTag('v0.1.1-macos-promote');
  assert.equal(singleTrackPromote.track, 'macos');
  assert.equal(singleTrackPromote.buildOnly, true);
  assert.equal(singleTrackPromote.autoPromote, false);

  // Build number tags
  const withBuild1 = parseTag('v0.1.1-b27-macos');
  assert.equal(withBuild1.version, '0.1.1');
  assert.equal(withBuild1.buildNumber, '27');
  assert.equal(withBuild1.track, 'macos');

  const withBuild2 = parseTag('v0.1.1-build42');
  assert.equal(withBuild2.version, '0.1.1');
  assert.equal(withBuild2.buildNumber, '42');
  assert.equal(withBuild2.track, 'all');

  const withBuild3 = parseTag('track-windows-v0.1.2-b99');
  assert.equal(withBuild3.version, '0.1.2');
  assert.equal(withBuild3.buildNumber, '99');
  assert.equal(withBuild3.track, 'windows');
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
  assert.ok(!args.includes('ios_action=upload'));

  const parsedPromote = parseTag('v0.1.1-b27-promote');
  const argsPromote = buildDispatchArguments({ parsed: parsedPromote });
  assert.ok(argsPromote.includes('verify_target=all'));
  assert.ok(argsPromote.includes('build_only=false'));
  assert.ok(argsPromote.includes('auto_promote=true'));
  assert.ok(argsPromote.includes('build_number=27'));
  assert.ok(argsPromote.includes('ios_action=upload'));
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
