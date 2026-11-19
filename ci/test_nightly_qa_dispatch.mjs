import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  buildBuildOnlyReleaseDispatchArgs,
  buildSourceCiDispatchArgs,
  buildSourceDiscoveryDispatchArgs,
  computeSourceCiCorrelationId,
  main as runNightlyQaDispatch,
  resolveNightlyQaPlan,
  selectVerificationVersion,
} from './nightly-qa-dispatch.mjs';
import { scanBufferForLeaks } from './promote-release.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

test('computeSourceCiCorrelationId produces deterministic 24-hex Source-CI correlation token', () => {
  const sourceSha = 'a'.repeat(40);
  const builderSha = 'b'.repeat(40);
  const cid = computeSourceCiCorrelationId('acme-test/sample-source', sourceSha, builderSha, 'ci');
  assert.match(cid, /^[0-9a-f]{24}$/);
  assert.equal(
    cid,
    computeSourceCiCorrelationId('acme-test/sample-source', sourceSha.toUpperCase(), builderSha, 'ci'),
  );
  assert.throws(
    () => computeSourceCiCorrelationId('bad slug', sourceSha, builderSha),
    /Invalid source repository slug/,
  );
});

test('buildBuildOnlyReleaseDispatchArgs enforces build_only=true, ios_action=skip, auto_promote=false across all targets', () => {
  const args = buildBuildOnlyReleaseDispatchArgs({
    verifyTarget: 'all',
    version: '0.1.5',
    buildNumber: 74,
    sourceSha: 'c'.repeat(40),
    runTest: true,
  });
  assert.ok(args.includes('release.yml'));
  assert.ok(args.includes('build_only=true'));
  assert.ok(args.includes('verify_target=all'));
  assert.ok(args.includes('ios_action=skip'));
  assert.ok(args.includes('automatic_release=false'));
  assert.ok(args.includes('include_selfhost=false'));
  assert.ok(args.includes('auto_promote=false'));
  assert.ok(args.includes('run_test=true'));
  assert.ok(args.includes(`source_sha=${'c'.repeat(40)}`));

  assert.throws(
    () => buildBuildOnlyReleaseDispatchArgs({ verifyTarget: 'invalid-os', version: '0.1.5', buildNumber: 1 }),
    /Unsupported verify_target/,
  );
});

test('buildSourceCiDispatchArgs and buildSourceDiscoveryDispatchArgs construct canonical workflow_dispatch invocations', () => {
  const sourceSha = '1'.repeat(40);
  const builderSha = '2'.repeat(40);
  const catalogSha256 = '3'.repeat(64);
  const correlationId = computeSourceCiCorrelationId('acme-test/sample-source', sourceSha, builderSha, 'ci');

  const directArgs = buildSourceCiDispatchArgs({
    sourceSha,
    builderSha,
    catalogSha256,
    correlationId,
  });
  assert.ok(directArgs.includes('source-ci.yml'));
  assert.ok(directArgs.includes(`source_sha=${sourceSha}`));
  assert.ok(directArgs.includes('source_ref=refs/heads/main'));
  assert.ok(directArgs.includes(`builder_sha=${builderSha}`));
  assert.ok(directArgs.includes(`catalog_sha256=${catalogSha256}`));
  assert.ok(directArgs.includes(`correlation_id=${correlationId}`));

  const discoveryArgs = buildSourceDiscoveryDispatchArgs();
  assert.deepEqual(discoveryArgs, [
    'workflow',
    'run',
    'source-discovery.yml',
    '-R',
    'omnisolo-llc/leapterm-release',
    '--ref',
    'main',
  ]);
});

test('resolveNightlyQaPlan selects direct source-ci.yml or source-discovery.yml and skips duplicate scheduled runs', async () => {
  const fetchActive = async (url) => {
    const u = String(url);
    if (u.endsWith('/git/ref/heads/main')) {
      return { ok: true, status: 200, async json() { return { object: { sha: 'd'.repeat(40) } }; } };
    }
    if (u.includes('/releases')) {
      return { ok: true, status: 200, async json() { return [{ tag_name: 'v0.1.6-b80' }]; } };
    }
    if (u.includes('/actions/workflows/release.yml/runs')) {
      return {
        ok: true,
        status: 200,
        async json() {
          return {
            workflow_runs: [{ id: 7001, status: 'in_progress', created_at: new Date().toISOString() }],
          };
        },
      };
    }
    if (u.includes('/actions/workflows/source-ci.yml/runs')) {
      return {
        ok: true,
        status: 200,
        async json() {
          return {
            workflow_runs: [{ id: 8001, status: 'queued', created_at: new Date().toISOString() }],
          };
        },
      };
    }
    return { ok: true, status: 200, async json() { return { workflow_runs: [] }; } };
  };

  const plan = await resolveNightlyQaPlan({
    env: {
      SOURCE_REPOSITORY: 'acme-test/sample-source',
      SOURCE_CI_DISCOVERY_ENABLED: 'true',
      GITHUB_SHA: 'd'.repeat(40),
    },
    fetchImpl: fetchActive,
  });
  assert.equal(plan.version, '0.1.6');
  assert.equal(plan.buildNumber, 80);
  assert.equal(plan.sourceCiMode, 'discovery');
  assert.equal(selectVerificationVersion(['v0.1.2', 'v0.1.6']), '0.1.6');

  // Scheduled cron skips duplicate active runs
  const scheduledCalls = [];
  const scheduledOut = await runNightlyQaDispatch({
    env: {
      GITHUB_EVENT_NAME: 'schedule',
      SOURCE_REPOSITORY: 'acme-test/sample-source',
      SOURCE_CI_DISCOVERY_ENABLED: 'true',
      GITHUB_SHA: 'd'.repeat(40),
    },
    fetchImpl: fetchActive,
    execFileImpl: (cmd, args) => scheduledCalls.push([cmd, args]),
  });
  assert.equal(scheduledCalls.length, 0);
  assert.equal(scheduledOut.dispatched.skippedSourceCi, true);
  assert.equal(scheduledOut.dispatched.skippedBuildVerify, true);

  // Manual workflow_dispatch dispatches both direct source-ci.yml and build_only release.yml
  const manualCalls = [];
  const manualOut = await runNightlyQaDispatch({
    env: {
      GITHUB_EVENT_NAME: 'workflow_dispatch',
      SOURCE_REPOSITORY: 'acme-test/sample-source',
      GITHUB_SHA: 'd'.repeat(40),
      INPUT_SOURCE_SHA: 'e'.repeat(40),
      INPUT_CATALOG_SHA256: 'f'.repeat(64),
      INPUT_VERIFY_TARGET: 'fast',
    },
    fetchImpl: fetchActive,
    execFileImpl: (cmd, args) => manualCalls.push([cmd, args]),
  });
  assert.equal(manualCalls.length, 2);
  assert.ok(manualCalls[0][1].includes('source-ci.yml'));
  assert.ok(manualCalls[1][1].includes('release.yml'));
  assert.ok(manualCalls[1][1].includes('build_only=true'));
  assert.ok(manualCalls[1][1].includes('verify_target=fast'));
  assert.equal(manualOut.dispatched.sourceCi, true);
  assert.equal(manualOut.dispatched.buildVerify, true);
});

test('nightly-qa-longevity.yml and nightly-qa-dispatch.mjs contain zero private leaks and use off-peak cron on ubuntu-24.04', () => {
  const workflowPath = path.resolve(
    __dirname,
    '..',
    '.github',
    'workflows',
    'nightly-qa-longevity.yml',
  );
  const dispatcherPath = path.resolve(__dirname, 'nightly-qa-dispatch.mjs');
  const testPath = fileURLToPath(import.meta.url);

  for (const filePath of [workflowPath, dispatcherPath, testPath]) {
    const buf = fs.readFileSync(filePath);
    const leaks = scanBufferForLeaks(buf, path.basename(filePath)).filter(
      (msg) => !msg.includes('production product domain'),
    );
    assert.deepEqual(leaks, [], `Unexpected boundary leak in ${path.basename(filePath)}: ${leaks.join('; ')}`);
  }

  const workflowContent = fs.readFileSync(workflowPath, 'utf8');
  const cronMatch = workflowContent.match(/cron:\s*'(\d+)\s+([0-9,*/-]+)\s+\*\s+\*\s+\*'/);
  assert.ok(cronMatch, 'Expected 5-field cron expression in nightly-qa-longevity.yml');
  const minute = Number(cronMatch[1]);
  assert.ok(
    minute > 0 && minute < 60 && minute !== 15 && minute !== 30,
    `Expected off-peak cron minute avoiding :00/:15/:30 congestion, got ${minute}`,
  );
  assert.match(workflowContent, /runs-on:\s*ubuntu-24\.04/);
});
