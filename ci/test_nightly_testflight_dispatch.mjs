import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  buildNightlyDispatchArgs,
  collectGithubReleaseState,
  compareSemver,
  computeNextPatchVersion,
  main as runNightlyDispatch,
  parseSemverTag,
  queryHighestAscBuild,
  resolveAppleApiCredentials,
  resolveDispatchPlan,
} from './nightly-testflight-dispatch.mjs';
import { scanBufferForLeaks } from './promote-release.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

function generateTestEs256KeyBase64() {
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const pem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  return Buffer.from(pem, 'utf8').toString('base64');
}

test('parseSemverTag extracts 3-part numeric semver and optional build suffix', () => {
  assert.deepEqual(parseSemverTag('v0.1.3'), {
    version: '0.1.3',
    parts: [0, 1, 3],
    buildNumber: null,
  });
  assert.deepEqual(parseSemverTag('0.1.4'), {
    version: '0.1.4',
    parts: [0, 1, 4],
    buildNumber: null,
  });
  assert.deepEqual(parseSemverTag('v0.1.1-fast'), {
    version: '0.1.1',
    parts: [0, 1, 1],
    buildNumber: null,
  });
  assert.deepEqual(parseSemverTag('v0.1.1-b63'), {
    version: '0.1.1',
    parts: [0, 1, 1],
    buildNumber: 63,
  });
  assert.equal(parseSemverTag('ci-stage/application-41569831986-1'), null);
  assert.equal(parseSemverTag(''), null);
});

test('compareSemver and computeNextPatchVersion advance monotonically past published and staged versions', () => {
  assert.ok(compareSemver('0.1.4', '0.1.3') > 0);
  assert.ok(compareSemver('0.2.0', '0.1.99') > 0);
  assert.equal(compareSemver('0.1.4', '0.1.4'), 0);

  assert.equal(computeNextPatchVersion([]), '0.1.4');
  assert.equal(computeNextPatchVersion(['0.1.1', '0.1.3', '0.1.2']), '0.1.4');
  assert.equal(computeNextPatchVersion(['0.1.3', '0.1.4']), '0.1.5');
});

test('resolveAppleApiCredentials supports direct env vars and APPLE_CONFIG JSON fallback', () => {
  const direct = resolveAppleApiCredentials({
    APP_STORE_CONNECT_KEY_ID: 'KEY123',
    APP_STORE_CONNECT_ISSUER_ID: 'ISS456',
    APP_STORE_CONNECT_API_KEY_BASE64: 'B64KEY',
  });
  assert.deepEqual(direct, {
    keyId: 'KEY123',
    issuerId: 'ISS456',
    apiKeyBase64: 'B64KEY',
    appId: '6812974189',
  });

  const fromJson = resolveAppleApiCredentials({
    APPLE_CONFIG: JSON.stringify({
      APP_STORE_CONNECT_KEY_ID: 'JSON_KEY',
      APP_STORE_CONNECT_ISSUER_ID: 'JSON_ISS',
      APP_STORE_CONNECT_API_KEY_BASE64: 'JSON_B64',
      APP_STORE_CONNECT_APP_ID: '999999',
    }),
  });
  assert.deepEqual(fromJson, {
    keyId: 'JSON_KEY',
    issuerId: 'JSON_ISS',
    apiKeyBase64: 'JSON_B64',
    appId: '999999',
  });
});

test('queryHighestAscBuild syncs JWT iat with Apple Date header and parses builds + preReleaseVersions', async () => {
  const apiKeyBase64 = generateTestEs256KeyBase64();
  const appleServerDate = 'Tue, 03 Nov 2026 05:10:00 GMT';
  const expectedIat = Math.floor(new Date(appleServerDate).getTime() / 1000);
  let capturedJwtClaims = null;

  const fetchImpl = async (url, options = {}) => {
    if (options.method === 'HEAD') {
      return {
        ok: true,
        status: 200,
        headers: new Map([['date', appleServerDate]]),
      };
    }
    const auth = options.headers?.Authorization || '';
    const token = auth.replace(/^Bearer\s+/, '');
    const [, claimsB64] = token.split('.');
    capturedJwtClaims = JSON.parse(Buffer.from(claimsB64, 'base64url').toString('utf8'));
    return {
      ok: true,
      status: 200,
      async json() {
        return {
          data: [
            { attributes: { version: '71' } },
            { attributes: { version: '70' } },
          ],
          included: [
            { type: 'preReleaseVersions', attributes: { version: '0.1.4' } },
          ],
        };
      },
    };
  };

  const result = await queryHighestAscBuild({
    env: {
      APP_STORE_CONNECT_KEY_ID: 'K1',
      APP_STORE_CONNECT_ISSUER_ID: 'I1',
      APP_STORE_CONNECT_API_KEY_BASE64: apiKeyBase64,
    },
    fetchImpl,
  });

  assert.equal(capturedJwtClaims.iat, expectedIat);
  assert.equal(result.maxBuild, 71);
  assert.deepEqual(result.versions, ['0.1.4']);
});

test('collectGithubReleaseState inspects public releases, staging releases, and in-flight release.yml runs', async () => {
  const fetchImpl = async (url) => {
    const u = String(url);
    if (u.includes('/repos/omnisolo-llc/leapterm-release/releases')) {
      return {
        ok: true,
        status: 200,
        async json() {
          return [{ tag_name: 'v0.1.3', draft: false }];
        },
      };
    }
    if (u.includes('/repos/example-org/private-source/releases')) {
      return {
        ok: true,
        status: 200,
        async json() {
          return [
            { tag_name: 'ci-stage/application-41569831986-1', draft: true },
            { tag_name: 'v0.1.3', draft: false },
          ];
        },
      };
    }
    if (u.includes('/actions/workflows/release.yml/runs')) {
      return {
        ok: true,
        status: 200,
        async json() {
          return {
            workflow_runs: [
              { id: 41569831986, status: 'in_progress', conclusion: null },
            ],
          };
        },
      };
    }
    if (u.includes('/actions/runs/41569831986/jobs')) {
      return {
        ok: true,
        status: 200,
        async json() {
          return {
            jobs: [
              {
                id: 9991,
                name: 'Validate release request automatically',
                conclusion: 'success',
              },
            ],
          };
        },
      };
    }
    if (u.includes('/actions/jobs/9991/logs')) {
      return {
        ok: true,
        status: 200,
        async text() {
          return [
            'RELEASE_REQUEST: {',
            '  "build_only": false,',
            '  "verify_target": "all",',
            '  "version": "0.1.4",',
            '  "build_number": "72"',
            '}',
          ].join('\n');
        },
      };
    }
    throw new Error(`Unexpected fetch URL: ${u}`);
  };

  const state = await collectGithubReleaseState({
    publicRepo: 'omnisolo-llc/leapterm-release',
    sourceRepo: 'example-org/private-source',
    token: 'ghs_test_token',
    fetchImpl,
  });

  assert.ok(state.versions.includes('0.1.3'));
  assert.ok(state.versions.includes('0.1.4'));
  assert.equal(state.maxBuildNumber, 72);
});

test('resolveDispatchPlan advances past both ASC and in-flight GitHub release versions and builds', async () => {
  const apiKeyBase64 = generateTestEs256KeyBase64();
  const fetchImpl = async (url, options = {}) => {
    const u = String(url);
    if (options.method === 'HEAD') {
      return { ok: true, status: 200, headers: new Map() };
    }
    if (u.includes('api.appstoreconnect.apple.com')) {
      return {
        ok: true,
        status: 200,
        async json() {
          return {
            data: [{ attributes: { version: '71' } }],
            included: [],
          };
        },
      };
    }
    if (u.includes('/repos/omnisolo-llc/leapterm-release/releases')) {
      return {
        ok: true,
        status: 200,
        async json() {
          return [{ tag_name: 'v0.1.3', draft: false }];
        },
      };
    }
    if (u.includes('/repos/example-org/private-source/releases')) {
      return {
        ok: true,
        status: 200,
        async json() {
          return [{ tag_name: 'v0.1.4', draft: false }];
        },
      };
    }
    if (u.includes('/actions/workflows/release.yml/runs')) {
      return {
        ok: true,
        status: 200,
        async json() {
          return {
            workflow_runs: [
              { id: 5001, status: 'in_progress', conclusion: null },
            ],
          };
        },
      };
    }
    if (u.includes('/actions/runs/5001/jobs')) {
      return {
        ok: true,
        status: 200,
        async json() {
          return {
            jobs: [
              {
                id: 5002,
                name: 'Validate release request automatically',
                conclusion: 'success',
              },
            ],
          };
        },
      };
    }
    if (u.includes('/actions/jobs/5002/logs')) {
      return {
        ok: true,
        status: 200,
        async text() {
          return '"build_only": false,\n"version": "0.1.4",\n"build_number": "72"\n';
        },
      };
    }
    throw new Error(`Unexpected URL: ${u}`);
  };

  const plan = await resolveDispatchPlan({
    env: {
      GH_TOKEN: 'ghs_test',
      SOURCE_REPOSITORY: 'example-org/private-source',
      APP_STORE_CONNECT_KEY_ID: 'K1',
      APP_STORE_CONNECT_ISSUER_ID: 'I1',
      APP_STORE_CONNECT_API_KEY_BASE64: apiKeyBase64,
    },
    fetchImpl,
  });

  assert.equal(plan.target, 'all');
  assert.equal(plan.version, '0.1.5');
  assert.equal(plan.buildNumber, 73);
  assert.equal(plan.sourceSha, '');

  const args = buildNightlyDispatchArgs(plan);
  assert.ok(args.includes('verify_target=all'));
  assert.ok(args.includes('build_only=false'));
  assert.ok(args.includes('version=0.1.5'));
  assert.ok(args.includes('build_number=73'));
  assert.ok(args.includes('ios_action=upload'));
  assert.ok(args.includes('include_selfhost=true'));
  assert.ok(args.includes('auto_promote=true'));
  assert.ok(!args.some((a) => a.startsWith('source_sha=')));
  assert.ok(!args.some((a) => a.startsWith('builder_sha=')));
});

test('buildNightlyDispatchArgs rejects single-platform targets incompatible with full release mode', () => {
  assert.throws(
    () =>
      buildNightlyDispatchArgs({
        target: 'ios',
        version: '0.1.5',
        buildNumber: 73,
      }),
    /Unsupported scheduled release target/,
  );
});

test('twice-daily workflow and dispatcher contain zero private repository leaks', () => {
  const workflowPath = path.resolve(
    __dirname,
    '..',
    '.github',
    'workflows',
    'nightly-testflight.yml',
  );
  const scriptPath = path.resolve(__dirname, 'nightly-testflight-dispatch.mjs');
  for (const filePath of [workflowPath, scriptPath]) {
    const buf = fs.readFileSync(filePath);
    const leaks = scanBufferForLeaks(buf, path.basename(filePath)).filter(
      (msg) => !msg.includes('production product domain'),
    );
    assert.deepEqual(leaks, []);
  }
});

test('nightly workflow avoids top-of-hour cron congestion and clearly identifies Nightly Release', () => {
  const workflowPath = path.resolve(
    __dirname,
    '..',
    '.github',
    'workflows',
    'nightly-testflight.yml',
  );
  const content = fs.readFileSync(workflowPath, 'utf8');
  assert.match(content, /^name:\s*.*Nightly.*Release/m);
  const cronMatch = content.match(/cron:\s*'(\d+)\s+([0-9,*/-]+)\s+\*\s+\*\s+\*'/);
  assert.ok(cronMatch, 'expected a 5-field cron schedule in nightly-testflight.yml');
  const minute = Number(cronMatch[1]);
  assert.ok(
    minute > 0 && minute < 60,
    `expected off-hour-boundary cron minute (1-59) to avoid GitHub schedule starvation, got ${cronMatch[1]}`,
  );
});

test('scheduled nightly run skips duplicate dispatch when a full release.yml run is already active, while manual dispatch proceeds', async () => {
  const apiKeyBase64 = generateTestEs256KeyBase64();
  const fetchImpl = async (url, options = {}) => {
    const u = String(url);
    if (options.method === 'HEAD') {
      return { ok: true, status: 200, headers: new Map() };
    }
    if (u.includes('api.appstoreconnect.apple.com')) {
      return {
        ok: true,
        status: 200,
        async json() {
          return { data: [{ attributes: { version: '71' } }], included: [] };
        },
      };
    }
    if (u.includes('/releases')) {
      return {
        ok: true,
        status: 200,
        async json() {
          return [{ tag_name: 'v0.1.3', draft: false }];
        },
      };
    }
    if (u.includes('/actions/workflows/release.yml/runs')) {
      return {
        ok: true,
        status: 200,
        async json() {
          return {
            workflow_runs: [
              { id: 9001, status: 'in_progress', conclusion: null },
            ],
          };
        },
      };
    }
    if (u.includes('/actions/runs/9001/jobs')) {
      return {
        ok: true,
        status: 200,
        async json() {
          return {
            jobs: [
              {
                id: 9002,
                name: 'Validate release request automatically',
                conclusion: 'success',
              },
            ],
          };
        },
      };
    }
    if (u.includes('/actions/jobs/9002/logs')) {
      return {
        ok: true,
        status: 200,
        async text() {
          return '"build_only": false,\n"version": "0.1.4",\n"build_number": "72"\n';
        },
      };
    }
    throw new Error(`Unexpected URL: ${u}`);
  };

  const scheduledCalls = [];
  const scheduledResult = await runNightlyDispatch({
    env: {
      GITHUB_EVENT_NAME: 'schedule',
      GH_TOKEN: 'ghs_test',
      APP_STORE_CONNECT_KEY_ID: 'K1',
      APP_STORE_CONNECT_ISSUER_ID: 'I1',
      APP_STORE_CONNECT_API_KEY_BASE64: apiKeyBase64,
    },
    fetchImpl,
    execFileImpl: (cmd, args) => scheduledCalls.push([cmd, args]),
  });
  assert.equal(scheduledResult.skipped, true);
  assert.equal(scheduledCalls.length, 0);

  const manualCalls = [];
  const manualResult = await runNightlyDispatch({
    env: {
      GITHUB_EVENT_NAME: 'workflow_dispatch',
      GH_TOKEN: 'ghs_test',
      APP_STORE_CONNECT_KEY_ID: 'K1',
      APP_STORE_CONNECT_ISSUER_ID: 'I1',
      APP_STORE_CONNECT_API_KEY_BASE64: apiKeyBase64,
    },
    fetchImpl,
    execFileImpl: (cmd, args) => manualCalls.push([cmd, args]),
  });
  assert.equal(Boolean(manualResult.skipped), false);
  assert.equal(manualCalls.length, 1);
  assert.equal(manualCalls[0][0], 'gh');
});

test('release.yml blocks option1_signatures and publish on upstream track failure and isolates auto_promote docs deploy', () => {
  const releaseYml = fs.readFileSync(
    path.resolve(__dirname, '..', '.github', 'workflows', 'release.yml'),
    'utf8',
  );
  const sigMatch = releaseYml.match(/option1_signatures:[\s\S]*?if:\s*(.+)/);
  assert.ok(sigMatch, 'expected option1_signatures if condition');
  assert.ok(sigMatch[1].includes('!failure()'), 'option1_signatures must guard against upstream track failure');

  const pubMatch = releaseYml.match(/\n  publish:\n[\s\S]*?if:\s*(.+)/);
  assert.ok(pubMatch, 'expected publish if condition');
  assert.ok(pubMatch[1].includes('!failure()'), 'publish must guard against upstream track failure');
  assert.ok(
    pubMatch[1].includes("needs.option1_signatures.result == 'success'"),
    'publish must require option1_signatures success',
  );

  const autoPromoteMatch = releaseYml.match(
    /Auto-promoting release candidate to internal store tracks[\s\S]*?if \[ "\$\{PUBLISH_PUBLIC_RELEASE\}" = "true" \]/,
  );
  assert.ok(autoPromoteMatch, 'expected internal store auto-promote block');
  assert.ok(
    autoPromoteMatch[0].includes('-f deploy_docs=false'),
    'internal store auto-promote run must disable duplicate docs/CDN deploy',
  );
});
