import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import vm from 'node:vm';

import {
  GHCR_CONTAINER_REGISTRY,
  PRIMARY_CONTAINER_REGISTRY,
  PUBLIC_TARGETS,
  FORBIDDEN_PRIVATE_TARGETS,
  assertNoPrivateLeakInPublicMetadata,
  buildEnvironmentRolloutPlan,
  buildPublicSha256Sums,
  canonicalJson,
  createAppStoreConnectJwt,
  createZipBuffer,
  executeEnvironmentRollout,
  filterPublicDownloadLinks,
  filterPublicProvenance,
  promoteAndroidToPlayStore,
  promoteIosToAppStoreConnect,
  promoteMacosToAppStoreConnect,
  promoteRelease,
  resolveGpgSigningCredentials,
  resolveRolloutEnvironment,
  scanDirectoryForLeaks,
  scanSelfHostedZipForLeaks,
  sha256Hex,
  verifyAppleStoreAccess,
  verifyGooglePlayStoreAccess,
} from './promote-release.mjs';

const mockRolloutCredentials = {
  CLOUDFLARE_API_TOKEN: 'mock-cloudflare-rollout-token',
  CLOUDFLARE_ACCOUNT_ID: 'a'.repeat(32),
  KUBECONFIG: 'apiVersion: v1\nkind: Config\nclusters: []\ncontexts: []\nusers: []\n',
  OMNI_GATEWAY_SOURCE_IMAGE: `omniterm/gateway@sha256:${'b'.repeat(64)}`,
};

test.beforeEach((t) => {
  const previous = {};
  for (const [name, value] of Object.entries(mockRolloutCredentials)) {
    previous[name] = process.env[name];
    process.env[name] = value;
  }
  t.after(() => {
    for (const [name, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  });
});

function makeStagingFixtures(version = '0.1.1') {
  const allTargets = [
    ['windows', `omniterm-${version}-windows-x64.zip`],
    ['linux', `omniterm-${version}-linux-x64.tar.gz`],
    ['macos', `omniterm-${version}-macos-arm64.zip`],
    ['android', `omniterm-${version}-android-universal.apk`],
    ['android-arm', `omniterm-${version}-android-armeabi-v7a.apk`],
    ['android-arm64', `omniterm-${version}-android-arm64-v8a.apk`],
    ['android-x64', `omniterm-${version}-android-x86_64.apk`],
    ['android-aab', `omniterm-${version}-android.aab`],
    ['services-linux', `omniterm-${version}-services-linux-x64.tar.gz`],
    ['services-windows', `omniterm-${version}-services-windows-x64.zip`],
    ['services-macos', `omniterm-${version}-services-macos-arm64.tar.gz`],
    ['agent-deb', `omniterm-${version}-agent-linux-amd64.deb`],
    ['agent-rpm', `omniterm-${version}-agent-linux-x86_64.rpm`],
    ['flutter-web', `omniterm-${version}-flutter-web.tar.gz`],
    ['workstation-web', `omniterm-${version}-workstation-web.tar.gz`],
  ];

  const stagingLinks = {
    version,
    build_number: 18,
    tag: `v${version}`,
    downloads: allTargets.map(([target, name], idx) => ({
      target,
      name,
      bytes: 1000 + idx,
      sha256: `${String(idx).padStart(2, '0')}${'a'.repeat(62)}`,
      url: `https://github.com/omnisolo-llc/omniterm/releases/download/v${version}/${name}`,
      checksum_url: `https://github.com/omnisolo-llc/omniterm/releases/download/v${version}/${name}.sha256`,
      signature_url: `https://github.com/omnisolo-llc/omniterm/releases/download/v${version}/${name}.sha256.sig`,
    })),
    self_hosted: {
      name: `omniterm-${version}-self-hosted.zip`,
      bytes: 4096,
      sha256: 'f'.repeat(64),
      url: `https://github.com/omnisolo-llc/omniterm/releases/download/v${version}/omniterm-${version}-self-hosted.zip`,
      sha256_url: `https://github.com/omnisolo-llc/omniterm/releases/download/v${version}/omniterm-${version}-self-hosted.zip.sha256`,
      signature_url: `https://github.com/omnisolo-llc/omniterm/releases/download/v${version}/omniterm-${version}-self-hosted.zip.sha256.sig`,
    },
    ios_delivery: {
      action: 'upload',
      artifact: `omniterm-${version}-ios-private.ipa`,
      url: `https://github.com/omnisolo-llc/omniterm/releases/download/v${version}/omniterm-${version}-ios-private.ipa`,
    },
  };

  const stagingProvenance = {
    schema_version: 1,
    canonicalization: 'json-sort-keys-compact-utf8-v1',
    source_sha: '1111111111111111111111111111111111111111',
    builder_sha: '2222222222222222222222222222222222222222',
    version,
    build_number: '18',
    run_id: '100',
    attempt: '1',
    proof: 'option1',
    release_route: 'option1',
    ios_action: 'upload',
    automatic_release: false,
    include_selfhost: true,
    managed_vpn: true,
    signer_fingerprint: 'ABCD'.repeat(10),
    public_key_bytes: 1234,
    public_key_sha256: 'c'.repeat(64),
    inventory_scope: 'catalog-application-artifacts',
    artifacts: stagingLinks.downloads.map((a) => ({
      target: a.target,
      name: a.name,
      bytes: a.bytes,
      sha256: a.sha256,
    })),
  };

  return { stagingLinks, stagingProvenance };
}

test('filterPublicDownloadLinks strips all private targets and rewrites URLs to public repo', () => {
  const { stagingLinks } = makeStagingFixtures('0.1.1');
  const pubLinks = filterPublicDownloadLinks(stagingLinks);

  assert.equal(pubLinks.artifacts.length, PUBLIC_TARGETS.length);
  assert.equal(pubLinks.downloads.length, PUBLIC_TARGETS.length);
  assert.deepEqual(
    pubLinks.artifacts.map((a) => a.target),
    PUBLIC_TARGETS,
  );
  for (const forbidden of FORBIDDEN_PRIVATE_TARGETS) {
    assert.ok(!pubLinks.artifacts.some((a) => a.target === forbidden));
  }
  const serialized = JSON.stringify(pubLinks);
  assertNoPrivateLeakInPublicMetadata('download-links.json', serialized);
  assert.ok(!serialized.includes('omnisolo-llc/omniterm/releases'));
  assert.ok(
    serialized.includes(
      'omnisolo-llc/omniterm-release/releases/download/v0.1.1/',
    ),
  );
});

test('filterPublicProvenance strips private targets and masks private source_sha', () => {
  const { stagingProvenance } = makeStagingFixtures('0.1.1');
  const pubProv = filterPublicProvenance(stagingProvenance);

  assert.equal(pubProv.inventory_scope, 'public-application-artifacts');
  assert.equal(pubProv.source_sha, stagingProvenance.builder_sha);
  assert.notEqual(pubProv.source_sha, stagingProvenance.source_sha);
  assert.equal(pubProv.artifacts.length, PUBLIC_TARGETS.length);

  const serialized = canonicalJson(pubProv);
  assertNoPrivateLeakInPublicMetadata(
    'omniterm-0.1.1-release-provenance.json',
    serialized,
  );
  assert.ok(!serialized.includes(stagingProvenance.source_sha));
});

test('resolveGpgSigningCredentials supports both PACKAGE_SIGNING_* and gpg_* keys', () => {
  const c1 = resolveGpgSigningCredentials({
    PACKAGE_SIGNING_PRIVATE_KEY_BASE64: 'YWJj',
    PACKAGE_SIGNING_PASSPHRASE: 'secret',
    PACKAGE_SIGNER_FINGERPRINT: '1234ABCD',
  });
  assert.equal(c1.privateKeyBase64, 'YWJj');
  assert.equal(c1.passphrase, 'secret');
  assert.equal(c1.keyId, '1234ABCD');

  const c2 = resolveGpgSigningCredentials({
    gpg_private_key_base64: 'ZGVm',
    gpg_passphrase: 'pass',
    gpg_key_id: '5678EF00',
  });
  assert.equal(c2.privateKeyBase64, 'ZGVm');
  assert.equal(c2.passphrase, 'pass');
  assert.equal(c2.keyId, '5678EF00');
});

test('promoteIosToAppStoreConnect and promoteMacosToAppStoreConnect support testflight and app-store', async () => {
  const { privateKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'prime256v1',
  });
  const pem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  const appleSigningConfigJson = JSON.stringify({
    APP_STORE_CONNECT_KEY_ID: 'ABC1234567',
    APP_STORE_CONNECT_ISSUER_ID: '11111111-2222-3333-4444-555555555555',
    APP_STORE_CONNECT_API_KEY_BASE64: Buffer.from(pem, 'utf8').toString(
      'base64',
    ),
  });

  const jwt = createAppStoreConnectJwt({
    keyId: 'ABC1234567',
    issuerId: '11111111-2222-3333-4444-555555555555',
    privateKeyBase64: Buffer.from(pem, 'utf8').toString('base64'),
    nowSeconds: 1700000000,
  });
  assert.equal(jwt.split('.').length, 3);

  const verifyRes = await verifyAppleStoreAccess({
    appleSigningConfigJson,
    fetchImpl: async () =>
      new Response(JSON.stringify({ data: [{ id: 'app-1', type: 'apps' }] }), {
        status: 200,
      }),
  });
  assert.equal(verifyRes.status, 'verified');
  assert.equal(verifyRes.ascAppId, 'app-1');

  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'omni-apple-promote-'));
  try {
    const ipaPath = path.join(tempDir, 'omniterm-0.1.1-ios-private.ipa');
    fs.writeFileSync(ipaPath, 'signed-ipa-fixture');

    let altoolArgs = null;
    const tfRes = await promoteIosToAppStoreConnect({
      version: '0.1.1',
      buildNumber: '18',
      action: 'testflight',
      ipaPath,
      iosSigningConfigJson: appleSigningConfigJson,
      execFileImpl: (cmd, args) => {
        assert.equal(cmd, 'xcrun');
        altoolArgs = args;
      },
    });
    assert.equal(tfRes.status, 'uploaded-to-testflight');
    assert.ok(altoolArgs.includes('--upload-app'));
    assert.ok(altoolArgs.includes('ios'));

    const macPkgPath = path.join(tempDir, 'omniterm-0.1.1-macos.pkg');
    fs.writeFileSync(macPkgPath, 'signed-pkg-fixture');
    let macAltoolArgs = null;
    const macTfRes = await promoteMacosToAppStoreConnect({
      version: '0.1.1',
      buildNumber: '18',
      action: 'testflight',
      packagePath: macPkgPath,
      macosSigningConfigJson: appleSigningConfigJson,
      execFileImpl: (cmd, args) => {
        assert.equal(cmd, 'xcrun');
        macAltoolArgs = args;
      },
    });
    assert.equal(macTfRes.platform, 'macos');
    assert.equal(macTfRes.status, 'uploaded-to-testflight');
    assert.ok(macAltoolArgs.includes('osx'));

    const apiCalls = [];
    const storeRes = await promoteMacosToAppStoreConnect({
      version: '0.1.1',
      buildNumber: '18',
      action: 'app-store',
      automaticRelease: false,
      macosSigningConfigJson: appleSigningConfigJson,
      fetchImpl: async (url, opts = {}) => {
        apiCalls.push({ url, method: opts.method || 'GET' });
        if (url.includes('/v1/apps?')) {
          return new Response(
            JSON.stringify({ data: [{ id: 'app-1', type: 'apps' }] }),
            { status: 200 },
          );
        }
        if (url.includes('/v1/builds?')) {
          assert.ok(url.includes('MAC_OS'));
          return new Response(
            JSON.stringify({
              data: [
                {
                  id: 'build-mac-18',
                  type: 'builds',
                  attributes: { processingState: 'VALID', expired: false },
                },
              ],
            }),
            { status: 200 },
          );
        }
        if (url.includes('/appStoreVersions?')) {
          return new Response(JSON.stringify({ data: [] }), { status: 200 });
        }
        if (url.endsWith('/v1/appStoreVersions') && opts.method === 'POST') {
          return new Response(
            JSON.stringify({
              data: { id: 'ver-mac-011', type: 'appStoreVersions' },
            }),
            { status: 201 },
          );
        }
        if (url.endsWith('/v1/appStoreVersionSubmissions')) {
          return new Response(
            JSON.stringify({
              data: { id: 'sub-mac-1', type: 'appStoreVersionSubmissions' },
            }),
            { status: 201 },
          );
        }
        throw new Error(`Unexpected URL: ${url}`);
      },
    });
    assert.equal(storeRes.platform, 'macos');
    assert.equal(storeRes.status, 'submitted-for-review');
    assert.equal(storeRes.asc_build_id, 'build-mac-18');
    assert.equal(storeRes.release_type, 'MANUAL');
    assert.equal(apiCalls.length, 5);
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

test('promoteAndroidToPlayStore and verifyGooglePlayStoreAccess work with service account JWT', async () => {
  const { privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
  });
  const pem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  const serviceAccountJson = JSON.stringify({
    type: 'service_account',
    client_email: 'play-publisher@omniterm.iam.gserviceaccount.com',
    private_key: pem,
  });

  const probeRes = await verifyGooglePlayStoreAccess({
    serviceAccountJson,
    fetchImpl: async (url, opts = {}) => {
      if (url === 'https://oauth2.googleapis.com/token') {
        return new Response(JSON.stringify({ access_token: 'ya29.fixture' }), {
          status: 200,
        });
      }
      if (url.endsWith('/edits') && opts.method === 'POST') {
        return new Response(JSON.stringify({ id: 'edit-1' }), { status: 200 });
      }
      if (url.endsWith('/edits/edit-1/tracks')) {
        return new Response(
          JSON.stringify({
            tracks: [{ track: 'internal' }, { track: 'production' }],
          }),
          { status: 200 },
        );
      }
      if (url.endsWith('/edits/edit-1') && opts.method === 'DELETE') {
        return new Response('{}', { status: 200 });
      }
      throw new Error(`Unexpected probe URL: ${url}`);
    },
  });
  assert.equal(probeRes.status, 'verified');
  assert.deepEqual(probeRes.tracks, ['internal', 'production']);

  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'omni-play-promote-'));
  try {
    const aabPath = path.join(tempDir, 'omniterm-0.1.1-android.aab');
    const aabBytes = Buffer.from('signed-aab-fixture');
    fs.writeFileSync(aabPath, aabBytes);
    const expectedSha = sha256Hex(aabBytes);

    const calls = [];
    const res = await promoteAndroidToPlayStore({
      version: '0.1.1',
      buildNumber: '18',
      track: 'internal',
      aabPath,
      serviceAccountJson,
      fetchImpl: async (url, opts = {}) => {
        calls.push({ url, method: opts.method || 'GET' });
        if (url === 'https://oauth2.googleapis.com/token') {
          return new Response(
            JSON.stringify({ access_token: 'ya29.fixture' }),
            { status: 200 },
          );
        }
        if (url.endsWith('/edits') && opts.method === 'POST') {
          return new Response(JSON.stringify({ id: 'edit-99' }), {
            status: 200,
          });
        }
        if (url.endsWith('/edits/edit-99/bundles') && opts.method === 'GET') {
          return new Response(JSON.stringify({ bundles: [] }), { status: 200 });
        }
        if (url.includes('/edits/edit-99/bundles?uploadType=media')) {
          return new Response(
            JSON.stringify({ versionCode: 18, sha256: expectedSha }),
            { status: 200 },
          );
        }
        if (url.endsWith('/edits/edit-99/tracks/internal')) {
          return new Response(JSON.stringify({ track: 'internal' }), {
            status: 200,
          });
        }
        if (
          url.endsWith('/edits/edit-99:validate') ||
          url.endsWith('/edits/edit-99:commit')
        ) {
          return new Response(JSON.stringify({ id: 'edit-99' }), {
            status: 200,
          });
        }
        throw new Error(`Unexpected Play URL: ${url}`);
      },
    });
    assert.equal(res.status, 'committed');
    assert.equal(res.track, 'internal');
    assert.equal(calls.length, 7);
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

test('self-hosted repository files and zip archive pass leak scanner and reject injected leaks', () => {
  const repoRoot = path.resolve(import.meta.dirname, '..');
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'omni-selfhost-test-'));
  try {
    fs.cpSync(path.join(repoRoot, 'relay'), path.join(tempDir, 'relay'), {
      recursive: true,
      filter: (src) => !src.split(path.sep).includes('node_modules'),
    });
    fs.copyFileSync(
      path.join(repoRoot, 'README.md'),
      path.join(tempDir, 'README.md'),
    );
    fs.writeFileSync(
      path.join(tempDir, 'START-HERE.md'),
      '# Self-host relay kit\n',
    );
    assert.deepEqual(scanDirectoryForLeaks(tempDir), []);

    const zipPath = path.join(tempDir, 'omniterm-0.1.1-self-hosted.zip');
    fs.writeFileSync(
      zipPath,
      createZipBuffer({
        'START-HERE.md': fs.readFileSync(path.join(tempDir, 'START-HERE.md')),
        'README.md': fs.readFileSync(path.join(tempDir, 'README.md')),
        'relay/README.md': fs.readFileSync(
          path.join(tempDir, 'relay/README.md'),
        ),
      }),
    );
    scanSelfHostedZipForLeaks(zipPath);

    // Inject production leak and verify scanner rejects it
    const leakyZipPath = path.join(tempDir, 'leaky.zip');
    fs.writeFileSync(
      leakyZipPath,
      createZipBuffer({
        'START-HERE.md': '# Self-host relay kit\n',
        'relay/README.md': 'UPSTREAM_URL=https://api.omniterm.dev/internal\n',
      }),
    );
    assert.throws(
      () => scanSelfHostedZipForLeaks(leakyZipPath),
      /Self-hosted archive failed leak scan/,
    );
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

test('buildPublicSha256Sums sorts deterministically and excludes private assets', () => {
  const sums = buildPublicSha256Sums([
    { name: 'omniterm-0.1.1-windows-x64.zip', sha256: 'b'.repeat(64) },
    { name: 'omniterm-0.1.1-linux-x64.tar.gz', sha256: 'a'.repeat(64) },
  ]);
  assert.equal(
    sums,
    `${'a'.repeat(64)}  omniterm-0.1.1-linux-x64.tar.gz\n${'b'.repeat(64)}  omniterm-0.1.1-windows-x64.zip\n`,
  );
  assertNoPrivateLeakInPublicMetadata('SHA256SUMS', sums);
});

test('resolveRolloutEnvironment maps candidate and production promotion inputs', () => {
  assert.equal(
    resolveRolloutEnvironment({
      rolloutEnvironment: 'auto',
      publishGithubRelease: false,
      iosStoreAction: 'testflight',
      macosStoreAction: 'testflight',
      androidStoreAction: 'internal',
    }),
    'staging',
  );
  assert.equal(
    resolveRolloutEnvironment({
      rolloutEnvironment: 'auto',
      publishGithubRelease: true,
      iosStoreAction: 'none',
      macosStoreAction: 'none',
      androidStoreAction: 'none',
    }),
    'production',
  );
  assert.equal(
    resolveRolloutEnvironment({
      rolloutEnvironment: 'auto',
      publishGithubRelease: false,
      iosStoreAction: 'app-store',
      macosStoreAction: 'none',
      androidStoreAction: 'none',
    }),
    'production',
  );
  assert.equal(
    resolveRolloutEnvironment({
      rolloutEnvironment: 'staging',
      publishGithubRelease: true,
    }),
    'staging',
  );
  assert.equal(
    resolveRolloutEnvironment({
      rolloutEnvironment: 'production',
      publishGithubRelease: false,
    }),
    'production',
  );
  assert.equal(
    resolveRolloutEnvironment({
      rolloutEnvironment: 'none',
      publishGithubRelease: true,
    }),
    'none',
  );
  assert.equal(
    resolveRolloutEnvironment({
      rolloutEnvironment: 'production',
      verifyStoreCredentialsOnly: true,
    }),
    'none',
  );
  assert.throws(
    () => resolveRolloutEnvironment({ rolloutEnvironment: 'invalid-env' }),
    /Unsupported rollout_environment/,
  );
});

test('buildEnvironmentRolloutPlan targets Docker Hub omniterm/omni primary registry and supports GHCR', () => {
  assert.equal(PRIMARY_CONTAINER_REGISTRY, 'omniterm/omni');
  assert.equal(
    GHCR_CONTAINER_REGISTRY,
    'ghcr.io/omnisolo-llc/omniterm/cloud',
  );

  const stagingPlan = buildEnvironmentRolloutPlan({
    environment: 'staging',
    version: 'v0.1.1',
    buildNumber: '18',
    sourceSha: '1'.repeat(40),
  });
  assert.equal(stagingPlan.environment, 'staging');
  assert.equal(stagingPlan.containerTag, 'cloud-staging-latest');
  assert.equal(
    stagingPlan.containerImage,
    'omniterm/omni:cloud-staging-latest',
  );
  assert.equal(
    stagingPlan.cloudflare.api_origin,
    'https://api.staging.omniterm.dev',
  );
  assert.equal(
    stagingPlan.cloudflare.cloud_origin,
    'https://cloud.staging.omniterm.dev',
  );
  assert.equal(
    stagingPlan.container.image,
    'omniterm/omni:cloud-staging-latest',
  );
  assert.equal(
    stagingPlan.container.alias_image,
    'omniterm/omni:latest-staging',
  );
  assert.equal(
    stagingPlan.container.client_image,
    'omniterm/omni:client-staging-latest',
  );
  assert.equal(stagingPlan.k3s.deployment, 'omniterm-staging');
  assert.deepEqual(stagingPlan.rollout_command, [
    'bash',
    'scripts/rollout-env.sh',
    '--env',
    'staging',
  ]);
  assert.deepEqual(stagingPlan.prune_command, [
    'node',
    'scripts/prune-ghcr-packages.mjs',
  ]);

  const prodPlan = buildEnvironmentRolloutPlan({
    environment: 'production',
    version: '0.1.1',
    buildNumber: '18',
    sourceSha: '2'.repeat(40),
  });
  assert.equal(prodPlan.environment, 'production');
  assert.equal(prodPlan.containerTag, 'cloud-latest');
  assert.equal(prodPlan.containerImage, 'omniterm/omni:cloud-latest');
  assert.equal(prodPlan.cloudflare.api_origin, 'https://api.omniterm.dev');
  assert.equal(prodPlan.cloudflare.cloud_origin, 'https://cloud.omniterm.dev');
  assert.equal(prodPlan.container.image, 'omniterm/omni:cloud-latest');
  assert.equal(prodPlan.container.alias_image, 'omniterm/omni:latest');
  assert.equal(prodPlan.container.client_image, 'omniterm/omni:client-latest');
  assert.equal(prodPlan.k3s.deployment, 'omniterm');
  assert.deepEqual(prodPlan.rollout_command, [
    'bash',
    'scripts/rollout-env.sh',
    '--env',
    'production',
  ]);

  const ghcrPlan = buildEnvironmentRolloutPlan({
    environment: 'staging',
    version: '0.1.1',
    buildNumber: '18',
    sourceSha: '3'.repeat(40),
    containerRegistry: GHCR_CONTAINER_REGISTRY,
  });
  assert.equal(
    ghcrPlan.container.image,
    'ghcr.io/omnisolo-llc/omniterm/cloud:cloud-staging-latest',
  );
});

test('executeEnvironmentRollout invokes rollout-env.sh and prune-ghcr-packages.mjs with Docker Hub and GHCR credentials', () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'omni-rollout-test-'));
  try {
    fs.mkdirSync(path.join(tempRoot, 'scripts'), { recursive: true });
    fs.writeFileSync(
      path.join(tempRoot, 'scripts', 'rollout-env.sh'),
      '#!/usr/bin/env bash\nexit 0\n',
      { mode: 0o755 },
    );
    fs.writeFileSync(
      path.join(tempRoot, 'scripts', 'prune-ghcr-packages.mjs'),
      '#!/usr/bin/env node\n',
      { mode: 0o755 },
    );

    const calls = [];
    const result = executeEnvironmentRollout({
      environment: 'staging',
      version: '0.1.1',
      buildNumber: '18',
      sourceSha: 'a'.repeat(40),
      sourceRoot: tempRoot,
      githubToken: 'ghs_test_token',
      dockerHubUsername: 'omniterm',
      dockerHubPatReadWrite: 'dckr_pat_rw_test',
      dockerHubPatReadOnly: 'dckr_pat_ro_test',
      execFileImpl: (cmd, args, opts) => {
        if (cmd === 'git') {
          if (args.includes('--show-toplevel')) return `${tempRoot}\n`;
          if (args.includes('status')) return '';
          return `${'a'.repeat(40)}\n`;
        }
        calls.push({ cmd, args, cwd: opts.cwd, env: opts.env });
      },
    });

    assert.equal(result.status, 'rolled-out');
    assert.equal(calls.length, 2);
    assert.equal(calls[0].cmd, 'bash');
    assert.deepEqual(calls[0].args, [
      'scripts/rollout-env.sh',
      '--env',
      'staging',
    ]);
    assert.equal(calls[0].env.OMNI_REGISTRY, 'omniterm/omni');
    assert.equal(calls[0].env.DOCKER_HUB_USERNAME, 'omniterm');
    assert.equal(calls[0].env.DOCKER_HUB_PAT_READ_WRITE, 'dckr_pat_rw_test');
    assert.equal(calls[0].env.DOCKER_HUB_PAT_READ_ONLY, 'dckr_pat_ro_test');
    assert.equal(calls[0].env.GITHUB_TOKEN, 'ghs_test_token');
    assert.equal(calls[1].cmd, 'node');
    assert.deepEqual(calls[1].args, ['scripts/prune-ghcr-packages.mjs']);
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});

test('release and promote-release workflows wire staging/production rollout and Docker Hub + GHCR credentials', () => {
  const workflowsDir = path.resolve(
    path.dirname(new URL(import.meta.url).pathname),
    '../.github/workflows',
  );
  const promoteYml = fs.readFileSync(
    path.join(workflowsDir, 'promote-release.yml'),
    'utf8',
  );
  const releaseYml = fs.readFileSync(
    path.join(workflowsDir, 'release.yml'),
    'utf8',
  );

  assert.match(promoteYml, /rollout_environment:/);
  assert.match(promoteYml, /packages:\s*write/);
  assert.match(promoteYml, /PROMOTE_CONTAINER_REGISTRY:\s*omniterm\/omni/);
  assert.match(promoteYml, /DOCKER_HUB_USERNAME:\s*omniterm/);
  assert.match(
    promoteYml,
    /DOCKER_HUB_PAT_READ_WRITE:\s*\$\{\{\s*secrets\.DOCKER_HUB_PAT_READ_WRITE\s*\}\}/,
  );
  assert.match(
    promoteYml,
    /PROMOTE_ROLLOUT_ENVIRONMENT:\s*\$\{\{\s*(?:inputs\.rollout_environment|steps\.rollout_environment\.outputs\.environment)\s*\}\}/,
  );
  assert.match(releaseYml, /-f rollout_environment=staging/);
});

function makeRolloutSourceFixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'omni-rollout-guard-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  fs.mkdirSync(path.join(root, 'scripts'));
  fs.writeFileSync(path.join(root, 'scripts/rollout-env.sh'), '# mock rollout\n');
  fs.writeFileSync(path.join(root, 'scripts/prune-ghcr-packages.mjs'), '// mock prune\n');
  return root;
}

function rolloutCheckoutMock(root, { head = 'a'.repeat(40), status = '', topLevel = root, failure = '' } = {}) {
  const actions = [];
  const execFileImpl = (cmd, args) => {
    if (cmd !== 'git') {
      actions.push({ cmd, args });
      return '';
    }
    if (failure) throw new Error(failure);
    if (args.includes('--show-toplevel')) return `${topLevel}\n`;
    if (args.includes('status')) return status;
    return `${head}\n`;
  };
  return { actions, execFileImpl };
}

test('rollout rejects a local checkout at a different commit before rollout or pruning', (t) => {
  const sourceRoot = makeRolloutSourceFixture(t);
  const mock = rolloutCheckoutMock(sourceRoot, { head: 'b'.repeat(40) });
  assert.throws(() => executeEnvironmentRollout({
    environment: 'staging', version: '0.1.1', sourceSha: 'a'.repeat(40), sourceRoot,
    execFileImpl: mock.execFileImpl,
  }), /source checkout.*(?:commit|HEAD|source_sha)/i);
  assert.deepEqual(mock.actions, []);
});

test('rollout checks PROMOTE_SOURCE_ROOT against the approved source commit', (t) => {
  const sourceRoot = makeRolloutSourceFixture(t);
  const prior = process.env.PROMOTE_SOURCE_ROOT;
  process.env.PROMOTE_SOURCE_ROOT = sourceRoot;
  t.after(() => {
    if (prior === undefined) delete process.env.PROMOTE_SOURCE_ROOT;
    else process.env.PROMOTE_SOURCE_ROOT = prior;
  });
  const mock = rolloutCheckoutMock(sourceRoot, { head: 'b'.repeat(40) });
  assert.throws(() => executeEnvironmentRollout({
    environment: 'staging', version: '0.1.1', sourceSha: 'a'.repeat(40),
    execFileImpl: mock.execFileImpl,
  }), /source checkout.*(?:commit|HEAD|source_sha)/i);
  assert.deepEqual(mock.actions, []);
});

for (const [name, sourceSha] of [
  ['missing', ''], ['abbreviated', 'a'.repeat(7)], ['invalid', 'g'.repeat(40)],
]) {
  test(`rollout rejects ${name} source SHA before any subprocess`, (t) => {
    const sourceRoot = makeRolloutSourceFixture(t);
    const calls = [];
    assert.throws(() => executeEnvironmentRollout({
      environment: 'staging', version: '0.1.1', sourceSha, sourceRoot,
      execFileImpl: (cmd, args) => { calls.push({ cmd, args }); return ''; },
    }), /source_sha.*40|40.*source_sha/i);
    assert.deepEqual(calls, []);
  });
}

for (const [name, status] of [
  ['modified tracked files', ' M scripts/rollout-env.sh\n'],
  ['staged files', 'M  scripts/rollout-env.sh\n'],
  ['untracked files', '?? scripts/local-deploy.sh\n'],
  ['dirty submodules', ' m myk3s\n'],
]) {
  test(`rollout rejects ${name} before rollout or pruning`, (t) => {
    const sourceRoot = makeRolloutSourceFixture(t);
    const mock = rolloutCheckoutMock(sourceRoot, { status });
    assert.throws(() => executeEnvironmentRollout({
      environment: 'staging', version: '0.1.1', sourceSha: 'a'.repeat(40), sourceRoot,
      execFileImpl: mock.execFileImpl,
    }), /source checkout.*(?:dirty|clean|changes)/i);
    assert.deepEqual(mock.actions, []);
  });
}

test('rollout rejects a directory inside another checkout root', (t) => {
  const sourceRoot = makeRolloutSourceFixture(t);
  const mock = rolloutCheckoutMock(sourceRoot, { topLevel: path.dirname(sourceRoot) });
  assert.throws(() => executeEnvironmentRollout({
    environment: 'staging', version: '0.1.1', sourceSha: 'a'.repeat(40), sourceRoot,
    execFileImpl: mock.execFileImpl,
  }), /source checkout.*root/i);
  assert.deepEqual(mock.actions, []);
});

test('rollout fails closed when checkout identity cannot be read', (t) => {
  const sourceRoot = makeRolloutSourceFixture(t);
  const mock = rolloutCheckoutMock(sourceRoot, { failure: 'mock repository read error' });
  assert.throws(() => executeEnvironmentRollout({
    environment: 'staging', version: '0.1.1', sourceSha: 'a'.repeat(40), sourceRoot,
    execFileImpl: mock.execFileImpl,
  }), /source checkout/i);
  assert.deepEqual(mock.actions, []);
});

test('rollout fails closed when no source checkout or checkout token is supplied', () => {
  const calls = [];
  assert.throws(() => executeEnvironmentRollout({
    environment: 'staging', version: '0.1.1', sourceSha: 'a'.repeat(40),
    execFileImpl: (cmd, args) => { calls.push({ cmd, args }); },
  }), /source checkout/i);
  assert.deepEqual(calls, []);
});

test('rollout fails closed when the checked source has no rollout script', (t) => {
  const sourceRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'omni-rollout-missing-'));
  t.after(() => fs.rmSync(sourceRoot, { recursive: true, force: true }));
  const mock = rolloutCheckoutMock(sourceRoot);
  assert.throws(() => executeEnvironmentRollout({
    environment: 'staging', version: '0.1.1', sourceSha: 'a'.repeat(40), sourceRoot,
    execFileImpl: mock.execFileImpl,
  }), /source checkout.*rollout.*script/i);
  assert.deepEqual(mock.actions, []);
});

function acquiredRolloutCheckoutMock({ head = 'a'.repeat(40) } = {}) {
  const calls = [];
  let checkoutRoot = '';
  const execFileImpl = (cmd, args, opts = {}) => {
    calls.push({ cmd, args, opts });
    if (cmd !== 'git') return '';
    if (args[0] === 'init') checkoutRoot = args[1];
    if (args.includes('checkout')) {
      fs.mkdirSync(path.join(checkoutRoot, 'scripts'));
      fs.writeFileSync(path.join(checkoutRoot, 'scripts/rollout-env.sh'), '# mock rollout\n');
      fs.writeFileSync(path.join(checkoutRoot, 'scripts/prune-ghcr-packages.mjs'), '// mock prune\n');
    }
    if (args.includes('--show-toplevel')) return `${checkoutRoot}\n`;
    if (args.includes('status')) return '';
    return `${head}\n`;
  };
  return { calls, execFileImpl };
}

test('rollout acquisition keeps checkout credentials out of Git arguments and supplies fetch-only authentication', () => {
  const mockToken = 'mock-private-checkout-token';
  const mock = acquiredRolloutCheckoutMock();
  const result = executeEnvironmentRollout({
    environment: 'staging', version: '0.1.1', sourceSha: 'a'.repeat(40),
    privateToken: mockToken, githubToken: 'mock-ghcr-token', execFileImpl: mock.execFileImpl,
  });
  assert.equal(result.status, 'rolled-out');
  assert.equal(mock.calls.some(({ args }) => args.some((arg) => String(arg).includes(mockToken))), false,
    'Checkout credentials must not appear in Git arguments');
  const remote = mock.calls.find(({ args }) => args.includes('remote'));
  assert.equal(remote.args.at(-1), 'https://github.com/omnisolo-llc/omniterm.git');
  const fetch = mock.calls.find(({ args }) => args.includes('fetch'));
  assert.equal(fetch.args.at(-1), 'a'.repeat(40));
  assert.equal(fetch.opts.env.GIT_TERMINAL_PROMPT, '0');
  assert.equal(fetch.opts.env.GIT_CONFIG_COUNT, '1');
  assert.equal(fetch.opts.env.GIT_CONFIG_KEY_0, 'http.https://github.com/.extraheader');
  assert.equal(fetch.opts.env.GIT_CONFIG_VALUE_0,
    `AUTHORIZATION: basic ${Buffer.from(`x-access-token:${mockToken}`).toString('base64')}`);
  for (const call of mock.calls.filter(({ args }) => !args.includes('fetch'))) {
    assert.equal(call.opts.env?.GIT_CONFIG_VALUE_0, undefined);
  }
});

test('rollout verifies the acquired checkout before rollout or pruning', () => {
  const mock = acquiredRolloutCheckoutMock({ head: 'b'.repeat(40) });
  assert.throws(() => executeEnvironmentRollout({
    environment: 'staging', version: '0.1.1', sourceSha: 'a'.repeat(40),
    privateToken: 'mock-private-checkout-token', execFileImpl: mock.execFileImpl,
  }), /source checkout.*(?:commit|HEAD|source_sha)/i);
  assert.equal(mock.calls.some(({ cmd }) => cmd === 'bash' || cmd === 'node'), false);
});

test('rollout acquisition errors do not expose checkout credentials', () => {
  const mockToken = 'mock-private-checkout-token';
  assert.throws(() => executeEnvironmentRollout({
    environment: 'staging', version: '0.1.1', sourceSha: 'a'.repeat(40), privateToken: mockToken,
    execFileImpl: () => { throw new Error(`mock Git command error ${mockToken}`); },
  }), (err) => /source checkout/i.test(err.message) && !err.message.includes(mockToken));
});

function releaseWorkflowJob(filename, job) {
  const workflow = fs.readFileSync(path.resolve(import.meta.dirname, '../.github/workflows', filename), 'utf8');
  const block = workflow.match(new RegExp(`^  ${job}:\\n([\\s\\S]*?)(?=^  [a-z_]+:\\n|(?![\\s\\S]))`, 'm'));
  assert.ok(block, `Workflow job ${job} must exist`);
  return block[1];
}

function releaseWorkflowStep(job, name) {
  const step = job.split(/^      - /m).find((block) => block.startsWith(`name: ${name}\n`));
  assert.ok(step, `Workflow step ${name} must exist`);
  return step;
}

test('publication pins Node 24 before preparing public candidate bytes', () => {
  const publish = releaseWorkflowJob('release.yml', 'publish');
  const setup = publish.indexOf('uses: actions/setup-node@820762786026740c76f36085b0efc47a31fe5020');
  assert.ok(setup >= 0, 'Publication must pin setup-node');
  assert.match(publish.slice(setup), /node-version: '24\.21\.0'\n          package-manager-cache: false/);
  assert.ok(setup < publish.indexOf('run: bash ci/native-release/run.sh prepare-publication'));
});

test('publication retains the complete private archive before publication', () => {
  const publish = releaseWorkflowJob('release.yml', 'publish');
  const archive = releaseWorkflowStep(publish, 'Retain the complete private encrypted archive');
  assert.match(archive, /id: private_final_archive\n        run: bash ci\/native-release\/run\.sh prepare-private-final-archive/);
  assert.match(archive, /APPROVED_NATIVE_VERIFIER_SHA256: \$\{\{ steps\.publication_candidates\.outputs\.native_verifier_sha256 \}\}/);
  assert.match(archive, /APPROVED_PUBLICATION_PLAN_SHA256: \$\{\{ steps\.publication_candidates\.outputs\.publication_plan_sha256 \}\}/);
  assert.match(archive, /PRIVATE_FINAL_ARCHIVE_INPUTS_FILE: \$\{\{ vars\.PRIVATE_FINAL_ARCHIVE_INPUTS_FILE \}\}/);
  assert.doesNotMatch(archive, /(?:if|continue-on-error):/);
  assert.ok(publish.indexOf(archive) < publish.indexOf('name: Publish the verified public candidate bytes'));
});

test('publication independently reads back the complete private archive before publication', () => {
  const publish = releaseWorkflowJob('release.yml', 'publish');
  const readback = releaseWorkflowStep(publish, 'Independently read back the complete private archive');
  assert.match(readback, /id: private_final_archive_readback\n        run: bash ci\/native-release\/run\.sh verify-private-final-archive/);
  assert.doesNotMatch(readback, /(?:if|continue-on-error):/);
  assert.ok(publish.indexOf('run: bash ci/native-release/run.sh prepare-private-final-archive') < publish.indexOf(readback));
  assert.ok(publish.indexOf(readback) < publish.indexOf('name: Publish the verified public candidate bytes'));
});

test('public publication is gated on the independent private archive proof hash', () => {
  const publish = releaseWorkflowJob('release.yml', 'publish');
  const publication = releaseWorkflowStep(publish, 'Publish the verified public candidate bytes');
  assert.match(publication, /APPROVED_PRIVATE_ARCHIVE_PROOF_SHA256: \$\{\{ steps\.private_final_archive_readback\.outputs\.private_archive_proof_sha256 \}\}/);
});

test('Linux promotion resolves rollout from all actual inputs, including Apple-only promotions', () => {
  const job = releaseWorkflowJob('promote-release.yml', 'promote');
  const step = releaseWorkflowStep(job, 'Resolve environment rollout from all promotion inputs');
  assert.match(step, /id: rollout_environment/);
  const inputNames = {
    INPUT_ROLLOUT_ENVIRONMENT: 'rollout_environment', INPUT_PUBLISH_GITHUB_RELEASE: 'publish_github_release',
    INPUT_IOS_STORE_ACTION: 'ios_store_action', INPUT_MACOS_STORE_ACTION: 'macos_store_action',
    INPUT_ANDROID_STORE_ACTION: 'android_store_action', INPUT_VERIFY_STORE_CREDENTIALS_ONLY: 'verify_store_credentials_only',
  };
  for (const [envName, inputName] of Object.entries(inputNames)) {
    assert.match(step, new RegExp(`${envName}: \\$\\{\\{ inputs\\.${inputName} \\}\\}`));
  }
  const nodeScript = step.match(/^          node --input-type=module <<'NODE'\n([\s\S]+)^          NODE\s*$/m);
  assert.ok(nodeScript, 'Rollout resolver must run the shared helper');
  const script = nodeScript[1].replace(/^          /gm, '')
    .replace("import fs from 'node:fs';", '')
    .replace("import { resolveRolloutEnvironment } from './ci/promote-release.mjs';", '');
  const cases = [
    [{ INPUT_IOS_STORE_ACTION: 'testflight' }, 'staging'],
    [{ INPUT_MACOS_STORE_ACTION: 'testflight' }, 'staging'],
    [{ INPUT_IOS_STORE_ACTION: 'app-store' }, 'production'],
    [{ INPUT_MACOS_STORE_ACTION: 'app-store' }, 'production'],
    [{ INPUT_ANDROID_STORE_ACTION: 'internal' }, 'staging'],
    [{ INPUT_PUBLISH_GITHUB_RELEASE: 'true', INPUT_IOS_STORE_ACTION: 'testflight' }, 'production'],
    [{ INPUT_ROLLOUT_ENVIRONMENT: 'none', INPUT_IOS_STORE_ACTION: 'testflight' }, 'none'],
    [{ INPUT_ROLLOUT_ENVIRONMENT: 'staging', INPUT_PUBLISH_GITHUB_RELEASE: 'true' }, 'staging'],
    [{ INPUT_ROLLOUT_ENVIRONMENT: 'production', INPUT_IOS_STORE_ACTION: 'testflight' }, 'production'],
    [{ INPUT_VERIFY_STORE_CREDENTIALS_ONLY: 'true', INPUT_IOS_STORE_ACTION: 'app-store' }, 'none'],
  ];
  for (const [inputs, expected] of cases) {
    const outputs = [];
    vm.runInNewContext(script, {
      fs: { appendFileSync: (file, text) => { assert.equal(file, 'mock-workflow-output'); outputs.push(text); } },
      resolveRolloutEnvironment,
      process: { env: {
        INPUT_ROLLOUT_ENVIRONMENT: 'auto', INPUT_PUBLISH_GITHUB_RELEASE: 'false',
        INPUT_IOS_STORE_ACTION: 'none', INPUT_MACOS_STORE_ACTION: 'none', INPUT_ANDROID_STORE_ACTION: 'none',
        INPUT_VERIFY_STORE_CREDENTIALS_ONLY: 'false', GITHUB_OUTPUT: 'mock-workflow-output', ...inputs,
      } },
    });
    assert.deepEqual(outputs, [`environment=${expected}\n`]);
  }
  const promotion = releaseWorkflowStep(job, 'Promote verified public release, Play Store track, and environment rollout');
  assert.match(promotion, /PROMOTE_ROLLOUT_ENVIRONMENT: \$\{\{ steps\.rollout_environment\.outputs\.environment \}\}/);
  assert.match(promotion, /PROMOTE_IOS_STORE_ACTION: none\n          PROMOTE_MACOS_STORE_ACTION: none/);
  assert.ok(job.indexOf(step) < job.indexOf(promotion));
});

test('Linux promotion waits for requested Apple promotions to succeed', () => {
  const job = releaseWorkflowJob('promote-release.yml', 'promote');
  assert.match(job, /needs: \[promote_apple\]/);
  assert.match(job, /needs\.promote_apple\.result == 'success' \|\| needs\.promote_apple\.result == 'skipped'/);
});

test('Linux promotion forwards the approved gateway source image repository variable', () => {
  const job = releaseWorkflowJob('promote-release.yml', 'promote');
  const promotion = releaseWorkflowStep(job, 'Promote verified public release, Play Store track, and environment rollout');
  assert.match(promotion, /^          OMNI_GATEWAY_SOURCE_IMAGE: \$\{\{ vars\.OMNI_GATEWAY_SOURCE_IMAGE \}\}$/m);
});

for (const name of ['CLOUDFLARE_API_TOKEN', 'CLOUDFLARE_ACCOUNT_ID']) {
  test(`Linux promotion forwards the existing ${name} secret selector`, () => {
    const job = releaseWorkflowJob('promote-release.yml', 'promote');
    const promotion = releaseWorkflowStep(job, 'Promote verified public release, Play Store track, and environment rollout');
    assert.match(promotion, new RegExp(`^          ${name}: \\$\\{\\{ secrets\\.${name} \\}\\}$`, 'm'));
  });
}

test('Linux promotion forwards the existing KUBECONFIG secret selector', () => {
  const job = releaseWorkflowJob('promote-release.yml', 'promote');
  const promotion = releaseWorkflowStep(job, 'Promote verified public release, Play Store track, and environment rollout');
  assert.match(promotion, /^          KUBECONFIG: \$\{\{ secrets\.KUBECONFIG \}\}$/m);
});

for (const name of Object.keys(mockRolloutCredentials)) {
  for (const [label, value] of [['missing', undefined], ['blank', ' \n\t ']]) {
    test(`rollout rejects ${label} ${name} before any subprocess`, (t) => {
      const sourceRoot = makeRolloutSourceFixture(t);
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
      const calls = [];
      assert.throws(() => executeEnvironmentRollout({
        environment: 'staging', version: '0.1.1', sourceSha: 'a'.repeat(40), sourceRoot,
        execFileImpl: (cmd, args) => { calls.push({ cmd, args }); return ''; },
      }), new RegExp(`${name}.*required`, 'i'));
      assert.deepEqual(calls, []);
    });
  }
}

function assertPrivateKubeconfig(filename, expectedBytes) {
  assert.equal(fs.statSync(filename).isFile(), true);
  assert.equal(fs.statSync(filename).mode & 0o777, 0o600);
  assert.equal(fs.statSync(path.dirname(filename)).mode & 0o777, 0o700);
  if (process.getuid) assert.equal(fs.statSync(filename).uid, process.getuid());
  assert.deepEqual(fs.readFileSync(filename), expectedBytes);
}

test('rollout preserves opaque KUBECONFIG content privately and forwards Cloudflare credentials without logging', (t) => {
  const sourceRoot = makeRolloutSourceFixture(t);
  const opaque = `apiVersion: v1\nusers:\n- user:\n    token: mock-${'x'.repeat(8192)}\n  name: fixture\n\n`;
  process.env.KUBECONFIG = opaque;
  const mock = rolloutCheckoutMock(sourceRoot);
  const actions = [];
  const reported = [];
  const previousConsole = {};
  for (const name of ['log', 'error', 'warn']) {
    previousConsole[name] = console[name];
    console[name] = (...args) => { reported.push(args); };
  }
  let result;
  try {
    result = executeEnvironmentRollout({
      environment: 'staging', version: '0.1.1', sourceSha: 'a'.repeat(40), sourceRoot,
      execFileImpl: (cmd, args, opts) => {
        assert.notEqual(opts.env.KUBECONFIG, opaque);
        assertPrivateKubeconfig(opts.env.KUBECONFIG, Buffer.from(opaque));
        if (cmd === 'git') return mock.execFileImpl(cmd, args);
        assert.equal(opts.env.CLOUDFLARE_API_TOKEN, mockRolloutCredentials.CLOUDFLARE_API_TOKEN);
        assert.equal(opts.env.CLOUDFLARE_ACCOUNT_ID, mockRolloutCredentials.CLOUDFLARE_ACCOUNT_ID);
        assert.equal(args.some((arg) => String(arg).includes(opaque)), false);
        actions.push({ cmd, filename: opts.env.KUBECONFIG });
      },
    });
  } finally {
    for (const [name, value] of Object.entries(previousConsole)) console[name] = value;
  }
  assert.equal(result.status, 'rolled-out');
  assert.deepEqual(actions.map(({ cmd }) => cmd), ['bash', 'node']);
  assert.equal(actions[0].filename, actions[1].filename);
  assert.equal(fs.existsSync(actions[0].filename), false);
  assert.equal(fs.existsSync(path.dirname(actions[0].filename)), false);
  assert.deepEqual(reported, []);
  assert.equal(process.env.KUBECONFIG, opaque);
});

test('rollout copies a KUBECONFIG filename into an owned private file and preserves the original', (t) => {
  const sourceRoot = makeRolloutSourceFixture(t);
  const configuredFile = path.join(sourceRoot, 'cluster config.yaml');
  const configBytes = Buffer.from(mockRolloutCredentials.KUBECONFIG);
  fs.writeFileSync(configuredFile, configBytes, { mode: 0o640 });
  process.env.KUBECONFIG = configuredFile;
  const mock = rolloutCheckoutMock(sourceRoot);
  let usedFile;
  const result = executeEnvironmentRollout({
    environment: 'production', version: '0.1.1', sourceSha: 'a'.repeat(40), sourceRoot,
    execFileImpl: (cmd, args, opts) => {
      assert.notEqual(opts.env.KUBECONFIG, configuredFile);
      assertPrivateKubeconfig(opts.env.KUBECONFIG, configBytes);
      if (cmd === 'git') return mock.execFileImpl(cmd, args);
      usedFile = opts.env.KUBECONFIG;
    },
  });
  assert.equal(result.status, 'rolled-out');
  assert.equal(fs.existsSync(usedFile), false);
  assert.deepEqual(fs.readFileSync(configuredFile), configBytes);
  assert.equal(fs.statSync(configuredFile).mode & 0o777, 0o640);
});

for (const kind of ['directory', 'empty file']) {
  test(`rollout rejects a KUBECONFIG ${kind} before any subprocess without exposing the input`, (t) => {
    const sourceRoot = makeRolloutSourceFixture(t);
    const configuredPath = path.join(sourceRoot, `mock-private-${kind.replace(' ', '-')}`);
    if (kind === 'directory') fs.mkdirSync(configuredPath);
    else fs.writeFileSync(configuredPath, ' \n\t ');
    process.env.KUBECONFIG = configuredPath;
    const calls = [];
    assert.throws(() => executeEnvironmentRollout({
      environment: 'staging', version: '0.1.1', sourceSha: 'a'.repeat(40), sourceRoot,
      execFileImpl: (cmd, args) => { calls.push({ cmd, args }); return ''; },
    }), (error) => /KUBECONFIG.*(?:regular file|empty|required)/i.test(error.message) && !error.message.includes(configuredPath));
    assert.deepEqual(calls, []);
  });
}

for (const failingCommand of ['bash', 'node']) {
  test(`rollout removes its private KUBECONFIG when ${failingCommand} fails`, (t) => {
    const sourceRoot = makeRolloutSourceFixture(t);
    const mock = rolloutCheckoutMock(sourceRoot);
    let usedFile;
    assert.throws(() => executeEnvironmentRollout({
      environment: 'staging', version: '0.1.1', sourceSha: 'a'.repeat(40), sourceRoot,
      execFileImpl: (cmd, args, opts) => {
        if (cmd === 'git') return mock.execFileImpl(cmd, args);
        usedFile = opts.env.KUBECONFIG;
        assertPrivateKubeconfig(usedFile, Buffer.from(mockRolloutCredentials.KUBECONFIG));
        if (cmd === failingCommand) throw new Error(`mock ${cmd} failure`);
      },
    }), new RegExp(`mock ${failingCommand} failure`));
    assert.equal(fs.existsSync(usedFile), false);
    assert.equal(fs.existsSync(path.dirname(usedFile)), false);
  });
}

test('rollout removes its private KUBECONFIG when source acquisition fails', () => {
  let usedFile;
  assert.throws(() => executeEnvironmentRollout({
    environment: 'staging', version: '0.1.1', sourceSha: 'a'.repeat(40),
    privateToken: 'mock-private-checkout-token',
    execFileImpl: (cmd, args, opts) => {
      usedFile = opts.env.KUBECONFIG;
      assertPrivateKubeconfig(usedFile, Buffer.from(mockRolloutCredentials.KUBECONFIG));
      throw new Error('mock source acquisition failure');
    },
  }), /source checkout/i);
  assert.ok(usedFile);
  assert.equal(fs.existsSync(usedFile), false);
  assert.equal(fs.existsSync(path.dirname(usedFile)), false);
});

for (const name of Object.keys(mockRolloutCredentials)) {
  test(`promotion rejects missing ${name} before contacting any provider`, async (t) => {
    delete process.env[name];
    const previousFetch = globalThis.fetch;
    let providerRequests = 0;
    globalThis.fetch = async () => {
      providerRequests += 1;
      throw new Error('mock unexpected provider request before credential validation');
    };
    t.after(() => { globalThis.fetch = previousFetch; });
    await assert.rejects(promoteRelease({
      version: '0.1.1', privateToken: 'mock-private-release-token',
      publishGithubRelease: false, rolloutEnvironment: 'staging',
    }), new RegExp(`${name}.*required`, 'i'));
    assert.equal(providerRequests, 0);
  });
}

test('credential verification bypasses rollout requirements and provider mutation', async (t) => {
  for (const name of Object.keys(mockRolloutCredentials)) delete process.env[name];
  const previousLog = console.log;
  const reported = [];
  console.log = (message) => { reported.push(message); };
  t.after(() => { console.log = previousLog; });
  const result = await promoteRelease({
    version: '0.1.1', privateToken: 'mock-private-release-token',
    rolloutEnvironment: 'production', verifyStoreCredentialsOnly: true,
  });
  assert.deepEqual(result, { verified_stores: [] });
  assert.deepEqual(reported.map((message) => JSON.parse(message)), [{ verified_stores: [] }]);
});

for (const [label, pin] of [
  ['mutable tag', 'omniterm/gateway:latest'],
  ['missing repository', `@sha256:${'b'.repeat(64)}`],
  ['uppercase algorithm', `omniterm/gateway@SHA256:${'b'.repeat(64)}`],
  ['uppercase digest', `omniterm/gateway@sha256:${'B'.repeat(64)}`],
  ['short digest', `omniterm/gateway@sha256:${'b'.repeat(63)}`],
  ['leading whitespace', ` omniterm/gateway@sha256:${'b'.repeat(64)}`],
]) {
  test(`rollout rejects a gateway source image pin with ${label} before any subprocess`, (t) => {
    process.env.OMNI_GATEWAY_SOURCE_IMAGE = pin;
    const sourceRoot = makeRolloutSourceFixture(t);
    const calls = [];
    assert.throws(() => executeEnvironmentRollout({
      environment: 'staging', version: '0.1.1', sourceSha: 'a'.repeat(40), sourceRoot,
      execFileImpl: (cmd, args) => { calls.push({ cmd, args }); return ''; },
    }), (error) => /OMNI_GATEWAY_SOURCE_IMAGE.*(?:required|immutable)/i.test(error.message) && !error.message.includes(pin));
    assert.deepEqual(calls, []);
  });

  test(`promotion rejects a gateway source image pin with ${label} before contacting any provider`, async (t) => {
    process.env.OMNI_GATEWAY_SOURCE_IMAGE = pin;
    const previousFetch = globalThis.fetch;
    let providerRequests = 0;
    globalThis.fetch = async () => {
      providerRequests += 1;
      throw new Error('mock unexpected provider request before source image pin validation');
    };
    t.after(() => { globalThis.fetch = previousFetch; });
    await assert.rejects(promoteRelease({
      version: '0.1.1', privateToken: 'mock-private-release-token',
      publishGithubRelease: false, rolloutEnvironment: 'staging',
    }), (error) => /OMNI_GATEWAY_SOURCE_IMAGE.*(?:required|immutable)/i.test(error.message) && !error.message.includes(pin));
    assert.equal(providerRequests, 0);
  });
}

for (const repository of ['omniterm/gateway', 'Registry.EXAMPLE:5000/Team/Gateway_1']) {
  test(`rollout forwards a valid gateway source image pin unchanged for ${repository}`, (t) => {
    const pin = `${repository}@sha256:${'b'.repeat(64)}`;
    process.env.OMNI_GATEWAY_SOURCE_IMAGE = pin;
    const sourceRoot = makeRolloutSourceFixture(t);
    const mock = rolloutCheckoutMock(sourceRoot);
    const actions = [];
    const result = executeEnvironmentRollout({
      environment: 'staging', version: '0.1.1', sourceSha: 'a'.repeat(40), sourceRoot,
      execFileImpl: (cmd, args, opts) => {
        assert.equal(opts.env.OMNI_GATEWAY_SOURCE_IMAGE, pin);
        if (cmd === 'git') return mock.execFileImpl(cmd, args);
        actions.push(cmd);
      },
    });
    assert.equal(result.status, 'rolled-out');
    assert.deepEqual(actions, ['bash', 'node']);
  });
}
