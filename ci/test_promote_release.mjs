import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

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
  resolveGpgSigningCredentials,
  resolveRolloutEnvironment,
  scanDirectoryForLeaks,
  scanSelfHostedZipForLeaks,
  sha256Hex,
  verifyAppleStoreAccess,
  verifyGooglePlayStoreAccess,
} from './promote-release.mjs';

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
    /PROMOTE_ROLLOUT_ENVIRONMENT:\s*\$\{\{\s*inputs\.rollout_environment\s*\}\}/,
  );
  assert.match(releaseYml, /-f rollout_environment=staging/);
});


