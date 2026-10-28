import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import vm from 'node:vm';

import {
  GHCR_CONTAINER_REGISTRY,
  LEGACY_KEYRING_ASSET,
  PRIMARY_CONTAINER_REGISTRY,
  PRIMARY_KEYRING_ASSET,
  PUBLIC_TARGETS,
  FORBIDDEN_PRIVATE_TARGETS,
  STORE_LISTINGS,
  assertNoPrivateLeakInPublicMetadata,
  assertStoreTrackIsolation,
  buildEnvironmentRolloutPlan,
  buildPrivateIosStorageKeys,
  buildPublicReleaseBody,
  buildPublicSha256Sums,
  canonicalJson,
  createAppStoreConnectJwt,
  createZipBuffer,
  deployCompiledWebCdnAssets,
  executeEnvironmentRollout,
  filterPublicDownloadLinks,
  filterPublicProvenance,
  mergeAppleSigningConfig,
  mergeWaveStagingMetadata,
  parseInternalTesterEmails,
  promoteAndroidToPlayStore,
  promoteIosToAppStoreConnect,
  promoteMacosToAppStoreConnect,
  promoteRelease,
  pruneGithubReleases,
  pruneSupersededPagesDeployments,
  resolveGpgSigningCredentials,
  resolvePrivateStageRelease,
  resolveRolloutEnvironment,
  resolveStagingKeyringAssetName,
  sanitizePublicLogText,
  scanBufferForLeaks,
  scanDirectoryForLeaks,
  scanSelfHostedZipForLeaks,
  sha256Hex,
  stageCompiledWebCdnAssets,
  syncAppleInternalTesters,
  validateStoreListings,
  verifyAllReleaseBuildsReady,
  verifyAppleStoreAccess,
  verifyGooglePlayStoreAccess,
} from './promote-release.mjs';

delete process.env.GITHUB_ACTOR;

const mockRolloutCredentials = {
  CLOUDFLARE_API_TOKEN: 'mock-cloudflare-rollout-token',
  CLOUDFLARE_ACCOUNT_ID: 'a'.repeat(32),
  KUBECONFIG: 'apiVersion: v1\nkind: Config\nclusters: []\ncontexts: []\nusers: []\n',
  LEAP_GATEWAY_SOURCE_IMAGE: `leapterm/gateway@sha256:${'b'.repeat(64)}`,
};

const mockRolloutConfig = {
  SOURCE_REPOSITORY: 'example-org/private-source',
  PROMOTE_CONTAINER_REGISTRY: 'example-registry/private',
  PROMOTE_GHCR_REGISTRY: 'ghcr.io/example-org/private-cloud',
  PROMOTE_API_ORIGIN: 'https://api.example.test',
  PROMOTE_STAGING_API_ORIGIN: 'https://api.staging.example.test',
  PROMOTE_CLOUD_ORIGIN: 'https://cloud.example.test',
  PROMOTE_STAGING_CLOUD_ORIGIN: 'https://cloud.staging.example.test',
  PROMOTE_ROLLOUT_SCRIPT: 'scripts/rollout.sh',
  PROMOTE_PRUNE_SCRIPT: 'scripts/prune-packages.mjs',
  PROMOTE_K3S_NAMESPACE: 'example-ns',
  PROMOTE_K3S_DEPLOYMENT: 'example-app',
  PROMOTE_K3S_STAGING_DEPLOYMENT: 'example-app-staging',
  DOCKER_HUB_USERNAME: 'example-user',
};

test.beforeEach((t) => {
  const previous = {};
  for (const [name, value] of Object.entries({ ...mockRolloutCredentials, ...mockRolloutConfig })) {
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
    ['windows', `leapterm-${version}-windows-x64.zip`],
    ['linux', `leapterm-${version}-linux-x64.tar.gz`],
    ['macos', `leapterm-${version}-macos-arm64.zip`],
    ['android', `leapterm-${version}-android-universal.apk`],
    ['android-arm', `leapterm-${version}-android-armeabi-v7a.apk`],
    ['android-arm64', `leapterm-${version}-android-arm64-v8a.apk`],
    ['android-x64', `leapterm-${version}-android-x86_64.apk`],
    ['android-aab', `leapterm-${version}-android.aab`],
    ['services-linux', `leapterm-${version}-services-linux-x64.tar.gz`],
    ['services-windows', `leapterm-${version}-services-windows-x64.zip`],
    ['services-macos', `leapterm-${version}-services-macos-arm64.tar.gz`],
    ['agent-deb', `leapterm-${version}-agent-linux-amd64.deb`],
    ['agent-rpm', `leapterm-${version}-agent-linux-x86_64.rpm`],
    ['flutter-web', `leapterm-${version}-flutter-web.tar.gz`],
    ['workstation-web', `leapterm-${version}-workstation-web.tar.gz`],
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
      url: `https://github.com/omnisolo-llc/private-source/releases/download/v${version}/${name}`,
      checksum_url: `https://github.com/omnisolo-llc/private-source/releases/download/v${version}/${name}.sha256`,
      signature_url: `https://github.com/omnisolo-llc/private-source/releases/download/v${version}/${name}.sha256.sig`,
    })),
    self_hosted: {
      name: `leapterm-${version}-self-hosted.zip`,
      bytes: 4096,
      sha256: 'f'.repeat(64),
      url: `https://github.com/omnisolo-llc/private-source/releases/download/v${version}/leapterm-${version}-self-hosted.zip`,
      sha256_url: `https://github.com/omnisolo-llc/private-source/releases/download/v${version}/leapterm-${version}-self-hosted.zip.sha256`,
      signature_url: `https://github.com/omnisolo-llc/private-source/releases/download/v${version}/leapterm-${version}-self-hosted.zip.sha256.sig`,
    },
    ios_delivery: {
      action: 'upload',
      artifact: `leapterm-${version}-ios-private.ipa`,
      url: `https://github.com/omnisolo-llc/private-source/releases/download/v${version}/leapterm-${version}-ios-private.ipa`,
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
  assert.ok(!serialized.includes('omnisolo-llc/private-source/releases'));
  assert.ok(
    serialized.includes(
      'omnisolo-llc/leapterm-release/releases/download/v0.1.1/',
    ),
  );
});

test('filterPublicProvenance strips private targets and masks private source_sha', () => {
  const { stagingProvenance } = makeStagingFixtures('0.1.1');
  stagingProvenance.managed_vpn = {
    supported_platforms: ['linux', 'windows', 'macos', 'android', 'ios'],
    schema_version: 1,
  };
  const pubProv = filterPublicProvenance(stagingProvenance);

  assert.equal(pubProv.inventory_scope, 'public-application-artifacts');
  assert.equal(pubProv.source_sha, stagingProvenance.builder_sha);
  assert.notEqual(pubProv.source_sha, stagingProvenance.source_sha);
  assert.equal(pubProv.artifacts.length, PUBLIC_TARGETS.length);
  assert.equal(pubProv.ios_action, undefined);
  assert.deepEqual(pubProv.managed_vpn.supported_platforms, [
    'linux',
    'windows',
    'macos',
    'android',
  ]);

  const serialized = canonicalJson(pubProv);
  assertNoPrivateLeakInPublicMetadata(
    'leapterm-0.1.1-release-provenance.json',
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
  assert.equal(verifyRes.bundleId, 'com.leapterm.app');
  assert.equal(verifyRes.ascAppId, undefined);
  assert.equal(verifyRes.recentBuilds, undefined);

  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'leap-apple-promote-'));
  try {
    const ipaPath = path.join(tempDir, 'leapterm-0.1.1-ios-private.ipa');
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

    const macPkgPath = path.join(tempDir, 'leapterm-0.1.1-macos.pkg');
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

    const macZipPath = path.join(tempDir, 'leapterm-0.1.1-macos-arm64.zip');
    fs.writeFileSync(macZipPath, 'signed-app-zip-fixture');
    await assert.rejects(
      () =>
        promoteMacosToAppStoreConnect({
          version: '0.1.1',
          buildNumber: '18',
          action: 'testflight',
          packagePath: macZipPath,
          macosSigningConfigJson: appleSigningConfigJson,
          execFileImpl: () => {},
        }),
      /MACOS_INSTALLER_IDENTITY/,
    );

    const zipExecCalls = [];
    const macSigningWithInstaller = JSON.stringify({
      ...JSON.parse(appleSigningConfigJson),
      MACOS_INSTALLER_IDENTITY:
        '3rd Party Mac Developer Installer: OmniSolo LLC (TEAM123456)',
      MACOS_INSTALLER_CERTIFICATE_BASE64: Buffer.from(
        'fixture-p12',
        'utf8',
      ).toString('base64'),
      MACOS_INSTALLER_CERTIFICATE_PASSWORD: 'p12-password',
    });
    const macZipTfRes = await promoteMacosToAppStoreConnect({
      version: '0.1.1',
      buildNumber: '18',
      action: 'testflight',
      packagePath: macZipPath,
      macosSigningConfigJson: macSigningWithInstaller,
      execFileImpl: (cmd, args) => {
        zipExecCalls.push({ cmd, args });
        if (cmd === 'ditto') {
          const extractDir = args[3];
          fs.mkdirSync(path.join(extractDir, 'LeapTerm.app'), {
            recursive: true,
          });
        }
      },
    });
    assert.equal(macZipTfRes.status, 'uploaded-to-testflight');
    assert.ok(
      zipExecCalls.some(
        (c) =>
          c.cmd === 'productbuild' &&
          c.args.includes('--sign') &&
          c.args.includes(
            '3rd Party Mac Developer Installer: OmniSolo LLC (TEAM123456)',
          ) &&
          c.args.includes('--keychain'),
      ),
    );
    assert.ok(
      zipExecCalls.some(
        (c) => c.cmd === 'security' && c.args[0] === 'delete-keychain',
      ),
    );

    for (const prefix of [
      'MACOS_INSTALLER',
      'MACOS_DEVELOPER_ID_INSTALLER',
      'MACOS_DEVELOPER_ID',
    ]) {
      let imported = false;
      const certificateBytes = Buffer.from(`fixture-${prefix}`);
      await promoteMacosToAppStoreConnect({
        version: '0.1.1', buildNumber: '18', action: 'testflight',
        packagePath: macZipPath,
        macosSigningConfigJson: JSON.stringify({
          ...JSON.parse(appleSigningConfigJson),
          MACOS_INSTALLER_IDENTITY: 'fixture installer identity',
          MACOS_DEVELOPER_ID_CERTIFICATE_PASSWORD: 'other-certificate-password',
          [`${prefix}_CERTIFICATE_BASE64`]: certificateBytes.toString('base64'),
          [`${prefix}_CERTIFICATE_PASSWORD`]: '',
        }),
        execFileImpl: (cmd, args) => {
          if (cmd === 'ditto') fs.mkdirSync(path.join(args[3], 'LeapTerm.app'));
          if (cmd === 'security' && args[0] === 'import') {
            imported = true;
            assert.equal(args[args.indexOf('-P') + 1], '');
            assert.deepEqual(fs.readFileSync(args[1]), certificateBytes);
            if (process.platform !== 'win32') {
              assert.equal(fs.statSync(args[1]).mode & 0o777, 0o600);
              assert.equal(fs.statSync(path.dirname(args[1])).mode & 0o777, 0o700);
            }
          }
        },
      });
      assert.equal(imported, true);
    }

    for (const failedOperation of [
      'create-keychain', 'unlock-keychain', 'import', 'set-key-partition-list',
    ]) {
      const failureCalls = [];
      let privateDir;
      let keychainPassword;
      await assert.rejects(promoteMacosToAppStoreConnect({
        version: '0.1.1', buildNumber: '18', action: 'testflight',
        packagePath: macZipPath,
        macosSigningConfigJson: macSigningWithInstaller,
        execFileImpl: (cmd, args) => {
          failureCalls.push({ cmd, args });
          if (cmd === 'ditto') {
            privateDir = path.dirname(args[3]);
            fs.mkdirSync(path.join(args[3], 'LeapTerm.app'));
          }
          if (cmd === 'security' && args[0] === 'create-keychain') {
            keychainPassword = args[args.indexOf('-p') + 1];
          }
          if (cmd === 'security' && args[0] === failedOperation) {
            const error = new Error(`command failed: ${args.join(' ')} p12-password`);
            error.stderr = Buffer.from('provider diagnostic p12-password');
            throw error;
          }
        },
      }), (error) => {
        assert.equal(error.message, 'macOS installer certificate import failed');
        assert.equal(error.message.includes('p12-password'), false);
        assert.equal(error.message.includes(keychainPassword), false);
        assert.equal(error.cause, undefined);
        return true;
      });
      assert.equal(fs.existsSync(privateDir), false);
      assert.ok(failureCalls.some(({ cmd, args }) =>
        cmd === 'security' && args[0] === 'delete-keychain'));
      assert.equal(failureCalls.some(({ cmd }) => cmd === 'xcrun'), false);
    }

    const apiCalls = [];
    const storeRes = await promoteMacosToAppStoreConnect({
      version: '0.1.1',
      buildNumber: '18',
      action: 'app-store',
      automaticRelease: false,
      macosSigningConfigJson: appleSigningConfigJson,
      fetchImpl: async (url, opts = {}) => {
        apiCalls.push({
          url,
          method: opts.method || 'GET',
          body: opts.body ? JSON.parse(opts.body) : null,
        });
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
        if (
          url.endsWith(
            '/v1/appStoreVersions/ver-mac-011/appStoreVersionLocalizations',
          ) &&
          (!opts.method || opts.method === 'GET')
        ) {
          return new Response(
            JSON.stringify({
              data: [
                {
                  id: 'loc-mac-en-us',
                  type: 'appStoreVersionLocalizations',
                  attributes: { locale: 'en-US' },
                },
              ],
            }),
            { status: 200 },
          );
        }
        if (
          url.endsWith('/v1/appStoreVersionLocalizations/loc-mac-en-us') &&
          opts.method === 'PATCH'
        ) {
          return new Response(
            JSON.stringify({
              data: {
                id: 'loc-mac-en-us',
                type: 'appStoreVersionLocalizations',
              },
            }),
            { status: 200 },
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
    assert.equal(apiCalls.length, 7);

    const iosInternalRes = await promoteIosToAppStoreConnect({
      version: '0.1.1',
      buildNumber: '18',
      action: 'internal',
      ipaPath,
      iosSigningConfigJson: appleSigningConfigJson,
      execFileImpl: (cmd, args) => {
        assert.equal(cmd, 'xcrun');
        assert.ok(args.includes('--upload-app'));
        assert.ok(args.includes('ios'));
      },
    });
    assert.equal(iosInternalRes.action, 'internal');
    assert.equal(iosInternalRes.track, 'internal');
    assert.equal(iosInternalRes.status, 'uploaded-to-testflight-internal');

    for (const track of ['alpha', 'beta']) {
      const trackCalls = [];
      const trackRes = await promoteIosToAppStoreConnect({
        version: '0.1.1',
        buildNumber: '18',
        action: track,
        iosSigningConfigJson: appleSigningConfigJson,
        fetchImpl: async (url, opts = {}) => {
          trackCalls.push({ url, method: opts.method || 'GET', body: opts.body ? JSON.parse(opts.body) : null });
          if (url.includes('/v1/apps?')) {
            return new Response(
              JSON.stringify({ data: [{ id: 'app-1', type: 'apps' }] }),
              { status: 200 },
            );
          }
          if (url.includes('/v1/builds?')) {
            return new Response(
              JSON.stringify({
                data: [
                  {
                    id: 'build-ios-18',
                    type: 'builds',
                    attributes: { processingState: 'VALID', expired: false },
                  },
                ],
              }),
              { status: 200 },
            );
          }
          if (url.includes('/betaGroups?')) {
            return new Response(
              JSON.stringify({
                data: [
                  {
                    id: `internal-${track}`,
                    type: 'betaGroups',
                    attributes: { name: track, isInternalGroup: true },
                  },
                  {
                    id: `external-${track}`,
                    type: 'betaGroups',
                    attributes: { name: track.toUpperCase(), isInternalGroup: false },
                  },
                ],
              }),
              { status: 200 },
            );
          }
          if (url.includes('/v1/betaAppReviewSubmissions?')) {
            return new Response(JSON.stringify({ data: [] }), { status: 200 });
          }
          if (url.endsWith('/v1/betaAppReviewSubmissions') && opts.method === 'POST') {
            return new Response(
              JSON.stringify({ data: { id: 'review-1', type: 'betaAppReviewSubmissions' } }),
              { status: 201 },
            );
          }
          if (url.endsWith(`/v1/betaGroups/external-${track}/relationships/builds`) && opts.method === 'POST') {
            return new Response(null, { status: 204 });
          }
          throw new Error(`Unexpected TestFlight ${track} URL: ${url}`);
        },
      });
      assert.equal(trackRes.platform, 'ios');
      assert.equal(trackRes.action, track);
      assert.equal(trackRes.track, track);
      assert.equal(trackRes.asc_beta_group_id, `external-${track}`);
      assert.equal(trackRes.status, `promoted-to-testflight-${track}`);
      assert.equal(trackCalls.length, 6);
      assert.deepEqual(trackCalls.at(-1).body, {
        data: [{ type: 'builds', id: 'build-ios-18' }],
      });
    }
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
    client_email: 'play-publisher@leapterm.iam.gserviceaccount.com',
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
  assert.equal(probeRes.serviceAccount, undefined);
  assert.deepEqual(probeRes.tracks, ['internal', 'production']);

  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'leap-play-promote-'));
  try {
    const aabPath = path.join(tempDir, 'leapterm-0.1.1-android.aab');
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
        if (
          url.endsWith('/edits/edit-99/listings/en-US') &&
          opts.method === 'PUT'
        ) {
          return new Response(JSON.stringify({ language: 'en-US' }), {
            status: 200,
          });
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
    assert.equal(calls.length, 8);
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

test('self-hosted repository files and zip archive pass leak scanner and reject injected leaks', () => {
  const repoRoot = path.resolve(import.meta.dirname, '..');
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'leap-selfhost-test-'));
  try {
    fs.mkdirSync(path.join(tempDir, 'relay'), { recursive: true });
    fs.writeFileSync(
      path.join(tempDir, 'relay/README.md'),
      '# Self-hosted relay\n',
    );
    fs.copyFileSync(
      path.join(repoRoot, 'README.md'),
      path.join(tempDir, 'README.md'),
    );
    fs.writeFileSync(
      path.join(tempDir, 'START-HERE.md'),
      '# Self-host relay kit\n',
    );
    assert.deepEqual(scanDirectoryForLeaks(tempDir), []);

    const zipPath = path.join(tempDir, 'leapterm-0.1.1-self-hosted.zip');
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
        'relay/README.md': 'SOURCE_REPO=omnisolo-llc/private-source\n',
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
    { name: 'leapterm-0.1.1-windows-x64.zip', sha256: 'b'.repeat(64) },
    { name: 'leapterm-0.1.1-linux-x64.tar.gz', sha256: 'a'.repeat(64) },
  ]);
  assert.equal(
    sums,
    `${'a'.repeat(64)}  leapterm-0.1.1-linux-x64.tar.gz\n${'b'.repeat(64)}  leapterm-0.1.1-windows-x64.zip\n`,
  );
  assertNoPrivateLeakInPublicMetadata('SHA256SUMS', sums);
});

test('resolveRolloutEnvironment maps candidate and production promotion inputs and enforces track isolation', () => {
  for (const track of ['internal', 'alpha', 'beta', 'testflight']) {
    const androidTrack = track === 'testflight' ? 'internal' : track;
    assert.equal(
      resolveRolloutEnvironment({
        rolloutEnvironment: 'auto',
        publishGithubRelease: false,
        iosStoreAction: track,
        macosStoreAction: track,
        androidStoreAction: androidTrack,
      }),
      'staging',
    );
  }
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
  assert.throws(
    () =>
      assertStoreTrackIsolation({
        publishGithubRelease: true,
        iosStoreAction: 'internal',
      }),
    /Cannot publish public GitHub Release in the same promotion as pre-release store tracks/,
  );
  assert.throws(
    () =>
      assertStoreTrackIsolation({
        iosStoreAction: 'alpha',
        androidStoreAction: 'beta',
      }),
    /Cannot mix different pre-release store tracks/,
  );
  assert.throws(
    () =>
      assertStoreTrackIsolation({
        iosStoreAction: 'internal',
        androidStoreAction: 'production',
      }),
    /Cannot mix pre-release store tracks.*with public production store tracks/,
  );
  assert.throws(
    () =>
      assertStoreTrackIsolation({
        rolloutEnvironment: 'production',
        androidStoreAction: 'alpha',
      }),
    /Cannot target production rollout_environment when promoting pre-release store tracks/,
  );
});

test('buildEnvironmentRolloutPlan targets Docker Hub example-registry/private primary registry and supports GHCR', () => {
  assert.equal(PRIMARY_CONTAINER_REGISTRY, '');
  assert.equal(GHCR_CONTAINER_REGISTRY, '');

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
    'example-registry/private:cloud-staging-latest',
  );
  assert.equal(
    stagingPlan.cloudflare.api_origin,
    'https://api.staging.example.test',
  );
  assert.equal(
    stagingPlan.cloudflare.cloud_origin,
    'https://cloud.staging.example.test',
  );
  assert.equal(
    stagingPlan.container.image,
    'example-registry/private:cloud-staging-latest',
  );
  assert.equal(
    stagingPlan.container.alias_image,
    'example-registry/private:latest-staging',
  );
  assert.equal(
    stagingPlan.container.client_image,
    'example-registry/private:client-staging-latest',
  );
  assert.equal(stagingPlan.k3s.namespace, 'example-ns');
  assert.equal(stagingPlan.k3s.deployment, 'example-app-staging');
  assert.deepEqual(stagingPlan.rollout_command, [
    'bash',
    'scripts/rollout.sh',
    '--env',
    'staging',
  ]);
  assert.deepEqual(stagingPlan.prune_command, [
    'node',
    'scripts/prune-packages.mjs',
  ]);

  const prodPlan = buildEnvironmentRolloutPlan({
    environment: 'production',
    version: '0.1.1',
    buildNumber: '18',
    sourceSha: '2'.repeat(40),
  });
  assert.equal(prodPlan.environment, 'production');
  assert.equal(prodPlan.containerTag, 'cloud-latest');
  assert.equal(prodPlan.containerImage, 'example-registry/private:cloud-latest');
  assert.equal(prodPlan.cloudflare.api_origin, 'https://api.example.test');
  assert.equal(prodPlan.cloudflare.cloud_origin, 'https://cloud.example.test');
  assert.equal(prodPlan.container.image, 'example-registry/private:cloud-latest');
  assert.equal(prodPlan.container.alias_image, 'example-registry/private:latest');
  assert.equal(prodPlan.container.client_image, 'example-registry/private:client-latest');
  assert.equal(prodPlan.k3s.namespace, 'example-ns');
  assert.equal(prodPlan.k3s.deployment, 'example-app');
  assert.deepEqual(prodPlan.rollout_command, [
    'bash',
    'scripts/rollout.sh',
    '--env',
    'production',
  ]);

  const ghcrPlan = buildEnvironmentRolloutPlan({
    environment: 'staging',
    version: '0.1.1',
    buildNumber: '18',
    sourceSha: '3'.repeat(40),
    containerRegistry: 'ghcr.io/example-org/private-cloud',
  });
  assert.equal(
    ghcrPlan.container.image,
    'ghcr.io/example-org/private-cloud:cloud-staging-latest',
  );
});

test('executeEnvironmentRollout invokes rollout.sh and prune-packages.mjs with Docker Hub and GHCR credentials', () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'leap-rollout-test-'));
  try {
    fs.mkdirSync(path.join(tempRoot, 'scripts'), { recursive: true });
    fs.writeFileSync(
      path.join(tempRoot, 'scripts', 'rollout.sh'),
      '#!/usr/bin/env bash\nexit 0\n',
      { mode: 0o755 },
    );
    fs.writeFileSync(
      path.join(tempRoot, 'scripts', 'prune-packages.mjs'),
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
      dockerHubUsername: 'example-user',
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
      'scripts/rollout.sh',
      '--env',
      'staging',
    ]);
    assert.equal(calls[0].env.LEAP_REGISTRY, 'example-registry/private');
    assert.equal(calls[0].env.DOCKER_HUB_USERNAME, 'example-user');
    assert.equal(calls[0].env.DOCKER_HUB_PAT_READ_WRITE, 'dckr_pat_rw_test');
    assert.equal(calls[0].env.DOCKER_HUB_PAT_READ_ONLY, 'dckr_pat_ro_test');
    assert.equal(calls[0].env.GITHUB_TOKEN, 'ghs_test_token');
    assert.equal(calls[1].cmd, 'node');
    assert.deepEqual(calls[1].args, ['scripts/prune-packages.mjs']);
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});

test('release and promote-release workflows wire staging/production rollout and Docker Hub + GHCR credentials', () => {
  const workflowsDir = path.resolve(
    import.meta.dirname,
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
  assert.match(promoteYml, /PROMOTE_CONTAINER_REGISTRY:\s*\$\{\{\s*secrets\.PROMOTE_CONTAINER_REGISTRY\s*\}\}/);
  assert.match(promoteYml, /DOCKER_HUB_USERNAME:\s*\$\{\{\s*secrets\.DOCKER_HUB_USERNAME\s*\}\}/);
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
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'leap-rollout-guard-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  fs.mkdirSync(path.join(root, 'scripts'));
  fs.writeFileSync(path.join(root, 'scripts/rollout.sh'), '# mock rollout\n');
  fs.writeFileSync(path.join(root, 'scripts/prune-packages.mjs'), '// mock prune\n');
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
  ['modified tracked files', ' M scripts/rollout.sh\n'],
  ['staged files', 'M  scripts/rollout.sh\n'],
  ['untracked files', '?? scripts/local-deploy.sh\n'],
  ['dirty submodules', ' m cluster-submodule\n'],
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
  const sourceRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'leap-rollout-missing-'));
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
      fs.writeFileSync(path.join(checkoutRoot, 'scripts/rollout.sh'), '# mock rollout\n');
      fs.writeFileSync(path.join(checkoutRoot, 'scripts/prune-packages.mjs'), '// mock prune\n');
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
  assert.equal(remote.args.at(-1), 'https://github.com/example-org/private-source.git');
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
  const workflow = fs
    .readFileSync(path.resolve(import.meta.dirname, '../.github/workflows', filename), 'utf8')
    .replace(/\r\n/g, '\n');
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
  const setup = publish.indexOf('uses: actions/setup-node@949feb2413d6458794dcd2491c4babbbce0c15c1');
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
    [{ INPUT_IOS_STORE_ACTION: 'internal' }, 'staging'],
    [{ INPUT_IOS_STORE_ACTION: 'alpha' }, 'staging'],
    [{ INPUT_IOS_STORE_ACTION: 'beta' }, 'staging'],
    [{ INPUT_IOS_STORE_ACTION: 'testflight' }, 'staging'],
    [{ INPUT_MACOS_STORE_ACTION: 'internal' }, 'staging'],
    [{ INPUT_IOS_STORE_ACTION: 'app-store' }, 'production'],
    [{ INPUT_MACOS_STORE_ACTION: 'app-store' }, 'production'],
    [{ INPUT_ANDROID_STORE_ACTION: 'internal' }, 'staging'],
    [{ INPUT_PUBLISH_GITHUB_RELEASE: 'true', INPUT_IOS_STORE_ACTION: 'app-store' }, 'production'],
    [{ INPUT_ROLLOUT_ENVIRONMENT: 'none', INPUT_IOS_STORE_ACTION: 'internal' }, 'none'],
    [{ INPUT_ROLLOUT_ENVIRONMENT: 'staging', INPUT_PUBLISH_GITHUB_RELEASE: 'true' }, 'staging'],
    [{ INPUT_ROLLOUT_ENVIRONMENT: 'production', INPUT_IOS_STORE_ACTION: 'app-store' }, 'production'],
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
  for (const rejectedInputs of [
    { INPUT_PUBLISH_GITHUB_RELEASE: 'true', INPUT_IOS_STORE_ACTION: 'internal' },
    { INPUT_ROLLOUT_ENVIRONMENT: 'production', INPUT_IOS_STORE_ACTION: 'testflight' },
    { INPUT_IOS_STORE_ACTION: 'alpha', INPUT_ANDROID_STORE_ACTION: 'beta' },
  ]) {
    assert.throws(() =>
      vm.runInNewContext(script, {
        fs: { appendFileSync: () => {} },
        resolveRolloutEnvironment,
        process: { env: {
          INPUT_ROLLOUT_ENVIRONMENT: 'auto', INPUT_PUBLISH_GITHUB_RELEASE: 'false',
          INPUT_IOS_STORE_ACTION: 'none', INPUT_MACOS_STORE_ACTION: 'none', INPUT_ANDROID_STORE_ACTION: 'none',
          INPUT_VERIFY_STORE_CREDENTIALS_ONLY: 'false', GITHUB_OUTPUT: 'mock-workflow-output', ...rejectedInputs,
        } },
      }),
    );
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
  assert.match(promotion, /^          LEAP_GATEWAY_SOURCE_IMAGE: \$\{\{ vars\.LEAP_GATEWAY_SOURCE_IMAGE \}\}$/m);
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
  if (process.platform !== 'win32') {
    assert.equal(fs.statSync(filename).mode & 0o777, 0o600);
    assert.equal(fs.statSync(path.dirname(filename)).mode & 0o777, 0o700);
  }
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
  if (process.platform !== 'win32') {
    assert.equal(fs.statSync(configuredFile).mode & 0o777, 0o640);
  }
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
  ['mutable tag', 'leapterm/gateway:latest'],
  ['missing repository', `@sha256:${'b'.repeat(64)}`],
  ['uppercase algorithm', `leapterm/gateway@SHA256:${'b'.repeat(64)}`],
  ['uppercase digest', `leapterm/gateway@sha256:${'B'.repeat(64)}`],
  ['short digest', `leapterm/gateway@sha256:${'b'.repeat(63)}`],
  ['leading whitespace', ` leapterm/gateway@sha256:${'b'.repeat(64)}`],
]) {
  test(`rollout rejects a gateway source image pin with ${label} before any subprocess`, (t) => {
    process.env.LEAP_GATEWAY_SOURCE_IMAGE = pin;
    const sourceRoot = makeRolloutSourceFixture(t);
    const calls = [];
    assert.throws(() => executeEnvironmentRollout({
      environment: 'staging', version: '0.1.1', sourceSha: 'a'.repeat(40), sourceRoot,
      execFileImpl: (cmd, args) => { calls.push({ cmd, args }); return ''; },
    }), (error) => /LEAP_GATEWAY_SOURCE_IMAGE.*(?:required|immutable)/i.test(error.message) && !error.message.includes(pin));
    assert.deepEqual(calls, []);
  });

  test(`promotion rejects a gateway source image pin with ${label} before contacting any provider`, async (t) => {
    process.env.LEAP_GATEWAY_SOURCE_IMAGE = pin;
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
    }), (error) => /LEAP_GATEWAY_SOURCE_IMAGE.*(?:required|immutable)/i.test(error.message) && !error.message.includes(pin));
    assert.equal(providerRequests, 0);
  });
}

for (const repository of ['leapterm/gateway', 'Registry.EXAMPLE:5000/Team/Gateway_1']) {
  test(`rollout forwards a valid gateway source image pin unchanged for ${repository}`, (t) => {
    const pin = `${repository}@sha256:${'b'.repeat(64)}`;
    process.env.LEAP_GATEWAY_SOURCE_IMAGE = pin;
    const sourceRoot = makeRolloutSourceFixture(t);
    const mock = rolloutCheckoutMock(sourceRoot);
    const actions = [];
    const result = executeEnvironmentRollout({
      environment: 'staging', version: '0.1.1', sourceSha: 'a'.repeat(40), sourceRoot,
      execFileImpl: (cmd, args, opts) => {
        assert.equal(opts.env.LEAP_GATEWAY_SOURCE_IMAGE, pin);
        if (cmd === 'git') return mock.execFileImpl(cmd, args);
        actions.push(cmd);
      },
    });
    assert.equal(result.status, 'rolled-out');
    assert.deepEqual(actions, ['bash', 'node']);
  });
}

test('resolveStagingKeyringAssetName prefers leapterm-package-signing-key.gpg and falls back to leapterm-archive-keyring.gpg', async (t) => {
  assert.equal(PRIMARY_KEYRING_ASSET, 'leapterm-package-signing-key.gpg');
  assert.equal(LEGACY_KEYRING_ASSET, 'leapterm-archive-keyring.gpg');

  assert.equal(
    resolveStagingKeyringAssetName(
      new Map([['leapterm-package-signing-key.gpg', { name: 'leapterm-package-signing-key.gpg' }]]),
    ),
    'leapterm-package-signing-key.gpg',
  );
  assert.equal(
    resolveStagingKeyringAssetName(
      new Map([
        ['leapterm-package-signing-key.gpg', { name: 'leapterm-package-signing-key.gpg' }],
        ['leapterm-archive-keyring.gpg', { name: 'leapterm-archive-keyring.gpg' }],
      ]),
    ),
    'leapterm-package-signing-key.gpg',
  );
  assert.equal(
    resolveStagingKeyringAssetName(
      new Map([['leapterm-archive-keyring.gpg', { name: 'leapterm-archive-keyring.gpg' }]]),
    ),
    'leapterm-archive-keyring.gpg',
  );
  assert.equal(resolveStagingKeyringAssetName(new Map()), 'leapterm-package-signing-key.gpg');

  const downloadedUrls = [];
  const previousFetch = globalThis.fetch;
  globalThis.fetch = async (url) => {
    downloadedUrls.push(String(url));
    if (String(url).endsWith('/releases/tags/v0.1.1')) {
      return new Response(
        JSON.stringify({
          assets: [
            {
              name: 'leapterm-package-signing-key.gpg',
              url: 'https://api.github.com/repos/example-org/private-source/releases/assets/101',
            },
          ],
        }),
        { status: 200 },
      );
    }
    if (String(url).endsWith('/releases/assets/101')) {
      return new Response(Buffer.from('mock-gpg-keyring-bytes'), { status: 200 });
    }
    throw new Error(`Unexpected URL: ${url}`);
  };
  t.after(() => {
    globalThis.fetch = previousFetch;
  });

  await assert.rejects(
    promoteRelease({
      version: '0.1.1',
      privateToken: 'mock-private-token',
      publishGithubRelease: false,
      rolloutEnvironment: 'none',
    }),
    /missing required asset: download-links\.json/,
  );
  assert.ok(
    downloadedUrls.includes('https://api.github.com/repos/example-org/private-source/releases/assets/101'),
    'promoteRelease must download leapterm-package-signing-key.gpg when present on the staging release',
  );
});

test('buildPrivateIosStorageKeys supports option1 private/receipts keys and legacy fallback paths', () => {
  const option1Keys = buildPrivateIosStorageKeys({
    version: 'v0.1.1',
    buildNumber: '18',
    runId: '100',
    runAttempt: '1',
    proof: 'abc123proof',
    releaseRoute: 'option1',
  });
  assert.equal(option1Keys.basePrefix, 'releases/v0.1.1/18/100-1');
  assert.equal(option1Keys.prefix, 'releases/v0.1.1/18/100-1/option1');
  assert.equal(
    option1Keys.ipaKey,
    'releases/v0.1.1/18/100-1/option1/private/leapterm-0.1.1-ios-private.ipa',
  );
  assert.equal(
    option1Keys.receiptKey,
    'releases/v0.1.1/18/100-1/option1/receipts/ios-private-artifact.json',
  );
  assert.ok(
    option1Keys.ipaKeys.includes(
      'releases/v0.1.1/18/100-1/option1/private/leapterm-0.1.1-ios-private.ipa',
    ),
  );
  assert.ok(
    option1Keys.ipaKeys.includes(
      'releases/v0.1.1/18/100-1/option1/private-artifacts/leapterm-0.1.1-ios-private.ipa',
    ),
  );
  assert.ok(
    option1Keys.ipaKeys.includes(
      'releases/v0.1.1/18/100-1/private-artifacts/leapterm-0.1.1-ios-private.ipa',
    ),
  );
  assert.ok(
    option1Keys.receiptKeys.includes(
      'releases/v0.1.1/18/100-1/option1/receipts/ios-private-artifact.json',
    ),
  );
  assert.ok(
    option1Keys.receiptKeys.includes(
      'releases/v0.1.1/18/100-1/github-receipts/abc123proof/ios-private-artifact-receipt.json',
    ),
  );

  const legacyKeys = buildPrivateIosStorageKeys({
    version: '0.1.1',
    buildNumber: '18',
    runId: '100',
    attempt: '1',
    proof: 'abc123proof',
    releaseRoute: 'legacy-acceptance',
  });
  assert.equal(legacyKeys.prefix, 'releases/v0.1.1/18/100-1');
  assert.equal(
    legacyKeys.ipaKey,
    'releases/v0.1.1/18/100-1/private-artifacts/leapterm-0.1.1-ios-private.ipa',
  );
  assert.equal(
    legacyKeys.receiptKey,
    'releases/v0.1.1/18/100-1/github-receipts/abc123proof/ios-private-artifact-receipt.json',
  );
  assert.ok(
    legacyKeys.ipaKeys.includes(
      'releases/v0.1.1/18/100-1/option1/private/leapterm-0.1.1-ios-private.ipa',
    ),
  );
  assert.ok(
    legacyKeys.receiptKeys.includes(
      'releases/v0.1.1/18/100-1/option1/receipts/ios-private-artifact.json',
    ),
  );
  assert.equal(option1Keys.channel, 'internal');
  assert.equal(option1Keys.storeEnvironment, 'test_store');

  const alphaKeys = buildPrivateIosStorageKeys({
    version: 'v0.1.1',
    buildNumber: '18',
    runId: '100',
    runAttempt: '1',
    proof: 'abc123proof',
    releaseRoute: 'option1',
    channel: 'alpha',
  });
  assert.equal(alphaKeys.channel, 'alpha');
  assert.equal(alphaKeys.storeEnvironment, 'production');
  assert.equal(alphaKeys.ipaName, 'leapterm-0.1.1-ios-alpha.ipa');
  assert.equal(alphaKeys.receiptAssetName, 'ios-alpha-artifact-receipt.json');
  assert.equal(
    alphaKeys.ipaKey,
    'releases/v0.1.1/18/100-1/option1/private/leapterm-0.1.1-ios-alpha.ipa',
  );
  assert.ok(
    alphaKeys.ipaKeys.includes(
      'releases/v0.1.1/18/100-1/option1/private-artifacts/leapterm-0.1.1-ios-alpha.ipa',
    ),
  );
  assert.ok(
    alphaKeys.receiptKeys.includes(
      'releases/v0.1.1/18/100-1/option1/github-receipts/abc123proof/ios-alpha-artifact-receipt.json',
    ),
  );
});

test('mergeAppleSigningConfig overlays fresh APPLE_CONFIG credentials without clobbering existing certificates', () => {
  const base = JSON.stringify({
    IOS_DISTRIBUTION_CERTIFICATE_BASE64: 'existing-cert-b64',
    APP_STORE_CONNECT_KEY_ID: 'STALEKEY12',
    IOS_PROVISIONING_PROFILE_BASE64: 'stale-profile-b64',
  });
  const appleConfig = JSON.stringify({
    APP_STORE_CONNECT_KEY_ID: 'FRESHKEY34',
    APP_STORE_CONNECT_ISSUER_ID: 'fresh-issuer',
    APP_STORE_CONNECT_API_KEY_BASE64: 'fresh-api-key-b64',
    IOS_PROVISIONING_PROFILE_BASE64: 'fresh-profile-b64',
    MACOS_TEAM_ID: '   ',
  });
  const merged = JSON.parse(mergeAppleSigningConfig(base, appleConfig));
  assert.equal(merged.IOS_DISTRIBUTION_CERTIFICATE_BASE64, 'existing-cert-b64');
  assert.equal(merged.APP_STORE_CONNECT_KEY_ID, 'FRESHKEY34');
  assert.equal(merged.APP_STORE_CONNECT_ISSUER_ID, 'fresh-issuer');
  assert.equal(merged.APP_STORE_CONNECT_API_KEY_BASE64, 'fresh-api-key-b64');
  assert.equal(merged.IOS_PROVISIONING_PROFILE_BASE64, 'fresh-profile-b64');
  assert.equal(merged.MACOS_TEAM_ID, undefined);
  assert.equal(mergeAppleSigningConfig(base, ''), base);
});

test('verifyAllReleaseBuildsReady checks all 9 public targets, self_hosted, and signed assets', () => {
  const { stagingLinks, stagingProvenance } = makeStagingFixtures('0.1.1');
  const assetNames = new Set([
    'download-links.json',
    'leapterm-0.1.1-release-provenance.json',
    'leapterm-0.1.1-release-provenance.json.sig',
    PRIMARY_KEYRING_ASSET,
    stagingLinks.self_hosted.name,
    `${stagingLinks.self_hosted.name}.sha256`,
  ]);
  for (const item of stagingLinks.downloads) {
    if (PUBLIC_TARGETS.includes(item.target)) {
      assetNames.add(item.name);
      assetNames.add(`${item.name}.sha256`);
      assetNames.add(`${item.name}.sha256.sig`);
    }
  }

  const fullCheck = verifyAllReleaseBuildsReady({
    downloadLinks: stagingLinks,
    provenance: stagingProvenance,
    assetsByName: assetNames,
    version: '0.1.1',
  });
  assert.equal(fullCheck.ready, true);
  assert.deepEqual(fullCheck.missingTargets, []);
  assert.deepEqual(fullCheck.missingProvenanceTargets, []);
  assert.deepEqual(fullCheck.missingAssets, []);

  const fastLinks = {
    ...stagingLinks,
    downloads: stagingLinks.downloads.filter((a) => !['windows', 'macos'].includes(a.target)),
  };
  const fastProv = {
    ...stagingProvenance,
    artifacts: stagingProvenance.artifacts.filter((a) => !['windows', 'macos'].includes(a.target)),
  };
  const partialCheck = verifyAllReleaseBuildsReady({
    downloadLinks: fastLinks,
    provenance: fastProv,
    assetsByName: assetNames,
    version: '0.1.1',
  });
  assert.equal(partialCheck.ready, false);
  assert.deepEqual(partialCheck.missingTargets, ['windows', 'macos']);
  assert.deepEqual(partialCheck.missingProvenanceTargets, ['windows', 'macos']);

  const pubFastLinks = filterPublicDownloadLinks(fastLinks, undefined, null, {
    allowPartialWave: true,
  });
  assert.equal(pubFastLinks.artifacts.length, PUBLIC_TARGETS.length - 2);
});

test('mergeWaveStagingMetadata combines fast and slow wave releases and enforces matching source_sha', () => {
  const { stagingLinks, stagingProvenance } = makeStagingFixtures('0.1.1');
  const fastTargets = new Set([
    'linux',
    'android',
    'android-arm',
    'android-arm64',
    'android-x64',
    'agent-deb',
    'agent-rpm',
    'services-linux',
    'flutter-web',
    'workstation-web',
    'android-aab',
  ]);
  const slowTargets = new Set([
    'windows',
    'macos',
    'services-windows',
    'services-macos',
  ]);

  const makeWaveAssets = (downloads, includeSelfHosted) => {
    const assets = [
      { name: 'download-links.json', url: 'https://example.test/dl' },
      { name: 'leapterm-0.1.1-release-provenance.json', url: 'https://example.test/prov' },
      { name: 'leapterm-0.1.1-release-provenance.json.sig', url: 'https://example.test/prov.sig' },
      { name: PRIMARY_KEYRING_ASSET, url: 'https://example.test/key' },
    ];
    for (const item of downloads) {
      if (PUBLIC_TARGETS.includes(item.target)) {
        assets.push({ name: item.name, url: `https://example.test/${item.name}` });
        assets.push({ name: `${item.name}.sha256`, url: `https://example.test/${item.name}.sha256` });
        assets.push({ name: `${item.name}.sha256.sig`, url: `https://example.test/${item.name}.sha256.sig` });
      }
    }
    if (includeSelfHosted) {
      assets.push({ name: stagingLinks.self_hosted.name, url: 'https://example.test/sh.zip' });
      assets.push({ name: `${stagingLinks.self_hosted.name}.sha256`, url: 'https://example.test/sh.zip.sha256' });
    }
    return assets;
  };

  const fastDownloads = stagingLinks.downloads.filter((a) => fastTargets.has(a.target));
  const slowDownloads = stagingLinks.downloads.filter((a) => slowTargets.has(a.target));

  const fastWave = {
    tag: 'v0.1.1-fast',
    downloadLinks: {
      ...stagingLinks,
      tag: 'v0.1.1-fast',
      downloads: fastDownloads,
      ios_delivery: { action: 'skip', channel: 'none', status: 'skipped-in-wave' },
    },
    provenance: {
      ...stagingProvenance,
      artifacts: stagingProvenance.artifacts.filter((a) => fastTargets.has(a.target)),
    },
    assets: makeWaveAssets(fastDownloads, true),
  };

  const slowWave = {
    tag: 'v0.1.1-slow',
    downloadLinks: {
      version: '0.1.1',
      build_number: 18,
      tag: 'v0.1.1-slow',
      downloads: slowDownloads,
      ios_delivery: stagingLinks.ios_delivery,
    },
    provenance: {
      ...stagingProvenance,
      artifacts: stagingProvenance.artifacts.filter((a) => slowTargets.has(a.target)),
    },
    assets: makeWaveAssets(slowDownloads, false),
  };

  const fastOnly = mergeWaveStagingMetadata({
    wavePayloads: [fastWave],
    version: '0.1.1',
  });
  assert.equal(fastOnly.isCompleteWaveSet, false);

  const merged = mergeWaveStagingMetadata({
    wavePayloads: [fastWave, slowWave],
    version: '0.1.1',
  });
  assert.equal(merged.isCompleteWaveSet, true);
  assert.equal(merged.stagingLinks.tag, 'v0.1.1');
  assert.equal(merged.stagingLinks.self_hosted.name, stagingLinks.self_hosted.name);
  assert.equal(merged.stagingLinks.ios_delivery.action, 'upload');

  const pubLinks = filterPublicDownloadLinks(merged.stagingLinks);
  assert.equal(pubLinks.artifacts.length, PUBLIC_TARGETS.length);

  assert.throws(
    () =>
      mergeWaveStagingMetadata({
        wavePayloads: [
          fastWave,
          {
            ...slowWave,
            provenance: { ...slowWave.provenance, source_sha: '3'.repeat(40) },
          },
        ],
        version: '0.1.1',
      }),
    /source_sha mismatch/,
  );
});

test('parseInternalTesterEmails parses comma-separated emails and syncs TestFlight internal testers', async () => {
  assert.deepEqual(parseInternalTesterEmails(''), []);
  assert.deepEqual(parseInternalTesterEmails('   ,  '), []);
  assert.deepEqual(
    parseInternalTesterEmails(
      ' Alice@Example.com , bob@example.com, alice@example.com , ',
    ),
    ['alice@example.com', 'bob@example.com'],
  );
  assert.throws(
    () => parseInternalTesterEmails('alice@example.com, invalid-email'),
    /Invalid email in INTERNAL_TESTER_EMAILS/,
  );

  const { privateKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'prime256v1',
  });
  const pem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  const appleSigningConfigJson = JSON.stringify({
    APP_STORE_CONNECT_KEY_ID: 'ABC1234567',
    APP_STORE_CONNECT_ISSUER_ID: '00000000-0000-0000-0000-000000000001',
    APP_STORE_CONNECT_API_KEY_BASE64: Buffer.from(pem, 'utf8').toString('base64'),
  });

  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'leap-internal-testers-'));
  try {
    const ipaPath = path.join(tempDir, 'leapterm-0.1.1-ios-private.ipa');
    fs.writeFileSync(ipaPath, 'signed-ipa-fixture');

    const apiCalls = [];
    const res = await promoteIosToAppStoreConnect({
      version: '0.1.1',
      buildNumber: '25',
      action: 'internal',
      ipaPath,
      iosSigningConfigJson: appleSigningConfigJson,
      internalTesterEmails: 'alice@example.com, bob@example.com',
      execFileImpl: (cmd, args) => {
        assert.equal(cmd, 'xcrun');
        assert.ok(args.includes('--upload-app'));
      },
      fetchImpl: async (url, opts = {}) => {
        apiCalls.push({
          url,
          method: opts.method || 'GET',
          body: opts.body ? JSON.parse(opts.body) : null,
        });
        if (url.includes('/v1/apps?filter[bundleId]=com.leapterm.app')) {
          return new Response(
            JSON.stringify({ data: [{ id: 'app-1', type: 'apps' }] }),
            { status: 200 },
          );
        }
        if (url.endsWith('/v1/apps/app-1/betaGroups?limit=200')) {
          return new Response(
            JSON.stringify({
              data: [
                {
                  id: 'internal-grp-1',
                  type: 'betaGroups',
                  attributes: { name: 'Internal', isInternalGroup: true },
                },
              ],
            }),
            { status: 200 },
          );
        }
        if (url.endsWith('/v1/betaGroups/internal-grp-1/betaTesters?limit=200')) {
          return new Response(
            JSON.stringify({
              data: [
                {
                  id: 'tester-charlie',
                  type: 'betaTesters',
                  attributes: { email: 'charlie@example.com' },
                },
              ],
            }),
            { status: 200 },
          );
        }
        if (url.includes('/v1/betaTesters?filter[email]=alice%40example.com')) {
          return new Response(
            JSON.stringify({
              data: [
                {
                  id: 'tester-alice',
                  type: 'betaTesters',
                  attributes: { email: 'alice@example.com' },
                },
              ],
            }),
            { status: 200 },
          );
        }
        if (
          url.endsWith('/v1/betaGroups/internal-grp-1/relationships/betaTesters') &&
          opts.method === 'POST'
        ) {
          return new Response(null, { status: 204 });
        }
        if (url.includes('/v1/betaTesters?filter[email]=bob%40example.com')) {
          return new Response(JSON.stringify({ data: [] }), { status: 200 });
        }
        if (url.endsWith('/v1/betaTesters') && opts.method === 'POST') {
          return new Response(
            JSON.stringify({ data: { id: 'tester-bob', type: 'betaTesters' } }),
            { status: 201 },
          );
        }
        throw new Error(`Unexpected ASC URL: ${url}`);
      },
    });

    assert.equal(res.status, 'uploaded-to-testflight-internal');
    assert.equal(res.asc_internal_beta_group_id, 'internal-grp-1');
    assert.deepEqual(res.internal_testers_synced, [
      'alice@example.com',
      'bob@example.com',
    ]);
    assert.equal(apiCalls.length, 7);
    assert.deepEqual(
      apiCalls.find((c) => c.url.endsWith('/relationships/betaTesters'))?.body,
      { data: [{ type: 'betaTesters', id: 'tester-alice' }] },
    );
    assert.deepEqual(
      apiCalls.find((c) => c.url.endsWith('/v1/betaTesters'))?.body,
      {
        data: {
          type: 'betaTesters',
          attributes: { email: 'bob@example.com' },
          relationships: {
            betaGroups: {
              data: [{ type: 'betaGroups', id: 'internal-grp-1' }],
            },
          },
        },
      },
    );
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }

  const workflow = fs.readFileSync(
    path.resolve(import.meta.dirname, '..', '.github/workflows/promote-release.yml'),
    'utf8',
  );
  assert.match(
    workflow,
    /INTERNAL_TESTER_EMAILS:\s*\$\{\{\s*secrets\.INTERNAL_TESTER_EMAILS\s*\}\}/,
  );
  assert.match(
    workflow,
    /ADMIN_OPERATOR_ROLES:\s*\$\{\{\s*secrets\.ADMIN_OPERATOR_ROLES\s*\}\}/,
  );
});

test('install.sh is parsed from GitHub API json response and decoded from base64', () => {
  const mockApiContent = Buffer.from('#!/usr/bin/env bash\necho "installing leap-agent"\n').toString('base64');
  const mockJson = { content: mockApiContent };
  const decoded = Buffer.from(mockJson.content, 'base64').toString('utf8');
  assert.equal(decoded, '#!/usr/bin/env bash\necho "installing leap-agent"\n');
});

test('promoteRelease locates draft or past release in staging by expectedBuildNumber', async (t) => {
  const previousFetch = globalThis.fetch;
  const requestedUrls = [];
  globalThis.fetch = async (url) => {
    requestedUrls.push(String(url));
    if (String(url).endsWith('/releases/tags/v0.1.1-b48')) {
      return new Response(null, { status: 404 });
    }
    if (String(url).endsWith('/releases/tags/v0.1.1-48')) {
      return new Response(null, { status: 404 });
    }
    if (String(url).endsWith('/releases/tags/v0.1.1')) {
      return new Response(null, { status: 404 });
    }
    if (String(url).endsWith('/releases?per_page=100')) {
      return new Response(
        JSON.stringify([
          {
            id: 999,
            tag_name: 'v0.1.1-b48',
            name: 'LeapTerm v0.1.1 (Build 48)',
            draft: true,
            assets: [
              {
                name: 'leapterm-package-signing-key.gpg',
                url: 'https://api.github.com/repos/example-org/private-source/releases/assets/201',
              },
            ],
          },
        ]),
        { status: 200 },
      );
    }
    if (String(url).endsWith('/releases/assets/201')) {
      return new Response(Buffer.from('mock-gpg-keyring-bytes'), { status: 200 });
    }
    throw new Error(`Unexpected URL: ${url}`);
  };
  t.after(() => {
    globalThis.fetch = previousFetch;
  });

  await assert.rejects(
    promoteRelease({
      version: '0.1.1',
      expectedBuildNumber: '48',
      privateToken: 'mock-private-token',
      stagingRepo: 'example-org/private-source',
      publishGithubRelease: false,
      rolloutEnvironment: 'none',
    }),
    /missing required asset: download-links\.json/,
  );
  assert.ok(
    requestedUrls.some((u) => u.includes('/releases?per_page=100')),
    'promoteRelease should query staging releases list to locate past/draft release by build number',
  );
});

test('verifyAllReleaseBuildsReady recognizes self_hosted when present in assetsByName', () => {
  const version = '0.1.1';
  const downloads = PUBLIC_TARGETS.map((target) => ({
    target,
    name: `leapterm-${version}-${target}`,
    sha256: 'a'.repeat(64),
  }));
  const artifacts = downloads.map((d) => ({
    target: d.target,
    name: d.name,
    sha256: d.sha256,
  }));
  const assetsByName = new Set([
    'download-links.json',
    `leapterm-${version}-release-provenance.json`,
    `leapterm-${version}-release-provenance.json.sig`,
    PRIMARY_KEYRING_ASSET,
    `leapterm-${version}-self-hosted.zip`,
    `leapterm-${version}-self-hosted.zip.sha256`,
  ]);
  for (const d of downloads) {
    assetsByName.add(d.name);
    assetsByName.add(`${d.name}.sha256`);
    assetsByName.add(`${d.name}.sha256.sig`);
  }
  const readiness = verifyAllReleaseBuildsReady({
    downloadLinks: { version, downloads },
    provenance: { version, artifacts },
    assetsByName,
    version,
  });
  assert.equal(readiness.ready, true);
  assert.deepEqual(readiness.missingTargets, []);
});

test('promoteAndroidToPlayStore falls back to status draft on draft apps', async () => {
  const { privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
  });
  const pem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  const serviceAccountJson = JSON.stringify({
    type: 'service_account',
    client_email: 'play-publisher@leapterm.iam.gserviceaccount.com',
    private_key: pem,
  });

  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'leap-play-promote-fallback-'));
  try {
    const aabPath = path.join(tempDir, 'leapterm-0.1.1-android.aab');
    fs.writeFileSync(aabPath, Buffer.from('signed-aab-fixture'));

    const calls = [];
    const res = await promoteAndroidToPlayStore({
      version: '0.1.1',
      buildNumber: '19',
      track: 'production',
      aabPath,
      serviceAccountJson,
      fetchImpl: async (url, opts = {}) => {
        calls.push({ url, method: opts.method || 'GET' });
        if (url === 'https://oauth2.googleapis.com/token') {
          return new Response(JSON.stringify({ access_token: 'ya29.fixture' }), { status: 200 });
        }
        if (url.endsWith('/edits') && opts.method === 'POST') {
          return new Response(JSON.stringify({ id: 'edit-draft-test' }), { status: 200 });
        }
        if (url.endsWith('/edits/edit-draft-test/bundles') && opts.method === 'GET') {
          return new Response(JSON.stringify({ bundles: [{ versionCode: 19, sha256: sha256Hex(fs.readFileSync(aabPath)) }] }), { status: 200 });
        }
        if (url.endsWith('/edits/edit-draft-test/listings/en-US') && opts.method === 'PUT') {
          return new Response(JSON.stringify({ language: 'en-US' }), { status: 200 });
        }
        if (url.endsWith('/tracks/production') && opts.method === 'PUT') {
          const body = JSON.parse(opts.body);
          if (body.releases[0].status === 'completed') {
            // First attempt with completed status
            return new Response('{}', { status: 200 });
          }
          if (body.releases[0].status === 'draft') {
            // Second attempt with draft status
            return new Response('{}', { status: 200 });
          }
        }
        if (url.endsWith('/edits/edit-draft-test:validate') && opts.method === 'POST') {
          // If first attempt, throw draft app error
          const lastPut = calls.filter((c) => c.url.includes('/tracks/production')).length;
          if (lastPut === 1) {
            return new Response(
              JSON.stringify({ error: { message: 'Only releases with status draft may be created on draft app.' } }),
              { status: 400 },
            );
          }
          return new Response('{}', { status: 200 });
        }
        if (url.endsWith('/edits/edit-draft-test:commit') && opts.method === 'POST') {
          return new Response('{}', { status: 200 });
        }
        throw new Error(`Unexpected URL: ${url}`);
      },
    });
    assert.equal(res.platform, 'android');
    assert.equal(res.track, 'production');
    assert.equal(res.status, 'committed');
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

test('resolvePrivateStageRelease finds candidate by buildNumber and runId', async () => {
  const version = '0.1.1';
  const buildNumber = '50';
  const runId = '39752987222';
  const attempt = '1';
  const ipaKey = `releases/v${version}/${buildNumber}/${runId}-${attempt}/option1/private-artifacts/leapterm-${version}-ios-private.ipa`;
  const ipaObjName = `object-${sha256Hex(Buffer.from(ipaKey, 'utf8'))}.bin`;

  const mockStageReleases = [
    {
      id: 101,
      tag_name: 'ci-stage/application-39730105381-1',
      assets: [{ name: 'object-dummy.bin' }],
    },
    {
      id: 102,
      tag_name: `ci-stage/application-${runId}-${attempt}`,
      assets: [{ name: ipaObjName }],
    },
  ];

  const fetchImpl = async (url) => {
    assert.ok(url.includes('/releases?per_page=100'));
    return new Response(JSON.stringify(mockStageReleases), { status: 200 });
  };

  const byRun = await resolvePrivateStageRelease({
    stagingRepo: 'example-org/private-repo',
    privateToken: 'dummy-token',
    version,
    runId,
    fetchImpl,
  });
  assert.ok(byRun);
  assert.equal(byRun.runId, runId);
  assert.equal(byRun.stageRelease.id, 102);

  const byBuild = await resolvePrivateStageRelease({
    stagingRepo: 'example-org/private-repo',
    privateToken: 'dummy-token',
    version,
    buildNumber,
    fetchImpl,
  });
  assert.ok(byBuild);
  assert.equal(byBuild.runId, runId);
  assert.equal(byBuild.stageRelease.id, 102);

  const notFound = await resolvePrivateStageRelease({
    stagingRepo: 'example-org/private-repo',
    privateToken: 'dummy-token',
    version,
    buildNumber: '999',
    fetchImpl,
  });
  assert.equal(notFound, null);
});

test('promoteIosToAppStoreConnect sanitizes script shebang from flutter_assets and re-signs candidate before upload', async () => {
  const { privateKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'prime256v1',
  });
  const pem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  const appleSigningConfigJson = JSON.stringify({
    APP_STORE_CONNECT_KEY_ID: 'KEY1234567',
    APP_STORE_CONNECT_ISSUER_ID: '11111111-2222-3333-4444-555555555555',
    APP_STORE_CONNECT_API_KEY_BASE64: Buffer.from(pem, 'utf8').toString('base64'),
    IOS_DISTRIBUTION_CERTIFICATE_BASE64: Buffer.from('mock-p12-data').toString('base64'),
    IOS_DISTRIBUTION_CERTIFICATE_PASSWORD: 'mock-p12-password',
  });

  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'leap-ios-sanitize-'));
  try {
    const ipaPath = path.join(tempDir, 'candidate.ipa');
    const zipBuf = createZipBuffer({
      'Payload/Runner.app/Info.plist': 'plist-data',
    });
    fs.writeFileSync(ipaPath, zipBuf);

    const executedCommands = [];
    let sanitizedContent = null;

    const res = await promoteIosToAppStoreConnect({
      version: '0.1.1',
      buildNumber: '50',
      action: 'testflight',
      ipaPath,
      iosSigningConfigJson: appleSigningConfigJson,
      execFileImpl: (cmd, args) => {
        executedCommands.push({ cmd, args });
        if (cmd === 'ditto' && args[0] === '-x') {
          // Simulate extraction by creating the structure in destination
          const dest = args[3];
          const badDir = path.join(
            dest,
            'Payload/Runner.app/Frameworks/App.framework/flutter_assets/assets',
          );
          fs.mkdirSync(badDir, { recursive: true });
          fs.writeFileSync(
            path.join(badDir, 'ai-task-cache-keep-alive.txt'),
            '#!/bin/sh\necho "running keep alive"\n',
            'utf8',
          );
        }
        if (cmd === 'security' && args[0] === 'find-identity') {
          return '  1) 1234567890ABCDEF1234567890ABCDEF12345678 "Apple Distribution: OmniSolo LLC (TEAM123)"\n     1 valid identities found';
        }
        if (cmd === 'ditto' && args[0] === '-c') {
          const payloadDir = args[3];
          const file = path.join(
            payloadDir,
            'Runner.app/Frameworks/App.framework/flutter_assets/assets/ai-task-cache-keep-alive.txt',
          );
          if (fs.existsSync(file)) {
            sanitizedContent = fs.readFileSync(file, 'utf8');
          }
          fs.writeFileSync(args[4], 'sanitized-ipa-bytes');
        }
      },
    });

    assert.equal(res.status, 'uploaded-to-testflight');
    assert.ok(sanitizedContent, 'Sanitized content must have been captured');
    assert.ok(!sanitizedContent.startsWith('#!'), 'Shebang must be removed');
    assert.ok(sanitizedContent.includes('echo "running keep alive"'), 'Script body preserved');

    const secImports = executedCommands.filter(
      (c) => c.cmd === 'security' && c.args[0] === 'import',
    );
    assert.equal(secImports.length, 1);

    const codesigns = executedCommands.filter((c) => c.cmd === 'codesign');
    assert.ok(codesigns.length >= 2, 'Must sign App.framework and Runner.app');
    assert.ok(codesigns.some((c) => c.args.some((a) => a.includes('App.framework'))));
    assert.ok(codesigns.some((c) => c.args.some((a) => a.includes('Runner.app'))));

    const uploads = executedCommands.filter(
      (c) => c.cmd === 'xcrun' && c.args.includes('--upload-app'),
    );
    assert.equal(uploads.length, 1);
    const uploadedFile = uploads[0].args[uploads[0].args.indexOf('--file') + 1];
    assert.ok(uploadedFile.includes('sanitized.ipa'));
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

test('promoteIosToAppStoreConnect uploads distinct alpha IPA build with production store configuration and assigns to alpha beta group', async () => {
  const { privateKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'prime256v1',
  });
  const pem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  const appleSigningConfigJson = JSON.stringify({
    APP_STORE_CONNECT_KEY_ID: 'KEY1234567',
    APP_STORE_CONNECT_ISSUER_ID: '11111111-2222-3333-4444-555555555555',
    APP_STORE_CONNECT_API_KEY_BASE64: Buffer.from(pem, 'utf8').toString('base64'),
  });

  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'leap-ios-alpha-'));
  try {
    const alphaIpaPath = path.join(tempDir, 'leapterm-0.1.1-ios-alpha.ipa');
    fs.writeFileSync(alphaIpaPath, 'signed-alpha-ipa-fixture');

    const uploadedFiles = [];
    const res = await promoteIosToAppStoreConnect({
      version: '0.1.1',
      buildNumber: '51',
      action: 'alpha',
      ipaPath: alphaIpaPath,
      iosSigningConfigJson: appleSigningConfigJson,
      execFileImpl: (cmd, args) => {
        if (cmd === 'xcrun' && args.includes('--upload-app')) {
          uploadedFiles.push(args[args.indexOf('--file') + 1]);
        }
      },
      fetchImpl: async (url, opts = {}) => {
        if (url.includes('/v1/apps?')) {
          return new Response(
            JSON.stringify({ data: [{ id: 'app-1', type: 'apps' }] }),
            { status: 200 },
          );
        }
        if (url.includes('/v1/builds?')) {
          return new Response(
            JSON.stringify({
              data: [
                {
                  id: 'build-ios-51',
                  type: 'builds',
                  attributes: { processingState: 'VALID', expired: false },
                },
              ],
            }),
            { status: 200 },
          );
        }
        if (url.includes('/betaGroups?')) {
          return new Response(
            JSON.stringify({
              data: [
                {
                  id: 'external-alpha',
                  type: 'betaGroups',
                  attributes: { name: 'alpha', isInternalGroup: false },
                },
              ],
            }),
            { status: 200 },
          );
        }
        if (url.includes('/v1/betaAppReviewSubmissions?')) {
          return new Response(JSON.stringify({ data: [] }), { status: 200 });
        }
        if (url.endsWith('/v1/betaAppReviewSubmissions') && opts.method === 'POST') {
          return new Response(
            JSON.stringify({ data: { id: 'review-51', type: 'betaAppReviewSubmissions' } }),
            { status: 201 },
          );
        }
        if (url.endsWith('/v1/betaGroups/external-alpha/relationships/builds') && opts.method === 'POST') {
          return new Response(null, { status: 204 });
        }
        throw new Error(`Unexpected ASC URL: ${url}`);
      },
    });

    assert.equal(uploadedFiles.length, 1);
    assert.equal(uploadedFiles[0], alphaIpaPath);
    assert.equal(res.action, 'alpha');
    assert.equal(res.track, 'alpha');
    assert.equal(res.revenuecat_store, 'production');
    assert.equal(res.uploaded_candidate, true);
    assert.equal(res.status, 'promoted-to-testflight-alpha');
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

test('STORE_LISTINGS and buildPublicReleaseBody satisfy all store character limits and leak-scanner checks', () => {
  validateStoreListings(STORE_LISTINGS);

  for (const platform of ['ios', 'macos']) {
    const listing = STORE_LISTINGS[platform];
    assert.equal(listing.locale, 'en-US');
    assert.ok(listing.name.length > 0 && listing.name.length <= 30);
    assert.ok(listing.subtitle.length > 0 && listing.subtitle.length <= 30);
    assert.ok(
      listing.promotionalText.length > 0 &&
        listing.promotionalText.length <= 170,
    );
    assert.ok(listing.keywords.length > 0 && listing.keywords.length <= 100);
    assert.ok(
      listing.description.length > 100 && listing.description.length <= 4000,
    );
    assert.ok(listing.whatsNew.length > 20 && listing.whatsNew.length <= 4000);
  }

  const android = STORE_LISTINGS.android;
  assert.equal(android.language, 'en-US');
  assert.ok(android.title.length > 0 && android.title.length <= 30);
  assert.ok(
    android.shortDescription.length > 0 &&
      android.shortDescription.length <= 80,
  );
  assert.ok(
    android.fullDescription.length > 100 &&
      android.fullDescription.length <= 4000,
  );
  assert.ok(
    android.releaseNotes.length > 20 && android.releaseNotes.length <= 500,
  );

  assert.ok(STORE_LISTINGS.windows.title.length > 0);
  assert.ok(STORE_LISTINGS.windows.fullDescription.length > 100);
  assert.ok(STORE_LISTINGS.linux.summary.length > 20);

  const releaseBody = buildPublicReleaseBody({
    version: '0.1.1',
    tag: 'v0.1.1',
  });
  assert.match(releaseBody, /# LeapTerm v0\.1\.1/);
  assert.match(releaseBody, /iOS & iPadOS/);
  assert.match(releaseBody, /macOS/);
  assert.match(releaseBody, /Windows/);
  assert.match(releaseBody, /Android/);
  assert.match(releaseBody, /Linux/);
  assertNoPrivateLeakInPublicMetadata('github-release-body', releaseBody);
  assert.throws(
    () =>
      validateStoreListings({
        ...STORE_LISTINGS,
        android: {
          ...STORE_LISTINGS.android,
          title: 'x'.repeat(31),
        },
      }),
    /exceeds 30 characters/,
  );
  assert.throws(
    () =>
      validateStoreListings({
        ...STORE_LISTINGS,
        ios: {
          ...STORE_LISTINGS.ios,
          description: 'Leaked omnisolo-llc/private-source repository',
        },
      }),
    /leaked private repository reference/,
  );
});

test('promoteIosToAppStoreConnect and promoteAndroidToPlayStore sync platform store listings and release notes', async () => {
  const { privateKey: ecKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'prime256v1',
  });
  const ecPem = ecKey.export({ type: 'pkcs8', format: 'pem' });
  const appleSigningConfigJson = JSON.stringify({
    APP_STORE_CONNECT_KEY_ID: 'KEY1234567',
    APP_STORE_CONNECT_ISSUER_ID: '11111111-2222-3333-4444-555555555555',
    APP_STORE_CONNECT_API_KEY_BASE64: Buffer.from(ecPem, 'utf8').toString(
      'base64',
    ),
  });

  let createdLocPayload = null;
  const iosRes = await promoteIosToAppStoreConnect({
    version: '0.1.1',
    buildNumber: '52',
    action: 'app-store',
    automaticRelease: true,
    iosSigningConfigJson: appleSigningConfigJson,
    fetchImpl: async (url, opts = {}) => {
      if (url.includes('/v1/apps?')) {
        return new Response(
          JSON.stringify({ data: [{ id: 'app-1', type: 'apps' }] }),
          { status: 200 },
        );
      }
      if (url.includes('/v1/builds?')) {
        return new Response(
          JSON.stringify({
            data: [
              {
                id: 'build-ios-52',
                type: 'builds',
                attributes: { processingState: 'VALID', expired: false },
              },
            ],
          }),
          { status: 200 },
        );
      }
      if (url.includes('/appStoreVersions?')) {
        return new Response(
          JSON.stringify({
            data: [{ id: 'ver-ios-011', type: 'appStoreVersions' }],
          }),
          { status: 200 },
        );
      }
      if (
        url.endsWith('/v1/appStoreVersions/ver-ios-011') &&
        opts.method === 'PATCH'
      ) {
        return new Response(
          JSON.stringify({
            data: { id: 'ver-ios-011', type: 'appStoreVersions' },
          }),
          { status: 200 },
        );
      }
      if (
        url.endsWith('/v1/appStoreVersions/ver-ios-011/relationships/build') &&
        opts.method === 'PATCH'
      ) {
        return new Response(null, { status: 204 });
      }
      if (
        url.endsWith(
          '/v1/appStoreVersions/ver-ios-011/appStoreVersionLocalizations',
        ) &&
        (!opts.method || opts.method === 'GET')
      ) {
        return new Response(JSON.stringify({ data: [] }), { status: 200 });
      }
      if (
        url.endsWith('/v1/appStoreVersionLocalizations') &&
        opts.method === 'POST'
      ) {
        createdLocPayload = JSON.parse(opts.body);
        return new Response(
          JSON.stringify({
            data: {
              id: 'loc-ios-en-us',
              type: 'appStoreVersionLocalizations',
            },
          }),
          { status: 201 },
        );
      }
      if (url.endsWith('/v1/appStoreVersionSubmissions')) {
        return new Response(
          JSON.stringify({
            data: { id: 'sub-ios-52', type: 'appStoreVersionSubmissions' },
          }),
          { status: 201 },
        );
      }
      throw new Error(`Unexpected iOS ASC URL: ${url}`);
    },
  });

  assert.equal(iosRes.status, 'submitted-for-review');
  assert.equal(iosRes.asc_localization_id, 'loc-ios-en-us');
  assert.ok(createdLocPayload);
  assert.equal(createdLocPayload.data.attributes.locale, 'en-US');
  assert.equal(
    createdLocPayload.data.attributes.description,
    STORE_LISTINGS.ios.description,
  );
  assert.equal(
    createdLocPayload.data.attributes.keywords,
    STORE_LISTINGS.ios.keywords,
  );
  assert.equal(
    createdLocPayload.data.attributes.promotionalText,
    STORE_LISTINGS.ios.promotionalText,
  );
  assert.equal(
    createdLocPayload.data.attributes.whatsNew,
    STORE_LISTINGS.ios.whatsNew,
  );

  const { privateKey: rsaKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
  });
  const rsaPem = rsaKey.export({ type: 'pkcs8', format: 'pem' });
  const serviceAccountJson = JSON.stringify({
    type: 'service_account',
    client_email: 'play-publisher@leapterm.iam.gserviceaccount.com',
    private_key: rsaPem,
  });

  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'leap-play-listing-'));
  try {
    const aabPath = path.join(tempDir, 'leapterm-0.1.1-android.aab');
    const aabBytes = Buffer.from('signed-aab-fixture');
    fs.writeFileSync(aabPath, aabBytes);

    let playListingPayload = null;
    let playTrackPayload = null;
    const playRes = await promoteAndroidToPlayStore({
      version: '0.1.1',
      buildNumber: '52',
      track: 'production',
      aabPath,
      serviceAccountJson,
      fetchImpl: async (url, opts = {}) => {
        if (url === 'https://oauth2.googleapis.com/token') {
          return new Response(
            JSON.stringify({ access_token: 'ya29.fixture' }),
            { status: 200 },
          );
        }
        if (url.endsWith('/edits') && opts.method === 'POST') {
          return new Response(JSON.stringify({ id: 'edit-52' }), {
            status: 200,
          });
        }
        if (url.endsWith('/edits/edit-52/bundles') && opts.method === 'GET') {
          return new Response(
            JSON.stringify({
              bundles: [{ versionCode: 52, sha256: sha256Hex(aabBytes) }],
            }),
            { status: 200 },
          );
        }
        if (
          url.endsWith('/edits/edit-52/listings/en-US') &&
          opts.method === 'PUT'
        ) {
          playListingPayload = JSON.parse(opts.body);
          return new Response(JSON.stringify({ language: 'en-US' }), {
            status: 200,
          });
        }
        if (
          url.endsWith('/edits/edit-52/tracks/production') &&
          opts.method === 'PUT'
        ) {
          playTrackPayload = JSON.parse(opts.body);
          return new Response(JSON.stringify({ track: 'production' }), {
            status: 200,
          });
        }
        if (
          url.endsWith('/edits/edit-52:validate') ||
          url.endsWith('/edits/edit-52:commit')
        ) {
          return new Response(JSON.stringify({ id: 'edit-52' }), {
            status: 200,
          });
        }
        throw new Error(`Unexpected Play URL: ${url}`);
      },
    });

    assert.equal(playRes.status, 'committed');
    assert.equal(playRes.listing_synced, 'en-US');
    assert.deepEqual(playListingPayload, {
      language: 'en-US',
      title: STORE_LISTINGS.android.title,
      shortDescription: STORE_LISTINGS.android.shortDescription,
      fullDescription: STORE_LISTINGS.android.fullDescription,
    });
    assert.deepEqual(playTrackPayload.releases[0].releaseNotes, [
      {
        language: 'en-US',
        text: STORE_LISTINGS.android.releaseNotes,
      },
    ]);
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

test('stageCompiledWebCdnAssets stages Wasm-only bundle into Cloudflare Pages dist/_cdn/web/<buildId>, expires old versions, and rejects dart2js, custom sections, comments, and private files', async () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'leap-web-cdn-test-'));
  try {
    const bundleDir = path.join(tempDir, 'web-bundle');
    const distDir = path.join(tempDir, 'website-dist');
    fs.mkdirSync(path.join(bundleDir, 'canvaskit'), { recursive: true });
    fs.mkdirSync(path.join(bundleDir, 'assets', 'fonts'), { recursive: true });
    fs.mkdirSync(path.join(bundleDir, 'browser-ssh-signer'), { recursive: true });
    // Pre-seed an older CDN buildId directory to verify it is purged when publishing a new version
    const staleBuildDir = path.join(distDir, '_cdn', 'web', '0000111122223333');
    fs.mkdirSync(staleBuildDir, { recursive: true });
    fs.writeFileSync(path.join(staleBuildDir, 'main.dart.wasm'), Buffer.from('stale'));

    const wasmBytes = Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x04, 0x01, 0x60, 0x00, 0x00]);
    const mjsBytes = Buffer.from('export const compileStreaming = () => {};\n');
    const skwasmJsBytes = Buffer.from('export default async function(){}\n');
    fs.writeFileSync(path.join(bundleDir, 'main.dart.wasm'), wasmBytes);
    fs.writeFileSync(path.join(bundleDir, 'main.dart.wasm.gz'), Buffer.from('gzip-sidecar'));
    fs.writeFileSync(path.join(bundleDir, 'main.dart.mjs'), mjsBytes);
    fs.writeFileSync(path.join(bundleDir, 'flutter_bootstrap.js'), 'console.log("wasm");\n');
    fs.writeFileSync(path.join(bundleDir, 'flutter.js'), 'console.log("flutter");\n');
    fs.writeFileSync(path.join(bundleDir, 'version.json'), '{"version":"0.1.1"}');
    fs.writeFileSync(path.join(bundleDir, 'manifest.json'), '{"name":"LeapTerm"}');
    fs.writeFileSync(path.join(bundleDir, 'canvaskit', 'skwasm.js'), skwasmJsBytes);
    fs.writeFileSync(path.join(bundleDir, 'canvaskit', 'skwasm.wasm'), wasmBytes);
    fs.writeFileSync(path.join(bundleDir, 'assets', 'fonts', 'MaterialIcons.otf'), Buffer.from('font'));
    fs.writeFileSync(path.join(bundleDir, 'assets', 'fonts', 'provenance.json'), '{"source":"internal"}');
    fs.writeFileSync(path.join(bundleDir, 'assets', 'fonts', 'bundled-font-inventory.json'), '{"design":"design/themes/themes.json"}');
    fs.writeFileSync(path.join(bundleDir, 'browser-ssh-signer', 'manifest.json'), '{"sources":{"tools/release-artifacts/src/runner.rs":"abc"}}');
    fs.writeFileSync(path.join(bundleDir, 'config.json'), '{"edge_url":"https://cloud.leapterm.com"}');
    fs.writeFileSync(path.join(bundleDir, 'index.html'), '<!doctype html>');

    const result = stageCompiledWebCdnAssets({
      bundleDir,
      distDir,
      version: '0.1.1',
      buildNumber: '52',
    });

    const expectedSha = sha256Hex(wasmBytes);
    assert.equal(result.wasmSha256, expectedSha);
    assert.equal(result.buildId, expectedSha.slice(0, 16));
    assert.equal(result.manifest.skwasm_js_sha256, sha256Hex(skwasmJsBytes));
    assert.equal(result.manifest.files['main.dart.wasm'].sha256, expectedSha);
    assert.ok(!fs.existsSync(staleBuildDir), 'Expected older _cdn/web/<oldBuildId> directory to be removed');
    assert.ok(fs.existsSync(path.join(result.targetDir, 'main.dart.wasm')));
    assert.ok(fs.existsSync(path.join(result.targetDir, 'main.dart.mjs')));
    assert.ok(fs.existsSync(path.join(result.targetDir, 'canvaskit', 'skwasm.wasm')));
    assert.ok(fs.existsSync(path.join(result.targetDir, 'assets', 'fonts', 'MaterialIcons.otf')));
    assert.ok(fs.existsSync(path.join(result.targetDir, 'cdn-manifest.json')));
    assert.ok(!fs.existsSync(path.join(result.targetDir, 'main.dart.wasm.gz')));
    assert.ok(!fs.existsSync(path.join(result.targetDir, 'config.json')));
    assert.ok(!fs.existsSync(path.join(result.targetDir, 'index.html')));
    assert.ok(!fs.existsSync(path.join(result.targetDir, 'flutter_bootstrap.js')));
    assert.ok(!fs.existsSync(path.join(result.targetDir, 'flutter.js')));
    assert.ok(!fs.existsSync(path.join(result.targetDir, 'version.json')));
    assert.ok(!fs.existsSync(path.join(result.targetDir, 'manifest.json')));
    assert.ok(!fs.existsSync(path.join(result.targetDir, 'browser-ssh-signer')));
    assert.ok(!fs.existsSync(path.join(result.targetDir, 'assets', 'fonts', 'provenance.json')));
    assert.ok(!fs.existsSync(path.join(result.targetDir, 'assets', 'fonts', 'bundled-font-inventory.json')));

    const headers = fs.readFileSync(path.join(distDir, '_headers'), 'utf8');
    assert.match(headers, /\/_cdn\/web\/\*/);
    assert.match(headers, /Access-Control-Allow-Origin: \*/);
    assert.match(headers, /Cache-Control: no-store, no-cache, must-revalidate, max-age=0/);
    assert.match(headers, /Cache-Control: public, max-age=3600, s-maxage=3600, must-revalidate/);
    assert.match(headers, /X-Robots-Tag: noindex, noarchive, nosnippet/);
    assert.match(headers, /Content-Security-Policy: default-src 'none'; sandbox/);

    const redirects = fs.readFileSync(path.join(distDir, '_redirects'), 'utf8');
    assert.match(redirects, new RegExp(`/_cdn/web/latest/\\* /_cdn/web/${result.buildId}/:splat 200`));

    // Verify _routes.json and _worker.js expire older CDN versions with HTTP 410 Gone
    assert.ok(fs.existsSync(path.join(distDir, '_routes.json')));
    assert.ok(fs.existsSync(path.join(distDir, '_worker.js')));
    const workerModule = await import(`file://${path.join(distDir, '_worker.js')}`);
    const mockEnv = {
      ASSETS: {
        fetch: async (req) => new Response('active-asset', { status: 200, headers: { 'Content-Type': 'application/wasm' } }),
      },
    };
    const expiredRes = await workerModule.default.fetch(
      new Request('https://cdn.leapterm.com/web/0000111122223333/main.dart.wasm'),
      mockEnv,
    );
    assert.equal(expiredRes.status, 410);
    assert.match(expiredRes.headers.get('cache-control') || '', /no-store/);
    const expiredBody = await expiredRes.json();
    assert.equal(expiredBody.error, 'cdn_version_expired');
    assert.equal(expiredBody.active_build_id, result.buildId);
    assert.equal(expiredBody.active_cdn_url, `https://cdn.leapterm.com/web/${result.buildId}/`);

    const healthRes = await workerModule.default.fetch(
      new Request('https://cdn.leapterm.com/healthz'),
      mockEnv,
    );
    assert.equal(healthRes.status, 200);
    const healthBody = await healthRes.json();
    assert.equal(healthBody.status, 'ok');
    assert.equal(healthBody.service, 'leapterm-cdn');
    assert.equal(healthBody.domain, 'cdn.leapterm.com');
    assert.equal(healthBody.active_build_id, result.buildId);

    const activeRes = await workerModule.default.fetch(
      new Request(`https://cdn.leapterm.com/web/${result.buildId}/main.dart.wasm`),
      mockEnv,
    );
    assert.equal(activeRes.status, 200);
    assert.match(activeRes.headers.get('cache-control') || '', /max-age=3600/);

    // Verify that unstripped Wasm custom section (id=0) is rejected
    const wasmWithCustomSection = Buffer.from([
      0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
      0x00, 0x05, 0x04, 0x6e, 0x61, 0x6d, 0x65,
    ]);
    fs.writeFileSync(path.join(bundleDir, 'main.dart.wasm'), wasmWithCustomSection);
    assert.throws(
      () => stageCompiledWebCdnAssets({ bundleDir, distDir }),
      /Unstripped Wasm custom section/,
    );
    fs.writeFileSync(path.join(bundleDir, 'main.dart.wasm'), wasmBytes);

    // Verify that unobfuscated main.dart.mjs symbols/comments are rejected
    fs.writeFileSync(path.join(bundleDir, 'main.dart.mjs'), 'class CompiledApp {}\n');
    assert.throws(
      () => stageCompiledWebCdnAssets({ bundleDir, distDir }),
      /Unobfuscated internal symbols in CDN main\.dart\.mjs/,
    );
    fs.writeFileSync(path.join(bundleDir, 'main.dart.mjs'), mjsBytes);

    // Verify that presence of legacy main.dart.js is rejected
    fs.writeFileSync(path.join(bundleDir, 'main.dart.js'), 'legacy dart2js');
    assert.throws(
      () => stageCompiledWebCdnAssets({ bundleDir, distDir }),
      /Legacy dart2js artifact main\.dart\.js is forbidden/,
    );
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

test('pruneSupersededPagesDeployments and deployCompiledWebCdnAssets deploy to leapterm-cdn, prune older deployments, and clean local dist', async () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'leap-cdn-deploy-test-'));
  const bundleDir = path.join(tempDir, 'web');
  const distDir = path.join(tempDir, 'cdn-dist');
  try {
    fs.mkdirSync(path.join(bundleDir, 'canvaskit'), { recursive: true });
    fs.mkdirSync(path.join(bundleDir, 'assets'), { recursive: true });
    fs.writeFileSync(
      path.join(bundleDir, 'main.dart.wasm'),
      Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x04, 0x01, 0x60, 0x00, 0x00]),
    );
    fs.writeFileSync(path.join(bundleDir, 'main.dart.mjs'), 'export async function compileStreaming(b){return b;}\n');
    fs.writeFileSync(path.join(bundleDir, 'flutter_bootstrap.js'), 'console.log("bootstrap");');
    fs.writeFileSync(path.join(bundleDir, 'canvaskit', 'skwasm.js'), 'console.log("skwasm");');
    fs.writeFileSync(path.join(bundleDir, 'canvaskit', 'skwasm.wasm'), Buffer.from('\0asm\x01\x00\x00\x00skwasm'));

    const deletedDeployments = [];
    const execCalls = [];
    const mockFetch = async (url, init = {}) => {
      const urlStr = String(url);
      if (!init.method || init.method === 'GET') {
        assert.match(urlStr, /\/pages\/projects\/leapterm-cdn\/deployments$/);
        return new Response(
          JSON.stringify({
            success: true,
            result: [
              { id: 'dep-active-newest' },
              { id: 'dep-old-1' },
              { id: 'dep-old-2' },
            ],
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        );
      }
      if (init.method === 'DELETE') {
        deletedDeployments.push(urlStr);
        return new Response(JSON.stringify({ success: true }), { status: 200 });
      }
      throw new Error(`Unexpected fetch: ${urlStr}`);
    };

    const deployRes = await deployCompiledWebCdnAssets({
      bundleDir,
      distDir,
      projectName: 'leapterm-cdn',
      version: '0.1.0',
      buildNumber: '12',
      cleanLocal: true,
      accountId: 'acc-123',
      apiToken: 'tok-123',
      execFileImpl: (cmd, args) => {
        execCalls.push({ cmd, args });
        return '';
      },
      fetchImpl: mockFetch,
    });

    assert.equal(deployRes.projectName, 'leapterm-cdn');
    assert.equal(deployRes.cdnUrl, `https://cdn.leapterm.com/web/${deployRes.buildId}/`);
    assert.equal(deployRes.prunedDeploymentsCount, 2);
    assert.equal(deletedDeployments.length, 2);
    assert.match(deletedDeployments[0], /dep-old-1\?force=true$/);
    assert.match(deletedDeployments[1], /dep-old-2\?force=true$/);
    assert.equal(execCalls.length, 1);
    assert.ok(execCalls[0].args.includes('--project-name=leapterm-cdn'));
    assert.ok(!fs.existsSync(distDir), 'cleanLocal should remove distDir after deploy');
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

test('pruneGithubReleases retains newest stable releases and currentTag while pruning old releases, wave tags, and stage runs', async () => {
  const deletedUrls = [];
  const publicReleases = [
    { id: 10, tag_name: 'v0.1.4', draft: false, prerelease: false, published_at: '2026-10-26T10:00:00Z' },
    { id: 9, tag_name: 'v0.1.4-fast', draft: false, prerelease: true, published_at: '2026-10-26T09:30:00Z' },
    { id: 8, tag_name: 'v0.1.3', draft: false, prerelease: false, published_at: '2026-10-25T10:00:00Z' },
    { id: 7, tag_name: 'v0.1.2', draft: false, prerelease: false, published_at: '2026-10-24T10:00:00Z' },
    { id: 6, tag_name: 'v0.1.1', draft: false, prerelease: false, published_at: '2026-10-20T10:00:00Z' },
    { id: 5, tag_name: 'v0.1.0-draft', draft: true, prerelease: false, created_at: '2026-10-19T10:00:00Z' },
  ];
  const publicRes = await pruneGithubReleases({
    repo: 'omnisolo-llc/leapterm-release',
    token: 'mock-pub-token',
    keepReleases: 3,
    currentTag: 'v0.1.4',
    isStagingRepo: false,
    fetchImpl: async (url, init = {}) => {
      const u = String(url);
      if (!init.method || init.method === 'GET') {
        return new Response(JSON.stringify(publicReleases), { status: 200 });
      }
      deletedUrls.push(u);
      return new Response(null, { status: 204 });
    },
  });
  assert.deepEqual(publicRes.kept, ['v0.1.4', 'v0.1.3', 'v0.1.2']);
  assert.deepEqual(publicRes.deleted, ['v0.1.4-fast', 'v0.1.1', 'v0.1.0-draft']);

  const stagingReleases = [
    { id: 20, tag_name: 'v0.1.4-fast', draft: false, prerelease: true, published_at: '2026-10-26T10:00:00Z' },
    { id: 19, tag_name: 'v0.1.4-slow', draft: false, prerelease: true, published_at: '2026-10-26T09:50:00Z' },
    { id: 18, tag_name: 'ci-stage/application-102-1', draft: false, prerelease: true, published_at: '2026-10-26T09:40:00Z' },
    { id: 17, tag_name: 'v0.1.3', draft: false, prerelease: false, published_at: '2026-10-25T10:00:00Z' },
    { id: 16, tag_name: 'ci-stage/application-101-1', draft: false, prerelease: true, published_at: '2026-10-25T09:40:00Z' },
    { id: 15, tag_name: 'v0.1.2-fast', draft: false, prerelease: true, published_at: '2026-10-20T10:00:00Z' },
    { id: 14, tag_name: 'ci-stage/application-99-1', draft: false, prerelease: true, published_at: '2026-10-19T09:40:00Z' },
  ];
  const stagingRes = await pruneGithubReleases({
    repo: 'omnisolo-llc/private-source',
    token: 'mock-priv-token',
    keepReleases: 1,
    currentTag: 'v0.1.4',
    isStagingRepo: true,
    fetchImpl: async (url, init = {}) => {
      if (!init.method || init.method === 'GET') {
        return new Response(JSON.stringify(stagingReleases), { status: 200 });
      }
      return new Response(null, { status: 204 });
    },
  });
  assert.deepEqual(stagingRes.kept, [
    'v0.1.4-fast',
    'v0.1.4-slow',
    'ci-stage/application-102-1',
    'ci-stage/application-101-1',
  ]);
  assert.deepEqual(stagingRes.deleted, [
    'v0.1.3',
    'v0.1.2-fast',
    'ci-stage/application-99-1',
  ]);

  const promoteYml = fs.readFileSync(
    path.resolve(import.meta.dirname, '..', '.github/workflows/promote-release.yml'),
    'utf8',
  );
  assert.match(promoteYml, /--project-name leapterm-cdn/);
  assert.match(promoteYml, /for PAGES_PROJ in leapterm-cdn leapterm-website leapterm-docs/);
  assert.match(promoteYml, /--prune-github-releases/);
});

test('sanitizePublicLogText, syncAppleInternalTesters masking, and install.sh leak scanning prevent public log/asset leaks', async () => {
  const rawLog =
    'Deploying docker.io/leapterm/private:cloud-latest from omnisolo-llc/private-repo via cloud/deploy/packaging/install.sh to preview-123.pages.dev and api.staging.leapterm.com (tag ci-stage/application-12345-1)';
  const sanitized = sanitizePublicLogText(rawLog);
  assert.ok(!sanitized.includes('docker.io/leapterm/private'));
  assert.ok(!sanitized.includes('omnisolo-llc/private-repo'));
  assert.ok(!sanitized.includes('cloud/deploy/packaging/install.sh'));
  assert.ok(!sanitized.includes('preview-123.pages.dev'));
  assert.ok(!sanitized.includes('api.staging.leapterm.com'));
  assert.ok(!sanitized.includes('ci-stage/application-12345-1'));

  const prevActions = process.env.GITHUB_ACTIONS;
  const prevLog = console.log;
  const prevWarn = console.warn;
  const logs = [];
  const warns = [];
  process.env.GITHUB_ACTIONS = 'true';
  console.log = (...args) => logs.push(args.join(' '));
  console.warn = (...args) => warns.push(args.join(' '));
  try {
    await syncAppleInternalTesters({
      internalTesterEmails: 'secret.tester@example.com',
      ascRequest: async (endpoint, method = 'GET') => {
        if (endpoint.startsWith('/v1/apps?')) {
          return { data: [{ id: 'app-1' }] };
        }
        if (endpoint.endsWith('/betaGroups?limit=200')) {
          return {
            data: [
              { id: 'grp-int', attributes: { isInternalGroup: true } },
              { id: 'grp-ext', attributes: { isInternalGroup: false, name: 'External' } },
            ],
          };
        }
        if (endpoint.endsWith('/betaTesters?limit=200')) {
          return { data: [] };
        }
        if (endpoint.startsWith('/v1/betaTesters?filter[email]=')) {
          return { data: [] };
        }
        if (endpoint === '/v1/betaTesters' && method === 'POST') {
          throw new Error('Cannot add secret.tester@example.com');
        }
        return {};
      },
    });
  } finally {
    if (prevActions === undefined) delete process.env.GITHUB_ACTIONS;
    else process.env.GITHUB_ACTIONS = prevActions;
    console.log = prevLog;
    console.warn = prevWarn;
  }
  assert.ok(logs.includes('::add-mask::secret.tester@example.com'));
  for (const w of warns) {
    assert.ok(!w.includes('secret.tester@example.com'), `Warn leaked email: ${w}`);
    assert.match(w, /tester#1/);
  }

  const leakyInstall = Buffer.from('#!/bin/sh\nREPO="omnisolo-llc/private-source"\n');
  assert.ok(scanBufferForLeaks(leakyInstall, 'install.sh').length > 0);
});



