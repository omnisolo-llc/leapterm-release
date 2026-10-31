#!/usr/bin/env node
import { createPrivateKey, sign } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '..');

function getEnv(key) {
  return (process.env[key] || '').trim();
}

async function queryHighestAscBuild(appId = '6812974189') {
  const keyId = getEnv('APP_STORE_CONNECT_KEY_ID');
  const issuerId = getEnv('APP_STORE_CONNECT_ISSUER_ID');
  const apiKeyBase64 = getEnv('APP_STORE_CONNECT_API_KEY_BASE64');

  if (!keyId || !issuerId || !apiKeyBase64) {
    console.warn('[nightly-dispatch] App Store Connect credentials not set, using default baseline.');
    return 70;
  }

  try {
    const privateKey = createPrivateKey(Buffer.from(apiKeyBase64, 'base64'));
    const now = Math.floor(Date.now() / 1000);
    const header = Buffer.from(JSON.stringify({ alg: 'ES256', kid: keyId, typ: 'JWT' })).toString('base64url');
    const claims = Buffer.from(JSON.stringify({
      iss: issuerId,
      iat: now,
      exp: now + 300,
      aud: 'appstoreconnect-v1',
    })).toString('base64url');
    const token = `${header}.${claims}.${sign('sha256', Buffer.from(`${header}.${claims}`), {
      key: privateKey,
      dsaEncoding: 'ieee-p1363',
    }).toString('base64url')}`;

    const url = `https://api.appstoreconnect.apple.com/v1/builds?filter[app]=${encodeURIComponent(appId)}&sort=-uploadedDate&limit=30`;
    const res = await fetch(url, {
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: 'application/json',
      },
    });

    if (!res.ok) {
      console.warn(`[nightly-dispatch] ASC API returned HTTP ${res.status}: ${await res.text()}`);
      return 70;
    }

    const data = await res.json();
    const builds = data?.data || [];
    let maxBuild = 0;
    for (const b of builds) {
      const v = parseInt(b.attributes?.version, 10);
      if (!isNaN(v) && v > maxBuild) {
        maxBuild = v;
      }
    }
    return maxBuild > 0 ? maxBuild : 70;
  } catch (err) {
    console.warn(`[nightly-dispatch] ASC query error: ${err.message}`);
    return 70;
  }
}

async function main() {
  const sourceSha = getEnv('APPROVED_SOURCE_SHA') || getEnv('APPROVED_RELEASE_SOURCE_SHA');
  const builderSha = getEnv('APPROVED_BUILDER_SHA') || getEnv('APPROVED_RELEASE_BUILDER_SHA') || getEnv('GITHUB_SHA');
  const target = getEnv('TARGET') || 'ios';
  const version = getEnv('VERSION') || '0.1.4';

  if (!sourceSha || !builderSha) {
    throw new Error(`APPROVED_SOURCE_SHA and APPROVED_BUILDER_SHA must be provided (sourceSha=${sourceSha}, builderSha=${builderSha})`);
  }

  const highestBuild = await queryHighestAscBuild();
  const nextBuild = highestBuild + 1;

  console.log(`[nightly-dispatch] Source SHA:  ${sourceSha}`);
  console.log(`[nightly-dispatch] Builder SHA: ${builderSha}`);
  console.log(`[nightly-dispatch] Version:     ${version}`);
  console.log(`[nightly-dispatch] Build Num:   ${nextBuild}`);
  console.log(`[nightly-dispatch] Target:      ${target}`);

  const args = [
    'workflow',
    'run',
    'release.yml',
    '-R',
    'omnisolo-llc/leapterm-release',
    '-f',
    'release_route=option1',
    '-f',
    'build_only=false',
    '-f',
    `verify_target=${target}`,
    '-f',
    `source_sha=${sourceSha}`,
    '-f',
    `builder_sha=${builderSha}`,
    '-f',
    `version=${version}`,
    '-f',
    `build_number=${nextBuild}`,
    '-f',
    'ios_action=upload',
    '-f',
    'auto_promote=true',
  ];

  console.log(`[nightly-dispatch] Running: gh ${args.join(' ')}`);
  if (process.env.DRY_RUN === 'true' || process.argv.includes('--dry-run')) {
    console.log('[nightly-dispatch] Dry run complete; skipping actual dispatch.');
    return;
  }
  execFileSync('gh', args, {
    stdio: 'inherit',
    env: process.env,
  });
  console.log('[nightly-dispatch] Successfully dispatched release workflow for nightly TestFlight!');
}

main().catch((err) => {
  console.error('[nightly-dispatch] Fatal:', err);
  process.exit(1);
});
