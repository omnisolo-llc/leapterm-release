#!/usr/bin/env node
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import zlib from 'node:zlib';

export const STAGING_REPOSITORY = 'omnisolo-llc/leapterm';
export const PUBLIC_REPOSITORY = 'omnisolo-llc/leapterm-release';
export const PRIMARY_CONTAINER_REGISTRY = 'omniterm/omni';
export const GHCR_CONTAINER_REGISTRY = 'ghcr.io/omnisolo-llc/leapterm/cloud';

export const PUBLIC_TARGETS = Object.freeze([
  'windows',
  'linux',
  'macos',
  'android',
  'android-arm',
  'android-arm64',
  'android-x64',
  'agent-deb',
  'agent-rpm',
]);

export const FORBIDDEN_PRIVATE_TARGETS = Object.freeze([
  'flutter-web',
  'workstation-web',
  'services-linux',
  'services-windows',
  'services-macos',
  'android-aab',
  'ios',
  'updates-linux',
  'updates-windows',
  'updates-macos',
]);

export const FORBIDDEN_ASSET_PATTERNS = Object.freeze([
  /-flutter-web\.tar\.gz$/,
  /-workstation-web\.tar\.gz$/,
  /-services-linux-x64\.tar\.gz$/,
  /-services-windows-x64\.zip$/,
  /-services-macos-arm64\.tar\.gz$/,
  /-updates-linux-x64\.zip$/,
  /-updates-windows-x64\.zip$/,
  /-updates-macos-arm64\.zip$/,
  /-android(-release)?\.aab$/,
  /-ios(-private)?\.ipa$/,
  /^omni-terminal-sbom\./,
]);

export const SELF_HOSTED_LEAK_PATTERNS = Object.freeze([
  { label: 'production API domain', regex: /api\.leapterm\.com/i },
  { label: 'production app domain', regex: /app\.leapterm\.com/i },
  { label: 'production RTC domain', regex: /rtc\.leapterm\.com/i },
  { label: 'production download domain', regex: /download\.leapterm\.com/i },
  { label: 'production leapterm.com domain', regex: /\bleapterm\.com\b/i },
  { label: 'corporate omnisolo.com domain', regex: /\bomnisolo\.com\b/i },
  {
    label: 'private source repository reference',
    regex: /omnisolo-llc\/leapterm(?!-release)/i,
  },
  {
    label: 'Cloudflare account or zone identifier',
    regex: /\b(?:account_id|zone_id)\s*[:=]\s*["']?[0-9a-f]{32}\b/i,
  },
  { label: 'Cloudflare R2 endpoint', regex: /r2\.cloudflarestorage\.com/i },
  {
    label: 'PEM private key block',
    regex: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/,
  },
  {
    label: 'diagnostics private key variable',
    regex: /DIAGNOSTICS_PRIVATE_KEY/,
  },
  { label: 'Cloudflare API token variable', regex: /CLOUDFLARE_API_TOKEN/ },
]);

export function sha256Hex(buffer) {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

export function canonicalJson(value) {
  const sortValue = (input) => {
    if (Array.isArray(input)) {
      return input.map(sortValue);
    }
    if (input !== null && typeof input === 'object') {
      const sorted = {};
      for (const key of Object.keys(input).sort()) {
        sorted[key] = sortValue(input[key]);
      }
      return sorted;
    }
    return input;
  };
  return `${JSON.stringify(sortValue(value))}\n`;
}

export function scanBufferForLeaks(buffer, relativePath) {
  const text = buffer.toString('utf8');
  const findings = [];
  for (const rule of SELF_HOSTED_LEAK_PATTERNS) {
    if (rule.regex.test(text)) {
      findings.push(`${relativePath}: leaked ${rule.label}`);
    }
  }
  return findings;
}

export function scanDirectoryForLeaks(rootDir) {
  const findings = [];
  const walk = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const fullPath = path.join(dir, entry.name);
      const rel = path.relative(rootDir, fullPath);
      if (
        entry.name === 'node_modules' ||
        entry.name === '.git' ||
        entry.name.startsWith('.env')
      ) {
        if (entry.name !== '.env.example') {
          findings.push(
            `${rel}: forbidden directory or env file in self-hosted archive`,
          );
          continue;
        }
      }
      if (entry.isDirectory()) {
        walk(fullPath);
      } else if (entry.isFile()) {
        const buf = fs.readFileSync(fullPath);
        findings.push(...scanBufferForLeaks(buf, rel));
      }
    }
  };
  walk(rootDir);
  return findings;
}

export function readZipEntries(zipBuffer) {
  let eocdOffset = -1;
  for (
    let i = zipBuffer.length - 22;
    i >= Math.max(0, zipBuffer.length - 65557);
    i--
  ) {
    if (zipBuffer.readUInt32LE(i) === 0x06054b50) {
      eocdOffset = i;
      break;
    }
  }
  if (eocdOffset < 0) {
    throw new Error('Invalid ZIP archive: End of Central Directory not found');
  }
  const totalEntries = zipBuffer.readUInt16LE(eocdOffset + 10);
  let cdOffset = zipBuffer.readUInt32LE(eocdOffset + 16);
  const entries = new Map();
  for (let i = 0; i < totalEntries; i++) {
    if (zipBuffer.readUInt32LE(cdOffset) !== 0x02014b50) {
      throw new Error('Invalid ZIP Central Directory header');
    }
    const method = zipBuffer.readUInt16LE(cdOffset + 10);
    const compressedSize = zipBuffer.readUInt32LE(cdOffset + 20);
    const nameLen = zipBuffer.readUInt16LE(cdOffset + 28);
    const extraLen = zipBuffer.readUInt16LE(cdOffset + 30);
    const commentLen = zipBuffer.readUInt16LE(cdOffset + 32);
    const localHeaderOffset = zipBuffer.readUInt32LE(cdOffset + 42);
    const name = zipBuffer
      .subarray(cdOffset + 46, cdOffset + 46 + nameLen)
      .toString('utf8');
    cdOffset += 46 + nameLen + extraLen + commentLen;
    if (name.endsWith('/')) continue;
    if (zipBuffer.readUInt32LE(localHeaderOffset) !== 0x04034b50) {
      throw new Error(`Invalid ZIP Local File header for ${name}`);
    }
    const localNameLen = zipBuffer.readUInt16LE(localHeaderOffset + 26);
    const localExtraLen = zipBuffer.readUInt16LE(localHeaderOffset + 28);
    const dataStart = localHeaderOffset + 30 + localNameLen + localExtraLen;
    const rawData = zipBuffer.subarray(dataStart, dataStart + compressedSize);
    let content;
    if (method === 0) {
      content = Buffer.from(rawData);
    } else if (method === 8) {
      content = zlib.inflateRawSync(rawData);
    } else {
      throw new Error(`Unsupported ZIP compression method ${method} in ${name}`);
    }
    entries.set(name, content);
  }
  return entries;
}

export function createZipBuffer(fileMap) {
  const localParts = [];
  const centralParts = [];
  let offset = 0;
  const names = Object.keys(fileMap).sort();
  for (const name of names) {
    const nameBuf = Buffer.from(name, 'utf8');
    const dataBuf = Buffer.isBuffer(fileMap[name])
      ? fileMap[name]
      : Buffer.from(String(fileMap[name]), 'utf8');
    const crc = zlib.crc32(dataBuf);
    const compressed = zlib.deflateRawSync(dataBuf);

    const localHeader = Buffer.alloc(30);
    localHeader.writeUInt32LE(0x04034b50, 0);
    localHeader.writeUInt16LE(20, 4);
    localHeader.writeUInt16LE(0, 6);
    localHeader.writeUInt16LE(8, 8);
    localHeader.writeUInt16LE(0, 10);
    localHeader.writeUInt16LE(0, 12);
    localHeader.writeUInt32LE(crc >>> 0, 14);
    localHeader.writeUInt32LE(compressed.length, 18);
    localHeader.writeUInt32LE(dataBuf.length, 22);
    localHeader.writeUInt16LE(nameBuf.length, 26);
    localHeader.writeUInt16LE(0, 28);

    const centralHeader = Buffer.alloc(46);
    centralHeader.writeUInt32LE(0x02014b50, 0);
    centralHeader.writeUInt16LE(20, 4);
    centralHeader.writeUInt16LE(20, 6);
    centralHeader.writeUInt16LE(0, 8);
    centralHeader.writeUInt16LE(8, 10);
    centralHeader.writeUInt16LE(0, 12);
    centralHeader.writeUInt16LE(0, 14);
    centralHeader.writeUInt32LE(crc >>> 0, 16);
    centralHeader.writeUInt32LE(compressed.length, 20);
    centralHeader.writeUInt32LE(dataBuf.length, 24);
    centralHeader.writeUInt16LE(nameBuf.length, 28);
    centralHeader.writeUInt16LE(0, 30);
    centralHeader.writeUInt16LE(0, 32);
    centralHeader.writeUInt16LE(0, 34);
    centralHeader.writeUInt16LE(0, 36);
    centralHeader.writeUInt32LE(0, 38);
    centralHeader.writeUInt32LE(offset, 42);

    localParts.push(localHeader, nameBuf, compressed);
    centralParts.push(centralHeader, nameBuf);
    offset += localHeader.length + nameBuf.length + compressed.length;
  }
  const cdBuffer = Buffer.concat(centralParts);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0, 4);
  eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(names.length, 8);
  eocd.writeUInt16LE(names.length, 10);
  eocd.writeUInt32LE(cdBuffer.length, 12);
  eocd.writeUInt32LE(offset, 16);
  eocd.writeUInt16LE(0, 20);
  return Buffer.concat([...localParts, cdBuffer, eocd]);
}

export function scanSelfHostedZipForLeaks(zipPath) {
  const zipBuffer = fs.readFileSync(zipPath);
  const entries = readZipEntries(zipBuffer);
  const files = [...entries.keys()];
  if (!files.includes('START-HERE.md') || !files.includes('relay/README.md')) {
    throw new Error(
      `Self-hosted archive missing required files (found: ${files.join(', ')})`,
    );
  }
  const findings = [];
  for (const [rel, buf] of entries.entries()) {
    const parts = rel.split('/');
    if (
      parts.includes('node_modules') ||
      parts.includes('.git') ||
      parts.some((p) => p.startsWith('.env') && p !== '.env.example')
    ) {
      findings.push(
        `${rel}: forbidden directory or env file in self-hosted archive`,
      );
      continue;
    }
    findings.push(...scanBufferForLeaks(buf, rel));
  }
  if (findings.length > 0) {
    throw new Error(
      `Self-hosted archive failed leak scan:\n${findings.join('\n')}`,
    );
  }
}

export function filterPublicDownloadLinks(
  stagingLinks,
  publicRepo = PUBLIC_REPOSITORY,
  selfHostedOverride = null,
) {
  if (!stagingLinks || typeof stagingLinks !== 'object') {
    throw new Error('Invalid download-links.json payload');
  }
  const version = String(stagingLinks.version || '').replace(/^v/, '');
  if (!version) {
    throw new Error('download-links.json missing version');
  }
  const tag = `v${version}`;
  const publicBaseUrl = `https://github.com/${publicRepo}/releases/download/${tag}`;
  const allowedTargets = new Set(PUBLIC_TARGETS);
  const rawList = Array.isArray(stagingLinks.downloads)
    ? stagingLinks.downloads
    : Array.isArray(stagingLinks.artifacts)
      ? stagingLinks.artifacts
      : [];
  const publicArtifacts = [];
  for (const item of rawList) {
    if (!item || typeof item !== 'object') continue;
    if (FORBIDDEN_PRIVATE_TARGETS.includes(item.target)) {
      continue;
    }
    if (!allowedTargets.has(item.target)) {
      continue;
    }
    const name = String(item.name || '');
    if (FORBIDDEN_ASSET_PATTERNS.some((rx) => rx.test(name))) {
      throw new Error(`Forbidden private asset matched public target: ${name}`);
    }
    publicArtifacts.push({
      ...item,
      url: `${publicBaseUrl}/${name}`,
      checksum_url: `${publicBaseUrl}/${name}.sha256`,
      sha256_url: `${publicBaseUrl}/${name}.sha256`,
      signature_url: `${publicBaseUrl}/${name}.sha256.sig`,
    });
  }
  if (publicArtifacts.length !== PUBLIC_TARGETS.length) {
    const found = publicArtifacts.map((a) => a.target);
    throw new Error(
      `Expected ${PUBLIC_TARGETS.length} public artifacts, found ${publicArtifacts.length} (${found.join(', ')})`,
    );
  }
  const result = {
    version,
    build_number: stagingLinks.build_number,
    tag,
    artifacts: publicArtifacts,
    downloads: publicArtifacts,
    ios_delivery: {
      action: 'public',
      channel: 'app-store',
      status: 'not-included-in-public-archive',
    },
  };
  const shSource =
    selfHostedOverride ||
    (stagingLinks.self_hosted && typeof stagingLinks.self_hosted === 'object'
      ? stagingLinks.self_hosted
      : null);
  if (shSource) {
    const shName = String(shSource.name || `omniterm-${version}-self-hosted.zip`);
    result.self_hosted = {
      ...shSource,
      name: shName,
      url: `${publicBaseUrl}/${shName}`,
      checksum_url: `${publicBaseUrl}/${shName}.sha256`,
      sha256_url: `${publicBaseUrl}/${shName}.sha256`,
      signature_url: `${publicBaseUrl}/${shName}.sha256.sig`,
    };
  } else {
    throw new Error('Staging release is missing self_hosted bundle metadata');
  }
  return result;
}

export function filterPublicProvenance(stagingProvenance) {
  if (!stagingProvenance || typeof stagingProvenance !== 'object') {
    throw new Error('Invalid release provenance payload');
  }
  const allowedTargets = new Set(PUBLIC_TARGETS);
  const stagingArtifacts = Array.isArray(stagingProvenance.artifacts)
    ? stagingProvenance.artifacts
    : [];
  const publicArtifacts = stagingArtifacts
    .filter((item) => item && allowedTargets.has(item.target))
    .map((item) => ({
      bytes: item.bytes,
      name: item.name,
      sha256: item.sha256,
      target: item.target,
    }));
  if (publicArtifacts.length !== PUBLIC_TARGETS.length) {
    throw new Error(
      `Provenance missing required public targets (found ${publicArtifacts.length} of ${PUBLIC_TARGETS.length})`,
    );
  }
  const builderSha = String(stagingProvenance.builder_sha || '');
  if (!/^[0-9a-f]{40}$/.test(builderSha)) {
    throw new Error('Provenance missing valid 40-char builder_sha');
  }
  const sanitized = {
    ...stagingProvenance,
    source_sha: builderSha,
    inventory_scope: 'public-application-artifacts',
    artifacts: publicArtifacts,
  };
  return sanitized;
}

export function buildPublicSha256Sums(entries) {
  const sorted = [...entries].sort((a, b) => a.name.localeCompare(b.name));
  return sorted.map((entry) => `${entry.sha256}  ${entry.name}\n`).join('');
}

export function assertNoPrivateLeakInPublicMetadata(filename, content) {
  const text = typeof content === 'string' ? content : content.toString('utf8');
  for (const forbiddenTarget of FORBIDDEN_PRIVATE_TARGETS) {
    const tokenRegex = new RegExp(`"${forbiddenTarget}"`, 'i');
    if (tokenRegex.test(text)) {
      throw new Error(
        `Public metadata ${filename} leaked private target "${forbiddenTarget}"`,
      );
    }
  }
  for (const pattern of FORBIDDEN_ASSET_PATTERNS) {
    if (pattern.test(text)) {
      throw new Error(
        `Public metadata ${filename} leaked private asset pattern ${pattern}`,
      );
    }
  }
  if (/omnisolo-llc\/leapterm(?!-release)/i.test(text)) {
    throw new Error(
      `Public metadata ${filename} leaked private repository omnisolo-llc/leapterm`,
    );
  }
}

export function resolveGpgSigningCredentials(signingConfig) {
  if (!signingConfig || typeof signingConfig !== 'object') {
    return { privateKeyBase64: '', passphrase: '', keyId: '' };
  }
  const privateKeyBase64 = String(
    signingConfig.PACKAGE_SIGNING_PRIVATE_KEY_BASE64 ||
      signingConfig.gpg_private_key_base64 ||
      '',
  ).trim();
  const passphrase = String(
    signingConfig.PACKAGE_SIGNING_PASSPHRASE ||
      signingConfig.gpg_passphrase ||
      '',
  );
  const keyId = String(
    signingConfig.PACKAGE_SIGNER_FINGERPRINT || signingConfig.gpg_key_id || '',
  ).trim();
  return { privateKeyBase64, passphrase, keyId };
}

function verifyGpgSignature(keyringPath, signaturePath, payloadPath) {
  execFileSync(
    'gpg',
    [
      '--batch',
      '--no-default-keyring',
      '--keyring',
      keyringPath,
      '--verify',
      signaturePath,
      payloadPath,
    ],
    { stdio: 'pipe' },
  );
}

function signDetachedWithGpg(signingConfig, payloadPath, outputSigPath) {
  const { privateKeyBase64, passphrase, keyId } =
    resolveGpgSigningCredentials(signingConfig);
  if (!privateKeyBase64) {
    throw new Error('Missing GPG private key in PACKAGE_SIGNING_CONFIG');
  }
  const gpgHome = fs.mkdtempSync(path.join(os.tmpdir(), 'omni-promote-gpg-'));
  fs.chmodSync(gpgHome, 0o700);
  try {
    const keyBytes = Buffer.from(privateKeyBase64, 'base64');
    const keyFile = path.join(gpgHome, 'private.key');
    fs.writeFileSync(keyFile, keyBytes, { mode: 0o600 });
    execFileSync(
      'gpg',
      ['--batch', '--homedir', gpgHome, '--import', keyFile],
      { stdio: 'pipe' },
    );
    const args = [
      '--batch',
      '--yes',
      '--homedir',
      gpgHome,
      '--pinentry-mode',
      'loopback',
      '--passphrase-fd',
      '0',
      '--detach-sign',
      '--armor',
    ];
    if (keyId) {
      args.push('--local-user', keyId);
    }
    args.push('--output', outputSigPath, payloadPath);
    execFileSync('gpg', args, {
      input: `${passphrase}\n`,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
  } finally {
    fs.rmSync(gpgHome, { recursive: true, force: true });
  }
}

async function githubRequest(url, token, options = {}) {
  const headers = {
    Accept: options.accept || 'application/vnd.github+json',
    Authorization: `Bearer ${token}`,
    'X-GitHub-Api-Version': '2022-11-28',
    'User-Agent': 'omniterm-release-promoter',
    ...(options.headers || {}),
  };
  const response = await fetch(url, {
    method: options.method || 'GET',
    headers,
    body: options.body,
    redirect: 'follow',
  });
  if (!response.ok) {
    throw new Error(`GitHub API request failed (${response.status}) for ${url}`);
  }
  return response;
}

async function downloadReleaseAsset(assetUrl, token, destinationPath) {
  const response = await githubRequest(assetUrl, token, {
    accept: 'application/octet-stream',
  });
  const arrayBuffer = await response.arrayBuffer();
  fs.writeFileSync(destinationPath, Buffer.from(arrayBuffer));
}

export function createAppStoreConnectJwt({
  keyId,
  issuerId,
  privateKeyBase64,
  nowSeconds = Math.floor(Date.now() / 1000),
}) {
  if (!keyId || !issuerId || !privateKeyBase64) {
    throw new Error(
      'App Store Connect credentials require APP_STORE_CONNECT_KEY_ID, APP_STORE_CONNECT_ISSUER_ID, and APP_STORE_CONNECT_API_KEY_BASE64',
    );
  }
  const pem = Buffer.from(privateKeyBase64, 'base64').toString('utf8');
  const header = Buffer.from(
    JSON.stringify({ alg: 'ES256', kid: keyId, typ: 'JWT' }),
  ).toString('base64url');
  const payload = Buffer.from(
    JSON.stringify({
      iss: issuerId,
      iat: nowSeconds,
      exp: nowSeconds + 1200,
      aud: 'appstoreconnect-v1',
    }),
  ).toString('base64url');
  const unsigned = `${header}.${payload}`;
  const signature = crypto
    .sign('sha256', Buffer.from(unsigned, 'utf8'), {
      key: pem,
      dsaEncoding: 'ieee-p1363',
    })
    .toString('base64url');
  return `${unsigned}.${signature}`;
}

export async function verifyAppleStoreAccess({
  appleSigningConfigJson,
  appBundleId = 'dev.omniterm.app',
  fetchImpl = fetch,
}) {
  const signing = JSON.parse(appleSigningConfigJson || '{}');
  const keyId = String(signing.APP_STORE_CONNECT_KEY_ID || '').trim();
  const issuerId = String(signing.APP_STORE_CONNECT_ISSUER_ID || '').trim();
  const apiKeyBase64 = String(
    signing.APP_STORE_CONNECT_API_KEY_BASE64 || '',
  ).trim();
  const jwt = createAppStoreConnectJwt({
    keyId,
    issuerId,
    privateKeyBase64: apiKeyBase64,
  });
  const url = `https://api.appstoreconnect.apple.com/v1/apps?filter[bundleId]=${encodeURIComponent(appBundleId)}`;
  const res = await fetchImpl(url, {
    headers: {
      Authorization: `Bearer ${jwt}`,
      Accept: 'application/json',
    },
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const detail =
      data?.errors?.map((e) => e.detail || e.title).join('; ') ||
      `HTTP ${res.status}`;
    throw new Error(`App Store Connect verification failed: ${detail}`);
  }
  const app = data?.data?.[0];
  if (!app?.id) {
    throw new Error(
      `App Store Connect app not found for bundleId ${appBundleId}`,
    );
  }
  return {
    provider: 'app-store-connect',
    bundleId: appBundleId,
    ascAppId: app.id,
    status: 'verified',
  };
}

export async function verifyGooglePlayStoreAccess({
  serviceAccountJson,
  packageName = 'dev.omniterm.app',
  fetchImpl = fetch,
}) {
  const key = JSON.parse(serviceAccountJson || '{}');
  if (
    key.type !== 'service_account' ||
    !key.client_email ||
    !key.private_key
  ) {
    throw new Error(
      'GOOGLE_PLAY_SERVICE_ACCOUNT_JSON must be a valid Google Cloud service_account key JSON',
    );
  }
  const encode = (value) =>
    Buffer.from(JSON.stringify(value)).toString('base64url');
  const now = Math.floor(Date.now() / 1000);
  const unsigned = `${encode({ alg: 'RS256', typ: 'JWT' })}.${encode({
    iss: key.client_email,
    scope: 'https://www.googleapis.com/auth/androidpublisher',
    aud: 'https://oauth2.googleapis.com/token',
    iat: now,
    exp: now + 3600,
  })}`;
  const signer = crypto.createSign('RSA-SHA256');
  signer.update(unsigned);
  const assertion = `${unsigned}.${signer.sign(key.private_key, 'base64url')}`;
  const tokenRes = await fetchImpl('https://oauth2.googleapis.com/token', {
    method: 'POST',
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion,
    }),
  });
  const tokenData = await tokenRes.json().catch(() => ({}));
  if (!tokenRes.ok || !tokenData.access_token) {
    throw new Error(`Google OAuth token exchange failed (${tokenRes.status})`);
  }
  const apiBase = `https://androidpublisher.googleapis.com/androidpublisher/v3/applications/${encodeURIComponent(packageName)}/`;
  const editRes = await fetchImpl(`${apiBase}edits`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${tokenData.access_token}`,
      'Content-Type': 'application/json',
    },
    body: '{}',
  });
  const editData = await editRes.json().catch(() => ({}));
  if (!editRes.ok || !editData.id) {
    throw new Error(
      `Google Play edits probe failed (${editRes.status}): ${editData?.error?.message || 'unknown'}`,
    );
  }
  try {
    const tracksRes = await fetchImpl(
      `${apiBase}edits/${encodeURIComponent(editData.id)}/tracks`,
      {
        headers: {
          Authorization: `Bearer ${tokenData.access_token}`,
          Accept: 'application/json',
        },
      },
    );
    const tracksData = await tracksRes.json().catch(() => ({}));
    if (!tracksRes.ok) {
      throw new Error(`Google Play tracks probe failed (${tracksRes.status})`);
    }
    return {
      provider: 'google-play',
      packageName,
      serviceAccount: key.client_email,
      tracks: (tracksData.tracks || []).map((t) => t.track),
      status: 'verified',
    };
  } finally {
    await fetchImpl(`${apiBase}edits/${encodeURIComponent(editData.id)}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
    }).catch(() => {});
  }
}

export async function promoteAppleToAppStoreConnect({
  platform = 'ios',
  version,
  buildNumber,
  action,
  automaticRelease = false,
  packagePath = '',
  appleSigningConfigJson,
  appBundleId = 'dev.omniterm.app',
  fetchImpl = fetch,
  execFileImpl = execFileSync,
}) {
  if (!['ios', 'macos'].includes(platform)) {
    throw new Error(`Unsupported Apple platform: ${platform}`);
  }
  if (!['testflight', 'app-store'].includes(action)) {
    throw new Error(`Unsupported ${platform}_store_action: ${action}`);
  }
  const ascPlatform = platform === 'macos' ? 'MAC_OS' : 'IOS';
  const altoolType = platform === 'macos' ? 'osx' : 'ios';
  const normalizedVersion = String(version || '').trim().replace(/^v/, '');
  const normalizedBuild = String(buildNumber || '').trim();
  if (!normalizedVersion || !/^\d+$/.test(normalizedBuild)) {
    throw new Error(
      `${platform} store promotion requires valid version and positive integer build_number`,
    );
  }
  const signing = JSON.parse(appleSigningConfigJson || '{}');
  const keyId = String(signing.APP_STORE_CONNECT_KEY_ID || '').trim();
  const issuerId = String(signing.APP_STORE_CONNECT_ISSUER_ID || '').trim();
  const apiKeyBase64 = String(
    signing.APP_STORE_CONNECT_API_KEY_BASE64 || '',
  ).trim();
  const jwt = createAppStoreConnectJwt({
    keyId,
    issuerId,
    privateKeyBase64: apiKeyBase64,
  });

  const ascRequest = async (endpoint, method = 'GET', body = null) => {
    const url = new URL(endpoint, 'https://api.appstoreconnect.apple.com');
    if (url.origin !== 'https://api.appstoreconnect.apple.com') {
      throw new Error('Untrusted App Store Connect URL');
    }
    const res = await fetchImpl(url.toString(), {
      method,
      headers: {
        Authorization: `Bearer ${jwt}`,
        Accept: 'application/json',
        ...(body ? { 'Content-Type': 'application/json' } : {}),
      },
      ...(body ? { body: JSON.stringify(body) } : {}),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      const detail =
        data?.errors?.map((e) => e.detail || e.title).join('; ') ||
        `HTTP ${res.status}`;
      throw new Error(
        `App Store Connect API ${method} ${url.pathname} failed: ${detail}`,
      );
    }
    return data;
  };

  if (action === 'testflight') {
    if (!packagePath || !fs.existsSync(packagePath)) {
      throw new Error(
        `TestFlight candidate upload for ${platform} requires verified packagePath`,
      );
    }
    const keyDir = fs.mkdtempSync(path.join(os.tmpdir(), 'omni-asc-key-'));
    fs.chmodSync(keyDir, 0o700);
    let tempKeychain = null;
    try {
      const keyFile = path.join(keyDir, `AuthKey_${keyId}.p8`);
      fs.writeFileSync(keyFile, Buffer.from(apiKeyBase64, 'base64'), {
        mode: 0o600,
      });
      let uploadFilePath = packagePath;
      if (platform === 'macos' && packagePath.endsWith('.zip')) {
        const installerIdentity = String(
          signing.MACOS_INSTALLER_IDENTITY ||
            signing.MACOS_DEVELOPER_ID_INSTALLER ||
            '',
        ).trim();
        if (!installerIdentity) {
          throw new Error(
            'macOS TestFlight .zip-to-.pkg packaging requires MACOS_INSTALLER_IDENTITY in MACOS_SIGNING_CONFIG',
          );
        }
        const extractDir = path.join(keyDir, 'macos-extract');
        fs.mkdirSync(extractDir, { recursive: true });
        execFileImpl('ditto', ['-x', '-k', packagePath, extractDir], {
          stdio: 'pipe',
        });
        const entries = fs.readdirSync(extractDir);
        const appName = entries.find((e) => e.endsWith('.app'));
        if (!appName) {
          throw new Error(
            `macOS archive ${path.basename(packagePath)} does not contain a .app bundle`,
          );
        }
        const certificatePrefix = [
          'MACOS_INSTALLER',
          'MACOS_DEVELOPER_ID_INSTALLER',
          'MACOS_DEVELOPER_ID',
        ].find((prefix) =>
          String(signing[`${prefix}_CERTIFICATE_BASE64`] || '').trim(),
        );
        const certBase64 = certificatePrefix
          ? String(signing[`${certificatePrefix}_CERTIFICATE_BASE64`]).trim()
          : '';
        const certPassword = certificatePrefix
          ? String(signing[`${certificatePrefix}_CERTIFICATE_PASSWORD`] ?? '')
          : '';
        if (certBase64) {
          const p12Path = path.join(keyDir, 'installer.p12');
          fs.writeFileSync(p12Path, Buffer.from(certBase64, 'base64'), {
            mode: 0o600,
          });
          tempKeychain = path.join(keyDir, 'installer.keychain-db');
          const kcPass = crypto.randomBytes(24).toString('hex');
          try {
            execFileImpl(
              'security',
              ['create-keychain', '-p', kcPass, tempKeychain],
              { stdio: 'pipe' },
            );
            execFileImpl(
              'security',
              ['unlock-keychain', '-p', kcPass, tempKeychain],
              { stdio: 'pipe' },
            );
            execFileImpl(
              'security',
              [
                'import',
                p12Path,
                '-P',
                certPassword,
                '-T',
                '/usr/bin/productbuild',
                '-T',
                '/usr/bin/productsign',
                '-f',
                'pkcs12',
                '-k',
                tempKeychain,
              ],
              { stdio: 'pipe' },
            );
            execFileImpl(
              'security',
              [
                'set-key-partition-list',
                '-S',
                'apple-tool:,apple:,codesign:,productsign:',
                '-k',
                kcPass,
                tempKeychain,
              ],
              { stdio: 'pipe' },
            );
          } catch {
            // Child-process errors can include password-bearing command arguments.
            throw new Error('macOS installer certificate import failed');
          }
        }
        const pkgPath = path.join(
          keyDir,
          `omniterm-${normalizedVersion}-macos.pkg`,
        );
        const productbuildArgs = [
          '--component',
          path.join(extractDir, appName),
          '/Applications',
          '--sign',
          installerIdentity,
        ];
        if (tempKeychain) {
          productbuildArgs.push('--keychain', tempKeychain);
        }
        productbuildArgs.push(pkgPath);
        execFileImpl('productbuild', productbuildArgs, { stdio: 'pipe' });
        uploadFilePath = pkgPath;
      }
      execFileImpl(
        'xcrun',
        [
          'altool',
          '--upload-app',
          '--type',
          altoolType,
          '--file',
          uploadFilePath,
          '--apiKey',
          keyId,
          '--apiIssuer',
          issuerId,
        ],
        {
          env: {
            ...process.env,
            API_PRIVATE_KEYS_DIR: keyDir,
          },
          stdio: 'pipe',
        },
      );
    } finally {
      if (tempKeychain) {
        try {
          execFileImpl('security', ['delete-keychain', tempKeychain], {
            stdio: 'pipe',
          });
        } catch {
          // ignore cleanup failure
        }
      }
      fs.rmSync(keyDir, { recursive: true, force: true });
    }
    return {
      platform,
      action: 'testflight',
      version: normalizedVersion,
      build_number: normalizedBuild,
      status: 'uploaded-to-testflight',
    };
  }

  // action === 'app-store': promote verified TestFlight build to App Store review
  const appsRes = await ascRequest(
    `/v1/apps?filter[bundleId]=${encodeURIComponent(appBundleId)}`,
  );
  const app = appsRes?.data?.[0];
  if (!app?.id) {
    throw new Error(
      `App Store Connect app not found for bundleId ${appBundleId}`,
    );
  }

  const buildsRes = await ascRequest(
    `/v1/builds?filter[app]=${encodeURIComponent(app.id)}&filter[preReleaseVersion.version]=${encodeURIComponent(normalizedVersion)}&filter[version]=${encodeURIComponent(normalizedBuild)}&filter[preReleaseVersion.platform]=${ascPlatform}`,
  );
  const builds = Array.isArray(buildsRes?.data) ? buildsRes.data : [];
  if (builds.length !== 1) {
    throw new Error(
      `Expected exactly 1 processed ${ascPlatform} TestFlight candidate build for v${normalizedVersion} (${normalizedBuild}), found ${builds.length}`,
    );
  }
  const build = builds[0];
  if (
    build?.attributes?.processingState !== 'VALID' ||
    build?.attributes?.expired === true
  ) {
    throw new Error(
      `TestFlight candidate build ${build.id} is not in VALID non-expired state`,
    );
  }

  const releaseType = automaticRelease ? 'AFTER_APPROVAL' : 'MANUAL';
  const versionsRes = await ascRequest(
    `/v1/apps/${encodeURIComponent(app.id)}/appStoreVersions?filter[versionString]=${encodeURIComponent(normalizedVersion)}&filter[platform]=${ascPlatform}`,
  );
  let appStoreVersion = versionsRes?.data?.[0];
  if (!appStoreVersion) {
    const created = await ascRequest('/v1/appStoreVersions', 'POST', {
      data: {
        type: 'appStoreVersions',
        attributes: {
          platform: ascPlatform,
          versionString: normalizedVersion,
          releaseType,
        },
        relationships: {
          app: {
            data: { type: 'apps', id: app.id },
          },
          build: {
            data: { type: 'builds', id: build.id },
          },
        },
      },
    });
    appStoreVersion = created?.data;
  } else {
    await ascRequest(
      `/v1/appStoreVersions/${encodeURIComponent(appStoreVersion.id)}`,
      'PATCH',
      {
        data: {
          type: 'appStoreVersions',
          id: appStoreVersion.id,
          attributes: { releaseType },
        },
      },
    );
    await ascRequest(
      `/v1/appStoreVersions/${encodeURIComponent(appStoreVersion.id)}/relationships/build`,
      'PATCH',
      {
        data: { type: 'builds', id: build.id },
      },
    );
  }

  await ascRequest('/v1/appStoreVersionSubmissions', 'POST', {
    data: {
      type: 'appStoreVersionSubmissions',
      relationships: {
        appStoreVersion: {
          data: { type: 'appStoreVersions', id: appStoreVersion.id },
        },
      },
    },
  });

  return {
    platform,
    action: 'app-store',
    version: normalizedVersion,
    build_number: normalizedBuild,
    asc_app_id: app.id,
    asc_build_id: build.id,
    asc_version_id: appStoreVersion.id,
    release_type: releaseType,
    status: 'submitted-for-review',
  };
}

export async function promoteIosToAppStoreConnect({
  version,
  buildNumber,
  action,
  automaticRelease = false,
  ipaPath = '',
  iosSigningConfigJson,
  appBundleId = 'dev.omniterm.app',
  fetchImpl = fetch,
  execFileImpl = execFileSync,
}) {
  return promoteAppleToAppStoreConnect({
    platform: 'ios',
    version,
    buildNumber,
    action,
    automaticRelease,
    packagePath: ipaPath,
    appleSigningConfigJson: iosSigningConfigJson,
    appBundleId,
    fetchImpl,
    execFileImpl,
  });
}

export async function promoteMacosToAppStoreConnect({
  version,
  buildNumber,
  action,
  automaticRelease = false,
  packagePath = '',
  macosSigningConfigJson,
  appBundleId = 'dev.omniterm.app',
  fetchImpl = fetch,
  execFileImpl = execFileSync,
}) {
  return promoteAppleToAppStoreConnect({
    platform: 'macos',
    version,
    buildNumber,
    action,
    automaticRelease,
    packagePath,
    appleSigningConfigJson: macosSigningConfigJson,
    appBundleId,
    fetchImpl,
    execFileImpl,
  });
}

export async function promoteAndroidToPlayStore({
  version,
  buildNumber,
  track,
  aabPath,
  serviceAccountJson,
  packageName = 'dev.omniterm.app',
  fetchImpl = fetch,
}) {
  if (!['internal', 'alpha', 'beta', 'production'].includes(track)) {
    throw new Error(`Unsupported android_store_action track: ${track}`);
  }
  const normalizedVersion = String(version || '').trim().replace(/^v/, '');
  const normalizedBuild = String(buildNumber || '').trim();
  if (!normalizedVersion || !/^\d+$/.test(normalizedBuild)) {
    throw new Error(
      'Google Play promotion requires valid version and positive integer build_number',
    );
  }
  if (!aabPath || !fs.existsSync(aabPath)) {
    throw new Error('Google Play promotion requires verified aabPath');
  }
  const key = JSON.parse(serviceAccountJson || '{}');
  if (
    key.type !== 'service_account' ||
    !key.client_email ||
    !key.private_key
  ) {
    throw new Error(
      'GOOGLE_PLAY_SERVICE_ACCOUNT_JSON must be a valid Google Cloud service_account key JSON',
    );
  }

  const encode = (value) =>
    Buffer.from(JSON.stringify(value)).toString('base64url');
  const now = Math.floor(Date.now() / 1000);
  const unsigned = `${encode({ alg: 'RS256', typ: 'JWT' })}.${encode({
    iss: key.client_email,
    scope: 'https://www.googleapis.com/auth/androidpublisher',
    aud: 'https://oauth2.googleapis.com/token',
    iat: now,
    exp: now + 3600,
  })}`;
  const signer = crypto.createSign('RSA-SHA256');
  signer.update(unsigned);
  const assertion = `${unsigned}.${signer.sign(key.private_key, 'base64url')}`;

  const tokenRes = await fetchImpl('https://oauth2.googleapis.com/token', {
    method: 'POST',
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion,
    }),
  });
  const tokenData = await tokenRes.json().catch(() => ({}));
  if (!tokenRes.ok || !tokenData.access_token) {
    throw new Error(`Google OAuth token exchange failed (${tokenRes.status})`);
  }

  const apiBase = `https://androidpublisher.googleapis.com/androidpublisher/v3/applications/${encodeURIComponent(packageName)}/`;
  const playRequest = async (
    subpath,
    method = 'GET',
    body = null,
    isMediaUpload = false,
  ) => {
    const base = isMediaUpload
      ? apiBase.replace('/androidpublisher/', '/upload/androidpublisher/')
      : apiBase;
    const url = new URL(subpath, base);
    if (url.origin !== 'https://androidpublisher.googleapis.com') {
      throw new Error('Untrusted Google Play API origin');
    }
    const res = await fetchImpl(url.toString(), {
      method,
      headers: {
        Authorization: `Bearer ${tokenData.access_token}`,
        'Content-Type': isMediaUpload
          ? 'application/octet-stream'
          : 'application/json',
      },
      ...(body
        ? { body: isMediaUpload ? body : JSON.stringify(body) }
        : {}),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      const msg = data?.error?.message || `HTTP ${res.status}`;
      throw new Error(
        `Google Play API ${method} ${url.pathname} failed: ${msg}`,
      );
    }
    return data;
  };

  const edit = await playRequest('edits', 'POST', {});
  const editId = edit.id;
  if (!editId) {
    throw new Error('Google Play API did not return an edit id');
  }
  try {
    const existingBundles = await playRequest(
      `edits/${encodeURIComponent(editId)}/bundles`,
    );
    const versionCode = Number(normalizedBuild);
    const alreadyUploaded = (existingBundles.bundles || []).some(
      (b) => Number(b.versionCode) === versionCode,
    );
    if (!alreadyUploaded) {
      const aabBytes = fs.readFileSync(aabPath);
      const expectedSha = sha256Hex(aabBytes);
      const uploaded = await playRequest(
        `edits/${encodeURIComponent(editId)}/bundles?uploadType=media`,
        'POST',
        aabBytes,
        true,
      );
      if (
        Number(uploaded.versionCode) !== versionCode ||
        (uploaded.sha256 && uploaded.sha256.toLowerCase() !== expectedSha)
      ) {
        throw new Error(
          `Uploaded AAB versionCode/sha256 mismatch (expected ${versionCode}/${expectedSha}, got ${uploaded.versionCode}/${uploaded.sha256})`,
        );
      }
    }

    await playRequest(
      `edits/${encodeURIComponent(editId)}/tracks/${encodeURIComponent(track)}`,
      'PUT',
      {
        track,
        releases: [
          {
            name: `v${normalizedVersion} (${normalizedBuild})`,
            versionCodes: [String(versionCode)],
            status: 'completed',
          },
        ],
      },
    );

    await playRequest(
      `edits/${encodeURIComponent(editId)}:validate`,
      'POST',
      {},
    );
    await playRequest(`edits/${encodeURIComponent(editId)}:commit`, 'POST', {});
  } catch (err) {
    await playRequest(`edits/${encodeURIComponent(editId)}`, 'DELETE').catch(
      () => {},
    );
    throw err;
  }

  return {
    platform: 'android',
    track,
    version: normalizedVersion,
    build_number: normalizedBuild,
    status: 'committed',
  };
}

export function resolveRolloutEnvironment({
  rolloutEnvironment = 'auto',
  publishGithubRelease = false,
  iosStoreAction = 'none',
  macosStoreAction = 'none',
  androidStoreAction = 'none',
  verifyStoreCredentialsOnly = false,
} = {}) {
  if (verifyStoreCredentialsOnly) {
    return 'none';
  }
  const normalized = String(rolloutEnvironment || 'auto')
    .trim()
    .toLowerCase();
  if (!['auto', 'none', 'staging', 'production'].includes(normalized)) {
    throw new Error(`Unsupported rollout_environment: ${rolloutEnvironment}`);
  }
  if (normalized !== 'auto') {
    return normalized;
  }
  const isProductionStore =
    iosStoreAction === 'app-store' ||
    macosStoreAction === 'app-store' ||
    androidStoreAction === 'production';
  if (publishGithubRelease || isProductionStore) {
    return 'production';
  }
  const isStagingStore =
    iosStoreAction === 'testflight' ||
    macosStoreAction === 'testflight' ||
    ['internal', 'alpha', 'beta'].includes(androidStoreAction);
  if (isStagingStore) {
    return 'staging';
  }
  return 'none';
}

export function buildEnvironmentRolloutPlan({
  environment,
  version,
  buildNumber = '',
  sourceSha = '',
  containerRegistry = PRIMARY_CONTAINER_REGISTRY,
  containerTag = '',
}) {
  if (!['staging', 'production'].includes(environment)) {
    throw new Error(
      `Unsupported rollout environment for plan: ${environment}`,
    );
  }
  const normalizedVersion = String(version || '').trim().replace(/^v/, '');
  const normalizedBuild = String(buildNumber || '').trim();
  const normalizedRegistry = String(
    containerRegistry || PRIMARY_CONTAINER_REGISTRY,
  )
    .trim()
    .replace(/\/+$/, '');
  const isStaging = environment === 'staging';
  const imageTag =
    String(containerTag || '').trim() ||
    (isStaging ? 'cloud-staging-latest' : 'cloud-latest');
  const aliasTag = isStaging ? 'latest-staging' : 'latest';
  const clientTag = isStaging ? 'client-staging-latest' : 'client-latest';
  const containerImage = `${normalizedRegistry}:${imageTag}`;
  return {
    environment,
    version: normalizedVersion,
    build_number: normalizedBuild,
    source_sha: String(sourceSha || '').trim(),
    containerTag: imageTag,
    containerImage,
    cloudflare: {
      env: isStaging ? 'staging' : 'production',
      api_origin: isStaging
        ? 'https://api.staging.leapterm.com'
        : 'https://api.leapterm.com',
      cloud_origin: isStaging
        ? 'https://cloud.staging.leapterm.com'
        : 'https://cloud.leapterm.com',
    },
    container: {
      registry: normalizedRegistry,
      image_tag: imageTag,
      alias_tag: aliasTag,
      client_tag: clientTag,
      image: containerImage,
      alias_image: `${normalizedRegistry}:${aliasTag}`,
      client_image: `${normalizedRegistry}:${clientTag}`,
      prune_script: 'scripts/prune-ghcr-packages.mjs',
    },
    k3s: {
      namespace: 'omniterm',
      deployment: isStaging ? 'omniterm-staging' : 'omniterm',
      host: isStaging ? 'cloud.staging.leapterm.com' : 'cloud.leapterm.com',
    },
    rollout_command: ['bash', 'scripts/rollout-env.sh', '--env', environment],
    prune_command: ['node', 'scripts/prune-ghcr-packages.mjs'],
  };
}

function requireEnvironmentRolloutCredentials() {
  for (const name of ['CLOUDFLARE_API_TOKEN', 'CLOUDFLARE_ACCOUNT_ID', 'KUBECONFIG']) {
    if (!String(process.env[name] || '').trim()) {
      throw new Error(`${name} is required for environment rollout`);
    }
  }
  if (!/^[A-Za-z0-9][A-Za-z0-9./_:-]*@sha256:[a-f0-9]{64}$/.test(String(process.env.OMNI_GATEWAY_SOURCE_IMAGE || ''))) {
    throw new Error('OMNI_GATEWAY_SOURCE_IMAGE is required as an immutable repository@sha256 digest pin');
  }
}

export function executeEnvironmentRollout({
  environment,
  version,
  buildNumber = '',
  sourceSha = '',
  sourceRoot = '',
  stagingRepo = STAGING_REPOSITORY,
  privateToken = '',
  githubToken = '',
  dockerHubUsername = 'omniterm',
  dockerHubPatReadWrite = '',
  dockerHubPatReadOnly = '',
  containerRegistry = PRIMARY_CONTAINER_REGISTRY,
  execFileImpl = execFileSync,
}) {
  const plan = buildEnvironmentRolloutPlan({
    environment,
    version,
    buildNumber,
    sourceSha,
    containerRegistry,
  });
  if (!/^[0-9a-f]{40}$/i.test(plan.source_sha)) {
    throw new Error('Rollout source_sha must be an exact 40-character commit SHA');
  }

  let resolvedRoot = String(
    sourceRoot || process.env.PROMOTE_SOURCE_ROOT || '',
  ).trim();
  let tempCheckoutDir = '';
  let tempKubeconfigDir = '';

  try {
    requireEnvironmentRolloutCredentials();
    const configuredKubeconfig = process.env.KUBECONFIG;
    let kubeconfigBytes = Buffer.from(configuredKubeconfig, 'utf8');
    let kubeconfigStat;
    try {
      kubeconfigStat = fs.statSync(configuredKubeconfig);
    } catch (error) {
      if (!['ENOENT', 'ENOTDIR', 'ENAMETOOLONG'].includes(error.code)) {
        throw new Error('KUBECONFIG must contain opaque content or name a readable regular file');
      }
    }
    if (kubeconfigStat) {
      if (!kubeconfigStat.isFile()) {
        throw new Error('KUBECONFIG must name a readable regular file');
      }
      try {
        kubeconfigBytes = fs.readFileSync(configuredKubeconfig);
      } catch {
        throw new Error('KUBECONFIG must name a readable regular file');
      }
    }
    if (!kubeconfigBytes.toString('utf8').trim()) {
      throw new Error('KUBECONFIG file must not be empty');
    }
    tempKubeconfigDir = fs.mkdtempSync(path.join(os.tmpdir(), 'omni-rollout-kubeconfig-'));
    fs.chmodSync(tempKubeconfigDir, 0o700);
    const kubeconfigPath = path.join(tempKubeconfigDir, 'config');
    fs.writeFileSync(kubeconfigPath, kubeconfigBytes, { mode: 0o600, flag: 'wx' });
    fs.chmodSync(kubeconfigPath, 0o600);
    const rolloutEnv = { ...process.env, KUBECONFIG: kubeconfigPath };

    if (!resolvedRoot) {
      if (!privateToken) {
        throw new Error('Rollout requires a source checkout or private checkout token');
      }
      tempCheckoutDir = fs.mkdtempSync(
        path.join(os.tmpdir(), 'omni-rollout-src-'),
      );
      const cloneUrl = `https://github.com/${stagingRepo}.git`;
      try {
        execFileImpl('git', ['init', tempCheckoutDir], { stdio: 'pipe', env: rolloutEnv });
        execFileImpl(
          'git',
          ['-C', tempCheckoutDir, 'remote', 'add', 'origin', cloneUrl],
          { stdio: 'pipe', env: rolloutEnv },
        );
        execFileImpl(
          'git',
          ['-C', tempCheckoutDir, 'fetch', '--depth=1', 'origin', plan.source_sha],
          {
            stdio: 'pipe',
            env: {
              ...rolloutEnv,
              GIT_TERMINAL_PROMPT: '0',
              GIT_CONFIG_COUNT: '1',
              GIT_CONFIG_KEY_0: 'http.https://github.com/.extraheader',
              GIT_CONFIG_VALUE_0: `AUTHORIZATION: basic ${Buffer.from(`x-access-token:${privateToken}`).toString('base64')}`,
            },
          },
        );
        execFileImpl(
          'git',
          ['-C', tempCheckoutDir, 'checkout', '--detach', 'FETCH_HEAD'],
          { stdio: 'pipe', env: rolloutEnv },
        );
      } catch {
        throw new Error('Unable to acquire rollout source checkout');
      }
      resolvedRoot = tempCheckoutDir;
    }

    let checkoutRoot;
    let gitRoot;
    let checkoutSha;
    let checkoutStatus;
    try {
      checkoutRoot = fs.realpathSync(resolvedRoot);
      const readOptions = {
        stdio: 'pipe',
        encoding: 'utf8',
        env: { ...rolloutEnv, GIT_OPTIONAL_LOCKS: '0' },
      };
      gitRoot = fs.realpathSync(String(execFileImpl(
        'git', ['-C', checkoutRoot, 'rev-parse', '--show-toplevel'], readOptions,
      )).trim());
      checkoutSha = String(execFileImpl(
        'git', ['-C', checkoutRoot, 'rev-parse', '--verify', 'HEAD'], readOptions,
      )).trim();
      checkoutStatus = String(execFileImpl(
        'git', ['-C', checkoutRoot, 'status', '--porcelain=v1', '--untracked-files=all', '--ignore-submodules=none'], readOptions,
      ));
    } catch {
      throw new Error('Unable to validate rollout source checkout');
    }
    if (gitRoot !== checkoutRoot) {
      throw new Error('Rollout source checkout must be the repository root');
    }
    if (checkoutSha.toLowerCase() !== plan.source_sha.toLowerCase()) {
      throw new Error('Rollout source checkout HEAD does not match approved source_sha commit');
    }
    if (checkoutStatus.trim()) {
      throw new Error('Rollout source checkout must be clean, with no local changes');
    }
    resolvedRoot = checkoutRoot;
    const rolloutScript = path.join(resolvedRoot, 'scripts', 'rollout-env.sh');
    if (!fs.existsSync(rolloutScript)) {
      throw new Error('Rollout source checkout is missing the rollout script');
    }

    const effectiveGithubToken =
      githubToken ||
      process.env.GITHUB_TOKEN ||
      privateToken ||
      process.env.GH_TOKEN ||
      '';
    const childEnv = {
      ...rolloutEnv,
      OMNI_REGISTRY: plan.container.registry,
      PROMOTE_CONTAINER_REGISTRY: plan.container.registry,
      PROMOTE_VERSION: plan.version,
      PROMOTE_BUILD_NUMBER: plan.build_number,
      RELEASE_SOURCE_SHA: plan.source_sha,
      DOCKER_HUB_USERNAME:
        dockerHubUsername || process.env.DOCKER_HUB_USERNAME || 'omniterm',
      DOCKER_HUB_PAT_READ_WRITE:
        dockerHubPatReadWrite || process.env.DOCKER_HUB_PAT_READ_WRITE || '',
      DOCKER_HUB_PAT_READ_ONLY:
        dockerHubPatReadOnly || process.env.DOCKER_HUB_PAT_READ_ONLY || '',
      GITHUB_TOKEN: effectiveGithubToken,
      GH_TOKEN: privateToken || effectiveGithubToken,
    };

    execFileImpl('bash', ['scripts/rollout-env.sh', '--env', environment], {
      cwd: resolvedRoot,
      env: childEnv,
      stdio: 'inherit',
    });

    const pruneScript = path.join(
      resolvedRoot,
      'scripts',
      'prune-ghcr-packages.mjs',
    );
    if (fs.existsSync(pruneScript)) {
      execFileImpl('node', ['scripts/prune-ghcr-packages.mjs'], {
        cwd: resolvedRoot,
        env: childEnv,
        stdio: 'inherit',
      });
    }

    return {
      ...plan,
      status: 'rolled-out',
    };
  } finally {
    if (tempKubeconfigDir) {
      fs.rmSync(tempKubeconfigDir, { recursive: true, force: true });
    }
    if (tempCheckoutDir) {
      fs.rmSync(tempCheckoutDir, { recursive: true, force: true });
    }
  }
}

export async function promoteRelease({
  version,
  expectedBuildNumber = '',
  stagingRepo = STAGING_REPOSITORY,
  publicRepo = PUBLIC_REPOSITORY,
  privateToken,
  publicToken,
  githubToken = '',
  dockerHubUsername = 'omniterm',
  dockerHubPatReadWrite = '',
  dockerHubPatReadOnly = '',
  signingConfigJson,
  publishGithubRelease = true,
  iosStoreAction = 'none',
  iosAutomaticRelease = false,
  iosSigningConfigJson = '',
  macosStoreAction = 'none',
  macosAutomaticRelease = false,
  macosSigningConfigJson = '',
  androidStoreAction = 'none',
  googlePlayServiceAccountJson = '',
  rolloutEnvironment = 'auto',
  containerRegistry = PRIMARY_CONTAINER_REGISTRY,
  sourceRoot = '',
  verifyStoreCredentialsOnly = false,
  execFileImpl = execFileSync,
}) {
  if (!privateToken) {
    throw new Error('PRIVATE_RELEASE_TOKEN is required');
  }
  const resolvedRolloutEnv = resolveRolloutEnvironment({
    rolloutEnvironment,
    publishGithubRelease,
    iosStoreAction,
    macosStoreAction,
    androidStoreAction,
    verifyStoreCredentialsOnly,
  });
  if (resolvedRolloutEnv !== 'none') requireEnvironmentRolloutCredentials();
  const actor = String(process.env.GITHUB_ACTOR || '').trim();
  if (actor) {
    const teamRes = await githubRequest(
      `https://api.github.com/orgs/omnisolo-llc/teams/release-eng/memberships/${encodeURIComponent(actor)}`,
      privateToken,
    );
    const teamData = await teamRes.json();
    if (teamData.state !== 'active') {
      throw new Error(
        `Release promotion requires active membership in the "Release Eng" (release-eng) team (actor: ${actor})`,
      );
    }
  }

  if (verifyStoreCredentialsOnly) {
    const results = [];
    if (googlePlayServiceAccountJson) {
      results.push(
        await verifyGooglePlayStoreAccess({
          serviceAccountJson: googlePlayServiceAccountJson,
        }),
      );
    }
    if (iosSigningConfigJson || macosSigningConfigJson) {
      results.push(
        await verifyAppleStoreAccess({
          appleSigningConfigJson: iosSigningConfigJson || macosSigningConfigJson,
        }),
      );
    }
    console.log(JSON.stringify({ verified_stores: results }, null, 2));
    return { verified_stores: results };
  }

  const normalizedVersion = String(version || '').trim().replace(/^v/, '');
  if (!/^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/.test(normalizedVersion)) {
    throw new Error(`Invalid version: ${version}`);
  }
  if (publishGithubRelease && !publicToken) {
    throw new Error('GH_TOKEN is required to publish public release');
  }
  const signingConfig = JSON.parse(signingConfigJson || '{}');
  const { privateKeyBase64 } = resolveGpgSigningCredentials(signingConfig);
  if (publishGithubRelease && !privateKeyBase64) {
    throw new Error(
      'PACKAGE_SIGNING_CONFIG with GPG private key is required to sign filtered public provenance and SHA256SUMS',
    );
  }

  const tag = `v${normalizedVersion}`;
  const stagingReleaseUrl = `https://api.github.com/repos/${stagingRepo}/releases/tags/${encodeURIComponent(tag)}`;
  const stagingRes = await githubRequest(stagingReleaseUrl, privateToken);
  const stagingRelease = await stagingRes.json();
  const assetsByName = new Map(
    (stagingRelease.assets || []).map((asset) => [asset.name, asset]),
  );

  const workDir = fs.mkdtempSync(path.join(os.tmpdir(), 'omni-promote-release-'));
  try {
    const requireStagingAsset = async (name) => {
      const asset = assetsByName.get(name);
      if (!asset) {
        throw new Error(
          `Staging release ${tag} is missing required asset: ${name}`,
        );
      }
      const dest = path.join(workDir, name);
      await downloadReleaseAsset(asset.url, privateToken, dest);
      return dest;
    };

    const keyringPath = await requireStagingAsset(
      'omni-terminal-archive-keyring.gpg',
    );
    const stagingLinksPath = await requireStagingAsset('download-links.json');
    const provenanceName = `omniterm-${normalizedVersion}-release-provenance.json`;
    const stagingProvPath = await requireStagingAsset(provenanceName);
    const stagingProvSigPath = await requireStagingAsset(
      `${provenanceName}.sig`,
    );

    verifyGpgSignature(keyringPath, stagingProvSigPath, stagingProvPath);

    const stagingLinks = JSON.parse(fs.readFileSync(stagingLinksPath, 'utf8'));
    const stagingProvenance = JSON.parse(
      fs.readFileSync(stagingProvPath, 'utf8'),
    );
    const resolvedBuildNumber = String(
      stagingLinks.build_number || stagingProvenance.build_number || '',
    );

    if (
      expectedBuildNumber &&
      resolvedBuildNumber !== String(expectedBuildNumber)
    ) {
      throw new Error(
        `Staging build_number mismatch: expected ${expectedBuildNumber}, found ${resolvedBuildNumber}`,
      );
    }

    if (publishGithubRelease) {
      const selfHostedName = `omniterm-${normalizedVersion}-self-hosted.zip`;
      const selfHostedBinPath = await requireStagingAsset(selfHostedName);
      const selfHostedShaPath = await requireStagingAsset(
        `${selfHostedName}.sha256`,
      );
      const selfHostedBytes = fs.statSync(selfHostedBinPath).size;
      const selfHostedSha = sha256Hex(fs.readFileSync(selfHostedBinPath));
      const recordedSelfHostedSha = fs
        .readFileSync(selfHostedShaPath, 'utf8')
        .trim()
        .split(/\s+/)[0];
      if (recordedSelfHostedSha !== selfHostedSha) {
        throw new Error(`.sha256 file mismatch for ${selfHostedName}`);
      }
      scanSelfHostedZipForLeaks(selfHostedBinPath);
      const selfHostedSigName = `${selfHostedName}.sha256.sig`;
      let selfHostedSigPath;
      if (assetsByName.has(selfHostedSigName)) {
        selfHostedSigPath = await requireStagingAsset(selfHostedSigName);
        verifyGpgSignature(keyringPath, selfHostedSigPath, selfHostedShaPath);
      } else {
        selfHostedSigPath = path.join(workDir, selfHostedSigName);
        signDetachedWithGpg(signingConfig, selfHostedShaPath, selfHostedSigPath);
        verifyGpgSignature(keyringPath, selfHostedSigPath, selfHostedShaPath);
      }

      const publicLinks = filterPublicDownloadLinks(stagingLinks, publicRepo, {
        name: selfHostedName,
        bytes: selfHostedBytes,
        sha256: selfHostedSha,
      });
      const publicProvenance = filterPublicProvenance(stagingProvenance);

      const filesToUpload = [];
      const sha256Entries = [];

      for (const item of publicLinks.artifacts) {
        const binPath = await requireStagingAsset(item.name);
        const shaPath = await requireStagingAsset(`${item.name}.sha256`);
        const sigPath = await requireStagingAsset(`${item.name}.sha256.sig`);

        const actualBytes = fs.statSync(binPath).size;
        const actualSha = sha256Hex(fs.readFileSync(binPath));
        if (actualSha !== item.sha256 || actualBytes !== item.bytes) {
          throw new Error(
            `Digest/size mismatch for ${item.name}: expected ${item.sha256} (${item.bytes}B), got ${actualSha} (${actualBytes}B)`,
          );
        }
        const recordedShaLine = fs
          .readFileSync(shaPath, 'utf8')
          .trim()
          .split(/\s+/)[0];
        if (recordedShaLine !== actualSha) {
          throw new Error(`.sha256 file mismatch for ${item.name}`);
        }
        verifyGpgSignature(keyringPath, sigPath, shaPath);

        filesToUpload.push(binPath, shaPath, sigPath);
        sha256Entries.push({ name: item.name, sha256: actualSha });
      }

      filesToUpload.push(
        selfHostedBinPath,
        selfHostedShaPath,
        selfHostedSigPath,
      );
      sha256Entries.push({ name: selfHostedName, sha256: selfHostedSha });

      const publicLinksJson = `${JSON.stringify(publicLinks, null, 2)}\n`;
      assertNoPrivateLeakInPublicMetadata(
        'download-links.json',
        publicLinksJson,
      );
      const outLinksPath = path.join(workDir, 'download-links.json');
      fs.writeFileSync(outLinksPath, publicLinksJson);

      const publicProvBytes = Buffer.from(
        canonicalJson(publicProvenance),
        'utf8',
      );
      assertNoPrivateLeakInPublicMetadata(provenanceName, publicProvBytes);
      if (
        stagingProvenance.source_sha !== stagingProvenance.builder_sha &&
        publicProvBytes.toString('utf8').includes(stagingProvenance.source_sha)
      ) {
        throw new Error('Public provenance leaked private source_sha');
      }
      const outProvPath = path.join(workDir, provenanceName);
      const outProvSigPath = path.join(workDir, `${provenanceName}.sig`);
      fs.writeFileSync(outProvPath, publicProvBytes);
      signDetachedWithGpg(signingConfig, outProvPath, outProvSigPath);
      verifyGpgSignature(keyringPath, outProvSigPath, outProvPath);

      sha256Entries.push({
        name: provenanceName,
        sha256: sha256Hex(publicProvBytes),
      });

      const sha256SumsContent = buildPublicSha256Sums(sha256Entries);
      assertNoPrivateLeakInPublicMetadata('SHA256SUMS', sha256SumsContent);
      const outSumsPath = path.join(workDir, 'SHA256SUMS');
      const outSumsSigPath = path.join(workDir, 'SHA256SUMS.sig');
      fs.writeFileSync(outSumsPath, sha256SumsContent);
      signDetachedWithGpg(signingConfig, outSumsPath, outSumsSigPath);
      verifyGpgSignature(keyringPath, outSumsSigPath, outSumsPath);

      filesToUpload.push(
        keyringPath,
        outLinksPath,
        outProvPath,
        outProvSigPath,
        outSumsPath,
        outSumsSigPath,
      );

      for (const filePath of filesToUpload) {
        const base = path.basename(filePath);
        if (FORBIDDEN_ASSET_PATTERNS.some((rx) => rx.test(base))) {
          throw new Error(`Refusing to upload forbidden private asset: ${base}`);
        }
      }

      let publicRelease;
      const existingRes = await fetch(
        `https://api.github.com/repos/${publicRepo}/releases/tags/${encodeURIComponent(tag)}`,
        {
          headers: {
            Accept: 'application/vnd.github+json',
            Authorization: `Bearer ${publicToken}`,
            'X-GitHub-Api-Version': '2022-11-28',
            'User-Agent': 'omniterm-release-promoter',
          },
        },
      );
      if (existingRes.status === 404) {
        const createRes = await githubRequest(
          `https://api.github.com/repos/${publicRepo}/releases`,
          publicToken,
          {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              tag_name: tag,
              name: `LeapTerm ${tag}`,
              body: `LeapTerm ${tag} public release.`,
              draft: true,
              prerelease: normalizedVersion.includes('-'),
            }),
          },
        );
        publicRelease = await createRes.json();
      } else if (existingRes.ok) {
        publicRelease = await existingRes.json();
        for (const existingAsset of publicRelease.assets || []) {
          await githubRequest(
            `https://api.github.com/repos/${publicRepo}/releases/assets/${existingAsset.id}`,
            publicToken,
            { method: 'DELETE' },
          );
        }
      } else {
        throw new Error(
          `Failed checking existing public release (${existingRes.status})`,
        );
      }

      const uploadBase = String(publicRelease.upload_url).replace(
        /\{\?.*$/,
        '',
      );
      for (const filePath of filesToUpload) {
        const fileName = path.basename(filePath);
        const data = fs.readFileSync(filePath);
        await githubRequest(
          `${uploadBase}?name=${encodeURIComponent(fileName)}`,
          publicToken,
          {
            method: 'POST',
            headers: {
              'Content-Type': 'application/octet-stream',
              'Content-Length': String(data.length),
            },
            body: data,
          },
        );
      }

      await githubRequest(
        `https://api.github.com/repos/${publicRepo}/releases/${publicRelease.id}`,
        publicToken,
        {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            draft: false,
            name: `LeapTerm ${tag}`,
            body: `LeapTerm ${tag} public release.`,
          }),
        },
      );

      console.log(
        `Promoted LeapTerm ${tag} (${filesToUpload.length} verified public assets) to ${publicRepo}.`,
      );
    }

    if (androidStoreAction && androidStoreAction !== 'none') {
      const aabName = assetsByName.has(`omniterm-${normalizedVersion}-android.aab`)
        ? `omniterm-${normalizedVersion}-android.aab`
        : `omniterm-${normalizedVersion}-android-release.aab`;
      const aabPath = await requireStagingAsset(aabName);
      const aabShaPath = await requireStagingAsset(`${aabName}.sha256`);
      const aabSigPath = await requireStagingAsset(`${aabName}.sha256.sig`);
      const actualAabSha = sha256Hex(fs.readFileSync(aabPath));
      const recordedAabSha = fs
        .readFileSync(aabShaPath, 'utf8')
        .trim()
        .split(/\s+/)[0];
      if (actualAabSha !== recordedAabSha) {
        throw new Error(`.sha256 mismatch for ${aabName}`);
      }
      verifyGpgSignature(keyringPath, aabSigPath, aabShaPath);

      const playResult = await promoteAndroidToPlayStore({
        version: normalizedVersion,
        buildNumber: resolvedBuildNumber,
        track: androidStoreAction,
        aabPath,
        serviceAccountJson: googlePlayServiceAccountJson,
      });
      console.log(
        `Promoted Android bundle ${aabName} to Google Play track "${playResult.track}".`,
      );
    }

    if (iosStoreAction && iosStoreAction !== 'none') {
      let ipaPath = '';
      if (iosStoreAction === 'testflight') {
        const ipaName = `omniterm-${normalizedVersion}-ios-private.ipa`;
        if (assetsByName.has(ipaName)) {
          ipaPath = await requireStagingAsset(ipaName);
        } else {
          const runId = String(stagingProvenance.run_id || '');
          const attempt = String(stagingProvenance.attempt || '');
          const proof = String(stagingProvenance.proof || '');
          const routeSuffix =
            stagingProvenance.release_route === 'option1' ? '/option1' : '';
          const prefix = `releases/v${normalizedVersion}/${resolvedBuildNumber}/${runId}-${attempt}${routeSuffix}`;
          const ipaKey = `${prefix}/private-artifacts/${ipaName}`;
          const receiptKey = `${prefix}/github-receipts/${proof}/ios-private-artifact-receipt.json`;
          const stageTag = `ci-stage/application-${runId}-${attempt}`;
          const stageReleasesRes = await githubRequest(
            `https://api.github.com/repos/${stagingRepo}/releases?per_page=100`,
            privateToken,
          );
          const stageReleases = await stageReleasesRes.json();
          const stageRelease = (stageReleases || []).find(
            (r) => r.tag_name === stageTag,
          );
          if (!stageRelease) {
            throw new Error(
              `Private stage release ${stageTag} not found on ${stagingRepo} for iOS IPA retrieval`,
            );
          }
          const stageAssets = new Map(
            (stageRelease.assets || []).map((a) => [a.name, a]),
          );
          const ipaObjName = `object-${sha256Hex(Buffer.from(ipaKey, 'utf8'))}.bin`;
          const receiptObjName = `object-${sha256Hex(Buffer.from(receiptKey, 'utf8'))}.bin`;
          const ipaAsset = stageAssets.get(ipaObjName);
          const receiptAsset = stageAssets.get(receiptObjName);
          if (!ipaAsset || !receiptAsset) {
            throw new Error(
              `Private stage release ${stageTag} missing signed iOS IPA (${ipaObjName}) or receipt (${receiptObjName})`,
            );
          }
          const receiptPath = path.join(workDir, 'ios-private-receipt.json');
          await downloadReleaseAsset(
            receiptAsset.url,
            privateToken,
            receiptPath,
          );
          const receiptEnvelope = JSON.parse(
            fs.readFileSync(receiptPath, 'utf8'),
          );
          const receipt = receiptEnvelope.receipt || receiptEnvelope;
          ipaPath = path.join(workDir, ipaName);
          await downloadReleaseAsset(ipaAsset.url, privateToken, ipaPath);
          const actualIpaSha = sha256Hex(fs.readFileSync(ipaPath));
          const actualIpaBytes = fs.statSync(ipaPath).size;
          if (
            actualIpaSha !== receipt.sha256 ||
            actualIpaBytes !== receipt.bytes
          ) {
            throw new Error(
              `Signed iOS IPA digest/size mismatch against private receipt`,
            );
          }
        }
      }
      const iosResult = await promoteIosToAppStoreConnect({
        version: normalizedVersion,
        buildNumber: resolvedBuildNumber,
        action: iosStoreAction,
        automaticRelease: iosAutomaticRelease,
        ipaPath,
        iosSigningConfigJson,
      });
      console.log(
        `Promoted iOS candidate v${normalizedVersion} (${resolvedBuildNumber}) via action "${iosResult.action}" (${iosResult.status}).`,
      );
    }

    if (macosStoreAction && macosStoreAction !== 'none') {
      let macosPackagePath = '';
      if (macosStoreAction === 'testflight') {
        const macosZipName = `omniterm-${normalizedVersion}-macos-arm64.zip`;
        macosPackagePath = await requireStagingAsset(macosZipName);
        const macosShaPath = await requireStagingAsset(`${macosZipName}.sha256`);
        const macosSigPath = await requireStagingAsset(
          `${macosZipName}.sha256.sig`,
        );
        const actualMacosSha = sha256Hex(fs.readFileSync(macosPackagePath));
        const recordedMacosSha = fs
          .readFileSync(macosShaPath, 'utf8')
          .trim()
          .split(/\s+/)[0];
        if (actualMacosSha !== recordedMacosSha) {
          throw new Error(`.sha256 mismatch for ${macosZipName}`);
        }
        verifyGpgSignature(keyringPath, macosSigPath, macosShaPath);
      }
      const macosResult = await promoteMacosToAppStoreConnect({
        version: normalizedVersion,
        buildNumber: resolvedBuildNumber,
        action: macosStoreAction,
        automaticRelease: macosAutomaticRelease,
        packagePath: macosPackagePath,
        macosSigningConfigJson: macosSigningConfigJson || iosSigningConfigJson,
      });
      console.log(
        `Promoted macOS candidate v${normalizedVersion} (${resolvedBuildNumber}) via action "${macosResult.action}" (${macosResult.status}).`,
      );
    }

    if (resolvedRolloutEnv !== 'none') {
      const rolloutResult = executeEnvironmentRollout({
        environment: resolvedRolloutEnv,
        version: normalizedVersion,
        buildNumber: resolvedBuildNumber,
        sourceSha: String(stagingProvenance.source_sha || ''),
        sourceRoot,
        stagingRepo,
        privateToken,
        githubToken,
        dockerHubUsername,
        dockerHubPatReadWrite,
        dockerHubPatReadOnly,
        containerRegistry,
        execFileImpl,
      });
      console.log(
        `Environment rollout (${rolloutResult.environment}) for v${normalizedVersion} (${resolvedBuildNumber}) image ${rolloutResult.container.image}: ${rolloutResult.status}.`,
      );
    }
  } finally {
    fs.rmSync(workDir, { recursive: true, force: true });
  }
}

if (
  process.argv[1] &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  promoteRelease({
    version: process.env.PROMOTE_VERSION,
    expectedBuildNumber: process.env.PROMOTE_BUILD_NUMBER || '',
    privateToken: process.env.PRIVATE_RELEASE_TOKEN,
    publicToken: process.env.GH_TOKEN,
    githubToken: process.env.GITHUB_TOKEN || '',
    dockerHubUsername: process.env.DOCKER_HUB_USERNAME || 'omniterm',
    dockerHubPatReadWrite: process.env.DOCKER_HUB_PAT_READ_WRITE || '',
    dockerHubPatReadOnly: process.env.DOCKER_HUB_PAT_READ_ONLY || '',
    signingConfigJson: process.env.PACKAGE_SIGNING_CONFIG,
    publishGithubRelease:
      String(process.env.PROMOTE_GITHUB_RELEASE ?? 'true') !== 'false',
    iosStoreAction: process.env.PROMOTE_IOS_STORE_ACTION || 'none',
    iosAutomaticRelease:
      String(process.env.PROMOTE_IOS_AUTOMATIC_RELEASE ?? 'false') === 'true',
    iosSigningConfigJson: process.env.IOS_SIGNING_CONFIG || '',
    macosStoreAction: process.env.PROMOTE_MACOS_STORE_ACTION || 'none',
    macosAutomaticRelease:
      String(process.env.PROMOTE_MACOS_AUTOMATIC_RELEASE ?? 'false') === 'true',
    macosSigningConfigJson: process.env.MACOS_SIGNING_CONFIG || '',
    androidStoreAction: process.env.PROMOTE_ANDROID_STORE_ACTION || 'none',
    googlePlayServiceAccountJson:
      process.env.GOOGLE_PLAY_SERVICE_ACCOUNT_JSON || '',
    rolloutEnvironment: process.env.PROMOTE_ROLLOUT_ENVIRONMENT || 'auto',
    containerRegistry:
      process.env.PROMOTE_CONTAINER_REGISTRY || PRIMARY_CONTAINER_REGISTRY,
    sourceRoot: process.env.PROMOTE_SOURCE_ROOT || '',
    verifyStoreCredentialsOnly:
      String(process.env.VERIFY_STORE_CREDENTIALS_ONLY ?? 'false') === 'true',
  }).catch((err) => {
    console.error(err instanceof Error ? err.message : String(err));
    process.exit(1);
  });
}
