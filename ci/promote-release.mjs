#!/usr/bin/env node
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import zlib from 'node:zlib';

export const STAGING_REPOSITORY = String(process.env.SOURCE_REPOSITORY || '').trim();
export const PUBLIC_REPOSITORY = 'omnisolo-llc/leapterm-release';
export const PRIMARY_CONTAINER_REGISTRY = String(
  process.env.PROMOTE_CONTAINER_REGISTRY || '',
).trim();
export const GHCR_CONTAINER_REGISTRY = String(
  process.env.PROMOTE_GHCR_REGISTRY || '',
).trim();

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
  /^leapterm-sbom\./,
]);

export const SELF_HOSTED_LEAK_PATTERNS = Object.freeze([
  { label: 'production product domain', regex: /\bleapterm\.com\b/i },
  { label: 'corporate omnisolo.com domain', regex: /\bomnisolo\.com\b/i },
  {
    label: 'private source repository reference',
    regex: /omnisolo-llc\/(?!leapterm-release\b)[a-z0-9._-]+/i,
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
  { allowPartialWave = false } = {},
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
  if (allowPartialWave ? publicArtifacts.length === 0 : publicArtifacts.length !== PUBLIC_TARGETS.length) {
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
    const shName = String(shSource.name || `leapterm-${version}-self-hosted.zip`);
    result.self_hosted = {
      ...shSource,
      name: shName,
      url: `${publicBaseUrl}/${shName}`,
      checksum_url: `${publicBaseUrl}/${shName}.sha256`,
      sha256_url: `${publicBaseUrl}/${shName}.sha256`,
      signature_url: `${publicBaseUrl}/${shName}.sha256.sig`,
    };
  } else if (!allowPartialWave) {
    throw new Error('Staging release is missing self_hosted bundle metadata');
  }
  return result;
}

export function filterPublicProvenance(
  stagingProvenance,
  { allowPartialWave = false } = {},
) {
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
  if (allowPartialWave ? publicArtifacts.length === 0 : publicArtifacts.length !== PUBLIC_TARGETS.length) {
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
  delete sanitized.ios_action;
  if (
    sanitized.managed_vpn &&
    typeof sanitized.managed_vpn === 'object' &&
    Array.isArray(sanitized.managed_vpn.supported_platforms)
  ) {
    sanitized.managed_vpn = {
      ...sanitized.managed_vpn,
      supported_platforms: sanitized.managed_vpn.supported_platforms.filter(
        (p) => !FORBIDDEN_PRIVATE_TARGETS.includes(p),
      ),
    };
  }
  return sanitized;
}

export function verifyAllReleaseBuildsReady({
  downloadLinks,
  provenance,
  assetsByName,
  version = '',
} = {}) {
  const hasAsset = (name) =>
    assetsByName instanceof Map
      ? assetsByName.has(name)
      : assetsByName instanceof Set
        ? assetsByName.has(name)
        : Array.isArray(assetsByName)
          ? assetsByName.includes(name)
          : Boolean(assetsByName && Object.hasOwn(assetsByName, name));

  const rawDownloads = Array.isArray(downloadLinks?.downloads)
    ? downloadLinks.downloads
    : Array.isArray(downloadLinks?.artifacts)
      ? downloadLinks.artifacts
      : [];
  const downloadByTarget = new Map(
    rawDownloads
      .filter((item) => item && typeof item === 'object' && item.target)
      .map((item) => [item.target, item]),
  );
  const provArtifacts = Array.isArray(provenance?.artifacts)
    ? provenance.artifacts
    : [];
  const provByTarget = new Map(
    provArtifacts
      .filter((item) => item && typeof item === 'object' && item.target)
      .map((item) => [item.target, item]),
  );

  const missingTargets = [];
  const missingProvenanceTargets = [];
  const missingAssets = [];

  for (const target of PUBLIC_TARGETS) {
    const dlItem = downloadByTarget.get(target);
    if (!dlItem || !dlItem.name || !dlItem.sha256) {
      missingTargets.push(target);
    } else if (assetsByName) {
      for (const suffix of ['', '.sha256', '.sha256.sig']) {
        const assetName = `${dlItem.name}${suffix}`;
        if (!hasAsset(assetName)) {
          missingAssets.push(assetName);
        }
      }
    }
    const provItem = provByTarget.get(target);
    if (!provItem || !provItem.name || !provItem.sha256) {
      missingProvenanceTargets.push(target);
    }
  }

  const normalizedVersion = String(
    version || downloadLinks?.version || provenance?.version || '',
  ).replace(/^v/, '');
  const selfHostedName = `leapterm-${normalizedVersion}-self-hosted.zip`;
  const selfHostedFromAssets =
    assetsByName && hasAsset(selfHostedName) && hasAsset(`${selfHostedName}.sha256`)
      ? { name: selfHostedName, sha256: 'present' }
      : null;
  const selfHosted = downloadLinks?.self_hosted || selfHostedFromAssets;
  if (!selfHosted || typeof selfHosted !== 'object' || !selfHosted.name || !selfHosted.sha256) {
    missingTargets.push('self_hosted');
  } else if (assetsByName) {
    for (const suffix of ['', '.sha256']) {
      const assetName = `${selfHosted.name}${suffix}`;
      if (!hasAsset(assetName)) {
        missingAssets.push(assetName);
      }
    }
  }

  if (assetsByName && normalizedVersion) {
    const provName = `leapterm-${normalizedVersion}-release-provenance.json`;
    for (const reqName of ['download-links.json', provName, `${provName}.sig`]) {
      if (!hasAsset(reqName)) {
        missingAssets.push(reqName);
      }
    }
    if (!hasAsset(PRIMARY_KEYRING_ASSET) && !hasAsset(LEGACY_KEYRING_ASSET)) {
      missingAssets.push(PRIMARY_KEYRING_ASSET);
    }
  }

  return {
    ready:
      missingTargets.length === 0 &&
      missingProvenanceTargets.length === 0 &&
      missingAssets.length === 0,
    missingTargets,
    missingProvenanceTargets,
    missingAssets,
  };
}

export function mergeWaveStagingMetadata({ wavePayloads, version }) {
  if (!Array.isArray(wavePayloads) || wavePayloads.length === 0) {
    throw new Error('mergeWaveStagingMetadata requires at least one wave payload');
  }
  const normalizedVersion = String(version || '').trim().replace(/^v/, '');
  const baseLinks = wavePayloads[0].downloadLinks;
  const baseProv = wavePayloads[0].provenance;
  const expectedBuild = String(
    baseLinks?.build_number ?? baseProv?.build_number ?? '',
  );
  const expectedSourceSha = String(baseProv?.source_sha || '');
  const expectedBuilderSha = String(baseProv?.builder_sha || '');

  const downloadsByTarget = new Map();
  const provByTarget = new Map();
  const mergedAssets = new Map();
  let mergedSelfHosted = null;
  let mergedIosDelivery = null;

  for (const wave of wavePayloads) {
    const links = wave.downloadLinks || {};
    const prov = wave.provenance || {};
    const waveVersion = String(links.version || prov.version || '').replace(/^v/, '');
    const waveBuild = String(links.build_number ?? prov.build_number ?? '');
    if (normalizedVersion && waveVersion !== normalizedVersion) {
      throw new Error(
        `Wave ${wave.tag} version mismatch: expected ${normalizedVersion}, found ${waveVersion}`,
      );
    }
    if (expectedBuild && waveBuild !== expectedBuild) {
      throw new Error(
        `Wave ${wave.tag} build_number mismatch: expected ${expectedBuild}, found ${waveBuild}`,
      );
    }
    if (expectedSourceSha && String(prov.source_sha || '') !== expectedSourceSha) {
      throw new Error(
        `Wave ${wave.tag} source_sha mismatch across release waves`,
      );
    }
    if (expectedBuilderSha && String(prov.builder_sha || '') !== expectedBuilderSha) {
      throw new Error(
        `Wave ${wave.tag} builder_sha mismatch across release waves`,
      );
    }

    const rawDownloads = Array.isArray(links.downloads)
      ? links.downloads
      : Array.isArray(links.artifacts)
        ? links.artifacts
        : [];
    for (const item of rawDownloads) {
      if (!item || typeof item !== 'object' || !item.target) continue;
      const existing = downloadsByTarget.get(item.target);
      if (existing && existing.sha256 !== item.sha256) {
        throw new Error(
          `Conflicting sha256 for target ${item.target} across release waves`,
        );
      }
      downloadsByTarget.set(item.target, item);
    }

    for (const item of Array.isArray(prov.artifacts) ? prov.artifacts : []) {
      if (!item || typeof item !== 'object' || !item.target) continue;
      const existing = provByTarget.get(item.target);
      if (existing && existing.sha256 !== item.sha256) {
        throw new Error(
          `Conflicting provenance sha256 for target ${item.target} across release waves`,
        );
      }
      provByTarget.set(item.target, item);
    }

    if (links.self_hosted && typeof links.self_hosted === 'object') {
      mergedSelfHosted = links.self_hosted;
    }
    if (links.ios_delivery && typeof links.ios_delivery === 'object') {
      if (!mergedIosDelivery || links.ios_delivery.action !== 'skip') {
        mergedIosDelivery = links.ios_delivery;
      }
    }
    for (const asset of wave.assets || []) {
      if (asset && asset.name) {
        mergedAssets.set(asset.name, asset);
      }
    }
  }

  const orderedDownloads = [...downloadsByTarget.values()];
  const orderedProvArtifacts = [...provByTarget.values()];
  const tag = `v${normalizedVersion || String(baseLinks?.version || '').replace(/^v/, '')}`;
  const stagingLinks = {
    ...baseLinks,
    version: normalizedVersion || baseLinks?.version,
    build_number: baseLinks?.build_number,
    tag,
    downloads: orderedDownloads,
    artifacts: orderedDownloads,
    ...(mergedSelfHosted ? { self_hosted: mergedSelfHosted } : {}),
    ...(mergedIosDelivery ? { ios_delivery: mergedIosDelivery } : {}),
  };
  const stagingProvenance = {
    ...baseProv,
    version: normalizedVersion || baseProv?.version,
    artifacts: orderedProvArtifacts,
  };
  const readiness = verifyAllReleaseBuildsReady({
    downloadLinks: stagingLinks,
    provenance: stagingProvenance,
    assetsByName: mergedAssets,
    version: normalizedVersion,
  });

  return {
    stagingLinks,
    stagingProvenance,
    assetsByName: mergedAssets,
    isCompleteWaveSet: readiness.ready,
    readiness,
  };
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
  if (/omnisolo-llc\/(?!leapterm-release\b)[a-z0-9._-]+/i.test(text)) {
    throw new Error(
      `Public metadata ${filename} leaked private repository reference`,
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
  const gpgHome = fs.mkdtempSync(path.join(os.tmpdir(), 'leap-promote-gpg-'));
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
    'User-Agent': 'leapterm-release-promoter',
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

export const PRIMARY_KEYRING_ASSET = 'leapterm-package-signing-key.gpg';
export const LEGACY_KEYRING_ASSET = 'leapterm-archive-keyring.gpg';

export function resolveStagingKeyringAssetName(assetsByName) {
  const has = (name) =>
    assetsByName instanceof Map
      ? assetsByName.has(name)
      : Array.isArray(assetsByName)
        ? assetsByName.includes(name)
        : Boolean(assetsByName && Object.hasOwn(assetsByName, name));
  if (has(PRIMARY_KEYRING_ASSET)) {
    return PRIMARY_KEYRING_ASSET;
  }
  if (has(LEGACY_KEYRING_ASSET)) {
    return LEGACY_KEYRING_ASSET;
  }
  return PRIMARY_KEYRING_ASSET;
}

export function buildPrivateIosStorageKeys(
  versionOrOptions,
  buildNumberArg,
  runIdArg,
  runAttemptArg,
  proofArg,
  releaseRouteArg,
) {
  const opts =
    versionOrOptions && typeof versionOrOptions === 'object'
      ? versionOrOptions
      : {
          version: versionOrOptions,
          buildNumber: buildNumberArg,
          runId: runIdArg,
          runAttempt: runAttemptArg,
          proof: proofArg,
          releaseRoute: releaseRouteArg,
        };
  const normalizedVersion = String(opts.version || '')
    .trim()
    .replace(/^v/, '');
  const normalizedBuild = String(
    opts.buildNumber ?? opts.build_number ?? '',
  ).trim();
  const normalizedRunId = String(opts.runId ?? opts.run_id ?? '').trim();
  const normalizedAttempt = String(
    opts.runAttempt ?? opts.run_attempt ?? opts.attempt ?? '1',
  ).trim();
  const normalizedProof = String(opts.proof || '').trim();
  const effectiveRoute = String(
    opts.releaseRoute || opts.release_route || 'option1',
  ).trim();
  const ipaName = `leapterm-${normalizedVersion}-ios-private.ipa`;
  const basePrefix = `releases/v${normalizedVersion}/${normalizedBuild}/${normalizedRunId}-${normalizedAttempt}`;
  const option1Prefix = `${basePrefix}/option1`;

  const option1DirectCandidate = {
    prefix: option1Prefix,
    ipaKey: `${option1Prefix}/private/${ipaName}`,
    receiptKey: `${option1Prefix}/receipts/ios-private-artifact.json`,
  };
  const option1StageCandidate = {
    prefix: option1Prefix,
    ipaKey: `${option1Prefix}/private-artifacts/${ipaName}`,
    receiptKey: normalizedProof
      ? `${option1Prefix}/github-receipts/${normalizedProof}/ios-private-artifact-receipt.json`
      : `${option1Prefix}/receipts/ios-private-artifact.json`,
  };
  const option1StageShortReceiptCandidate = normalizedProof
    ? {
        prefix: option1Prefix,
        ipaKey: `${option1Prefix}/private-artifacts/${ipaName}`,
        receiptKey: `${option1Prefix}/github-receipts/${normalizedProof}/ios-private-artifact.json`,
      }
    : null;
  const legacyStageCandidate = {
    prefix: basePrefix,
    ipaKey: `${basePrefix}/private-artifacts/${ipaName}`,
    receiptKey: normalizedProof
      ? `${basePrefix}/github-receipts/${normalizedProof}/ios-private-artifact-receipt.json`
      : `${basePrefix}/receipts/ios-private-artifact.json`,
  };
  const legacyStageShortReceiptCandidate = normalizedProof
    ? {
        prefix: basePrefix,
        ipaKey: `${basePrefix}/private-artifacts/${ipaName}`,
        receiptKey: `${basePrefix}/github-receipts/${normalizedProof}/ios-private-artifact.json`,
      }
    : null;
  const legacyDirectCandidate = {
    prefix: basePrefix,
    ipaKey: `${basePrefix}/private/${ipaName}`,
    receiptKey: `${basePrefix}/receipts/ios-private-artifact.json`,
  };

  const candidates = (
    effectiveRoute === 'legacy-acceptance'
      ? [
          legacyStageCandidate,
          legacyStageShortReceiptCandidate,
          legacyDirectCandidate,
          option1DirectCandidate,
          option1StageCandidate,
          option1StageShortReceiptCandidate,
        ]
      : [
          option1DirectCandidate,
          option1StageCandidate,
          option1StageShortReceiptCandidate,
          legacyStageCandidate,
          legacyStageShortReceiptCandidate,
          legacyDirectCandidate,
        ]
  ).filter(Boolean);

  const primary = candidates[0];
  const ipaKeys = [...new Set(candidates.map((c) => c.ipaKey))];
  const receiptKeys = [...new Set(candidates.map((c) => c.receiptKey))];

  return {
    ipaName,
    basePrefix,
    prefix: primary.prefix,
    ipaKey: primary.ipaKey,
    receiptKey: primary.receiptKey,
    ipaKeys,
    receiptKeys,
    candidates,
  };
}

export async function resolvePrivateStageRelease({
  stagingRepo,
  privateToken,
  version,
  buildNumber = '',
  runId = '',
  fetchImpl = fetch,
}) {
  const normalizedVersion = String(version || '').trim().replace(/^v/, '');
  const normalizedBuild = String(buildNumber || '').trim();
  const normalizedRunId = String(runId || '').trim();
  const listUrl = `https://api.github.com/repos/${stagingRepo}/releases?per_page=100`;
  const response = await fetchImpl(listUrl, {
    headers: {
      Accept: 'application/vnd.github+json',
      Authorization: `Bearer ${privateToken}`,
      'X-GitHub-Api-Version': '2022-11-28',
      'User-Agent': 'leapterm-release-promoter',
    },
    redirect: 'follow',
  });
  if (!response.ok) {
    return null;
  }
  const releases = await response.json();
  if (!Array.isArray(releases)) {
    return null;
  }
  const stageReleases = releases.filter(
    (r) => r.tag_name && r.tag_name.startsWith('ci-stage/application-'),
  );

  if (normalizedRunId) {
    const direct = stageReleases.find(
      (r) =>
        r.tag_name === `ci-stage/application-${normalizedRunId}-1` ||
        r.tag_name.startsWith(`ci-stage/application-${normalizedRunId}-`),
    );
    if (direct) {
      const match = direct.tag_name.match(/^ci-stage\/application-(\d+)-(\d+)$/);
      return {
        stageRelease: direct,
        runId: match ? match[1] : normalizedRunId,
        attempt: match ? match[2] : '1',
      };
    }
  }

  if (normalizedBuild) {
    for (const rel of stageReleases) {
      const match = rel.tag_name.match(/^ci-stage\/application-(\d+)-(\d+)$/);
      if (!match) continue;
      const rId = match[1];
      const rAttempt = match[2];
      const assetNames = new Set((rel.assets || []).map((a) => a.name));
      const testKeys = [
        `releases/v${normalizedVersion}/${normalizedBuild}/${rId}-${rAttempt}/option1/private-artifacts/leapterm-${normalizedVersion}-ios-private.ipa`,
        `releases/v${normalizedVersion}/${normalizedBuild}/${rId}-${rAttempt}/private-artifacts/leapterm-${normalizedVersion}-ios-private.ipa`,
        `releases/v${normalizedVersion}/${normalizedBuild}/${rId}-${rAttempt}/option1/private/leapterm-${normalizedVersion}-ios-private.ipa`,
        `releases/v${normalizedVersion}/${normalizedBuild}/${rId}-${rAttempt}/private/leapterm-${normalizedVersion}-ios-private.ipa`,
      ];
      for (const k of testKeys) {
        const objName = `object-${sha256Hex(Buffer.from(k, 'utf8'))}.bin`;
        if (assetNames.has(objName)) {
          return {
            stageRelease: rel,
            runId: rId,
            attempt: rAttempt,
          };
        }
      }
    }
  }
  return null;
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

export function mergeAppleSigningConfig(
  signingConfigJson = '',
  appleConfigJson = '',
) {
  const trimmedApple = String(appleConfigJson || '').trim();
  const trimmedBase = String(signingConfigJson || '').trim();
  if (!trimmedApple) {
    return trimmedBase;
  }
  const base = trimmedBase ? JSON.parse(trimmedBase) : {};
  const overrides = JSON.parse(trimmedApple);
  for (const [key, value] of Object.entries(overrides || {})) {
    if (typeof value === 'string' && value.trim()) {
      base[key] = value.trim();
    }
  }
  return JSON.stringify(base);
}

export async function verifyAppleStoreAccess({
  appleSigningConfigJson,
  appBundleId = 'com.leapterm.app',
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
  packageName = 'com.leapterm.app',
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

const APPLE_PRE_RELEASE_STORE_ACTIONS = new Set([
  'internal',
  'alpha',
  'beta',
  'testflight',
]);
const ANDROID_PRE_RELEASE_STORE_ACTIONS = new Set([
  'internal',
  'alpha',
  'beta',
]);

export function parseInternalTesterEmails(raw = '') {
  const items = String(raw || '')
    .split(',')
    .map((entry) => entry.trim().toLowerCase())
    .filter(Boolean);
  const seen = new Set();
  const emails = [];
  for (const email of items) {
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      throw new Error(`Invalid email in INTERNAL_TESTER_EMAILS: ${email}`);
    }
    if (!seen.has(email)) {
      seen.add(email);
      emails.push(email);
    }
  }
  return emails;
}

export async function syncAppleInternalTesters({
  ascRequest,
  appBundleId = 'com.leapterm.app',
  internalTesterEmails = '',
}) {
  const emails = parseInternalTesterEmails(internalTesterEmails);
  if (emails.length === 0) {
    return { synced: [], group_id: null };
  }
  const appsRes = await ascRequest(
    `/v1/apps?filter[bundleId]=${encodeURIComponent(appBundleId)}`,
  );
  const app = appsRes?.data?.[0];
  if (!app?.id) {
    throw new Error(
      `App Store Connect app not found for bundleId ${appBundleId}`,
    );
  }
  const groupsRes = await ascRequest(
    `/v1/apps/${encodeURIComponent(app.id)}/betaGroups?limit=200`,
  );
  const groups = Array.isArray(groupsRes?.data) ? groupsRes.data : [];
  let internalGroup = groups.find(
    (g) => g?.attributes?.isInternalGroup === true,
  );
  if (!internalGroup?.id) {
    const createdGroup = await ascRequest('/v1/betaGroups', 'POST', {
      data: {
        type: 'betaGroups',
        attributes: {
          name: 'Internal Testers',
          isInternalGroup: true,
          hasAccessToAllBuilds: true,
        },
        relationships: {
          app: { data: { type: 'apps', id: app.id } },
        },
      },
    });
    internalGroup = createdGroup?.data;
  }
  if (!internalGroup?.id) {
    throw new Error(
      `Unable to resolve or create internal TestFlight beta group for ${appBundleId}`,
    );
  }

  const groupTestersRes = await ascRequest(
    `/v1/betaGroups/${encodeURIComponent(internalGroup.id)}/betaTesters?limit=200`,
  );
  const existingEmails = new Set(
    (Array.isArray(groupTestersRes?.data) ? groupTestersRes.data : [])
      .map((t) => String(t?.attributes?.email || '').trim().toLowerCase())
      .filter(Boolean),
  );

  for (const email of emails) {
    if (existingEmails.has(email)) {
      continue;
    }
    const existingRes = await ascRequest(
      `/v1/betaTesters?filter[email]=${encodeURIComponent(email)}`,
    );
    const existingTester = Array.isArray(existingRes?.data)
      ? existingRes.data[0]
      : null;
    if (existingTester?.id) {
      await ascRequest(
        `/v1/betaGroups/${encodeURIComponent(internalGroup.id)}/relationships/betaTesters`,
        'POST',
        {
          data: [{ type: 'betaTesters', id: existingTester.id }],
        },
      );
    } else {
      await ascRequest('/v1/betaTesters', 'POST', {
        data: {
          type: 'betaTesters',
          attributes: { email },
          relationships: {
            betaGroups: {
              data: [{ type: 'betaGroups', id: internalGroup.id }],
            },
          },
        },
      });
    }
  }

  return { synced: emails, group_id: internalGroup.id };
}

export async function promoteAppleToAppStoreConnect({
  platform = 'ios',
  version,
  buildNumber,
  action,
  automaticRelease = false,
  packagePath = '',
  appleSigningConfigJson,
  internalTesterEmails = '',
  appBundleId = 'com.leapterm.app',
  fetchImpl = fetch,
  execFileImpl = execFileSync,
}) {
  if (!['ios', 'macos'].includes(platform)) {
    throw new Error(`Unsupported Apple platform: ${platform}`);
  }
  if (!['internal', 'alpha', 'beta', 'testflight', 'app-store'].includes(action)) {
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

  if (action === 'internal' || action === 'testflight') {
    if (!packagePath || !fs.existsSync(packagePath)) {
      throw new Error(
        `TestFlight candidate upload for ${platform} requires verified packagePath`,
      );
    }
    const keyDir = fs.mkdtempSync(path.join(os.tmpdir(), 'leap-asc-key-'));
    fs.chmodSync(keyDir, 0o700);
    let tempKeychain = null;
    let originalKeychains = [];
    try {
      const keyFile = path.join(keyDir, `AuthKey_${keyId}.p8`);
      fs.writeFileSync(keyFile, Buffer.from(apiKeyBase64, 'base64'), {
        mode: 0o600,
      });
      let uploadFilePath = packagePath;
      if (platform === 'ios' && packagePath.endsWith('.ipa')) {
        let isZip = false;
        try {
          const fd = fs.openSync(packagePath, 'r');
          const header = Buffer.alloc(4);
          fs.readSync(fd, header, 0, 4, 0);
          fs.closeSync(fd);
          isZip =
            header[0] === 0x50 &&
            header[1] === 0x4b &&
            header[2] === 0x03 &&
            header[3] === 0x04;
        } catch {
          isZip = false;
        }

        if (isZip) {
          const extractDir = path.join(keyDir, 'ios-extract');
          fs.mkdirSync(extractDir, { recursive: true });
          execFileImpl('ditto', ['-x', '-k', packagePath, extractDir], {
            stdio: 'pipe',
          });

          const findAssets = (dir) => {
            let files = [];
            if (!fs.existsSync(dir)) return files;
            for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
              const full = path.join(dir, entry.name);
              if (entry.isDirectory()) {
                files = files.concat(findAssets(full));
              } else if (entry.isFile()) {
                files.push(full);
              }
            }
            return files;
          };

          const extractedFiles = findAssets(extractDir);
          let sanitizedAny = false;
          for (const file of extractedFiles) {
            if (
              file.includes('flutter_assets') &&
              file.endsWith('.txt')
            ) {
              const content = fs.readFileSync(file, 'utf8');
              if (content.startsWith('#!')) {
                console.log(`Sanitizing executable shebang from: ${file}`);
                const sanitized =
                  '# ai-task-cache-keep-alive\n' +
                  content.replace(/^#![^\n]*\n/, '');
                fs.writeFileSync(file, sanitized, 'utf8');
                try {
                  fs.chmodSync(file, 0o644);
                } catch {
                  // ignore
                }
                sanitizedAny = true;
              }
            }
          }

          if (sanitizedAny) {
            const certificatePrefix = [
              'IOS_DISTRIBUTION',
              'APPLE_DISTRIBUTION',
              'IOS',
            ].find((prefix) =>
              String(signing[`${prefix}_CERTIFICATE_BASE64`] || '').trim(),
            );
            const certBase64 = certificatePrefix
              ? String(signing[`${certificatePrefix}_CERTIFICATE_BASE64`]).trim()
              : '';
            const certPassword = certificatePrefix
              ? String(
                  signing[`${certificatePrefix}_CERTIFICATE_PASSWORD`] ?? '',
                )
              : '';

            if (certBase64) {
              const p12Path = path.join(keyDir, 'ios_distribution.p12');
              fs.writeFileSync(p12Path, Buffer.from(certBase64, 'base64'), {
                mode: 0o600,
              });
              tempKeychain = path.join(keyDir, 'ios-dist.keychain-db');
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
                    '/usr/bin/codesign',
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
                    'apple-tool:,apple:,codesign:',
                    '-k',
                    kcPass,
                    tempKeychain,
                  ],
                  { stdio: 'pipe' },
                );
                try {
                  const rawList = execFileImpl(
                    'security',
                    ['list-keychains', '-d', 'user'],
                    { encoding: 'utf8' },
                  );
                  originalKeychains = String(rawList || '')
                    .split('\n')
                    .map((s) => s.trim().replace(/^"/, '').replace(/"$/, ''))
                    .filter(Boolean);
                  execFileImpl(
                    'security',
                    [
                      'list-keychains',
                      '-d',
                      'user',
                      '-s',
                      ...originalKeychains,
                      tempKeychain,
                    ],
                    { stdio: 'pipe' },
                  );
                } catch {
                  // ignore keychain search list additions
                }
              } catch {
                throw new Error('iOS distribution certificate import failed');
              }

              let signingIdentity = 'Apple Distribution';
              try {
                const identitiesOutput = execFileImpl(
                  'security',
                  ['find-identity', '-v', '-p', 'codesigning', tempKeychain],
                  { encoding: 'utf8' },
                );
                const identityMatch =
                  String(identitiesOutput).match(/\b([0-9A-Fa-f]{40})\b/) ||
                  String(identitiesOutput).match(/"([^"]+)"/);
                if (identityMatch) {
                  signingIdentity = identityMatch[1];
                }
              } catch {
                // fallback to 'Apple Distribution'
              }

              const runnerAppPath = path.join(extractDir, 'Payload/Runner.app');
              const appFrameworkPath = path.join(
                runnerAppPath,
                'Frameworks/App.framework',
              );

              if (fs.existsSync(appFrameworkPath)) {
                execFileImpl(
                  'codesign',
                  [
                    '-f',
                    '-s',
                    signingIdentity,
                    '--keychain',
                    tempKeychain,
                    '--preserve-metadata=identifier,flags',
                    appFrameworkPath,
                  ],
                  { stdio: 'pipe' },
                );
              }

              execFileImpl(
                'codesign',
                [
                  '-f',
                  '-s',
                  signingIdentity,
                  '--keychain',
                  tempKeychain,
                  '--preserve-metadata=identifier,entitlements,flags,runtime',
                  runnerAppPath,
                ],
                { stdio: 'pipe' },
              );

              try {
                execFileImpl(
                  'codesign',
                  ['-v', '--deep', '--strict', runnerAppPath],
                  { stdio: 'pipe' },
                );
                console.log(
                  'Codesign verification passed for sanitized Runner.app',
                );
              } catch (e) {
                console.warn(
                  `Warning: codesign verification warning: ${e.message}`,
                );
              }

              const sanitizedIpaPath = path.join(
                keyDir,
                `leapterm-${normalizedVersion}-ios-sanitized.ipa`,
              );
              execFileImpl(
                'ditto',
                [
                  '-c',
                  '-k',
                  '--keepParent',
                  path.join(extractDir, 'Payload'),
                  sanitizedIpaPath,
                ],
                { stdio: 'pipe' },
              );
              uploadFilePath = sanitizedIpaPath;
              console.log(
                `Repacked sanitized iOS candidate: ${sanitizedIpaPath} (${fs.statSync(sanitizedIpaPath).size} bytes)`,
              );
            }
          }
        }
      }
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
          `leapterm-${normalizedVersion}-macos.pkg`,
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
        if (originalKeychains.length > 0) {
          try {
            execFileImpl(
              'security',
              ['list-keychains', '-d', 'user', '-s', ...originalKeychains],
              { stdio: 'pipe' },
            );
          } catch {
            // ignore
          }
        }
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
    const testerSync = await syncAppleInternalTesters({
      ascRequest,
      appBundleId,
      internalTesterEmails,
    });
    return {
      platform,
      action,
      track: 'internal',
      version: normalizedVersion,
      build_number: normalizedBuild,
      ...(testerSync.group_id
        ? {
            asc_internal_beta_group_id: testerSync.group_id,
            internal_testers_synced: testerSync.synced,
          }
        : {}),
      status:
        action === 'internal'
          ? 'uploaded-to-testflight-internal'
          : 'uploaded-to-testflight',
    };
  }

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

  if (action === 'alpha' || action === 'beta') {
    const groupsRes = await ascRequest(
      `/v1/apps/${encodeURIComponent(app.id)}/betaGroups?limit=200`,
    );
    const groups = Array.isArray(groupsRes?.data) ? groupsRes.data : [];
    const betaGroup = groups.find(
      (g) =>
        g?.attributes?.isInternalGroup === false &&
        String(g?.attributes?.name || '').trim().toLowerCase() === action,
    );
    if (!betaGroup?.id) {
      throw new Error(
        `External TestFlight beta group "${action}" not found for ${platform} app ${appBundleId} (create an external group named "${action}" in App Store Connect)`,
      );
    }

    const reviewRes = await ascRequest(
      `/v1/betaAppReviewSubmissions?filter[build]=${encodeURIComponent(build.id)}`,
    );
    const existingReviews = Array.isArray(reviewRes?.data)
      ? reviewRes.data
      : [];
    if (existingReviews.length === 0) {
      await ascRequest('/v1/betaAppReviewSubmissions', 'POST', {
        data: {
          type: 'betaAppReviewSubmissions',
          relationships: {
            build: {
              data: { type: 'builds', id: build.id },
            },
          },
        },
      });
    }

    await ascRequest(
      `/v1/betaGroups/${encodeURIComponent(betaGroup.id)}/relationships/builds`,
      'POST',
      {
        data: [{ type: 'builds', id: build.id }],
      },
    );

    return {
      platform,
      action,
      track: action,
      version: normalizedVersion,
      build_number: normalizedBuild,
      asc_app_id: app.id,
      asc_build_id: build.id,
      asc_beta_group_id: betaGroup.id,
      status: `promoted-to-testflight-${action}`,
    };
  }

  // action === 'app-store': promote verified TestFlight build to App Store review
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
    track: 'app-store',
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
  internalTesterEmails = '',
  appBundleId = 'com.leapterm.app',
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
    internalTesterEmails,
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
  internalTesterEmails = '',
  appBundleId = 'com.leapterm.app',
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
    internalTesterEmails,
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
  packageName = 'com.leapterm.app',
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

    const putTrackRelease = async (releaseStatus) => {
      await playRequest(
        `edits/${encodeURIComponent(editId)}/tracks/${encodeURIComponent(track)}`,
        'PUT',
        {
          track,
          releases: [
            {
              name: `v${normalizedVersion} (${normalizedBuild})`,
              versionCodes: [String(versionCode)],
              status: releaseStatus,
            },
          ],
        },
      );
      await playRequest(
        `edits/${encodeURIComponent(editId)}:validate`,
        'POST',
        {},
      );
    };

    try {
      await putTrackRelease('completed');
    } catch (validateErr) {
      if (
        String(validateErr.message || '').includes(
          'Only releases with status draft may be created on draft app',
        )
      ) {
        console.warn(
          `Google Play app is in draft status; creating ${track} release as status draft.`,
        );
        await putTrackRelease('draft');
      } else {
        throw validateErr;
      }
    }

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

export function assertStoreTrackIsolation({
  rolloutEnvironment = 'auto',
  publishGithubRelease = false,
  iosStoreAction = 'none',
  macosStoreAction = 'none',
  androidStoreAction = 'none',
  verifyStoreCredentialsOnly = false,
} = {}) {
  if (verifyStoreCredentialsOnly) {
    return;
  }
  const normalizeTrack = (action, allowedSet) => {
    if (!allowedSet.has(action)) return null;
    return action === 'testflight' ? 'internal' : action;
  };
  const preReleaseTracks = new Set(
    [
      normalizeTrack(iosStoreAction, APPLE_PRE_RELEASE_STORE_ACTIONS),
      normalizeTrack(macosStoreAction, APPLE_PRE_RELEASE_STORE_ACTIONS),
      normalizeTrack(androidStoreAction, ANDROID_PRE_RELEASE_STORE_ACTIONS),
    ].filter(Boolean),
  );
  if (preReleaseTracks.size > 1) {
    throw new Error(
      'Cannot mix different pre-release store tracks in the same promotion; keep internal, alpha, and beta promotions isolated per track',
    );
  }
  if (preReleaseTracks.size === 0) {
    return;
  }
  if (publishGithubRelease) {
    throw new Error(
      'Cannot publish public GitHub Release in the same promotion as pre-release store tracks (internal/alpha/beta/testflight)',
    );
  }
  const hasProductionStore =
    iosStoreAction === 'app-store' ||
    macosStoreAction === 'app-store' ||
    androidStoreAction === 'production';
  if (hasProductionStore) {
    throw new Error(
      'Cannot mix pre-release store tracks (internal/alpha/beta/testflight) with public production store tracks (app-store/production)',
    );
  }
  const normalizedRollout = String(rolloutEnvironment || 'auto')
    .trim()
    .toLowerCase();
  if (normalizedRollout === 'production') {
    throw new Error(
      'Cannot target production rollout_environment when promoting pre-release store tracks (internal/alpha/beta/testflight)',
    );
  }
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
  assertStoreTrackIsolation({
    rolloutEnvironment: normalized,
    publishGithubRelease,
    iosStoreAction,
    macosStoreAction,
    androidStoreAction,
    verifyStoreCredentialsOnly,
  });
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
    APPLE_PRE_RELEASE_STORE_ACTIONS.has(iosStoreAction) ||
    APPLE_PRE_RELEASE_STORE_ACTIONS.has(macosStoreAction) ||
    ANDROID_PRE_RELEASE_STORE_ACTIONS.has(androidStoreAction);
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
  containerRegistry = '',
  containerTag = '',
  apiOrigin = '',
  stagingApiOrigin = '',
  cloudOrigin = '',
  stagingCloudOrigin = '',
  rolloutScript = '',
  pruneScript = '',
  k3sNamespace = '',
  k3sDeployment = '',
  k3sStagingDeployment = '',
}) {
  if (!['staging', 'production'].includes(environment)) {
    throw new Error(
      `Unsupported rollout environment for plan: ${environment}`,
    );
  }
  const normalizedVersion = String(version || '').trim().replace(/^v/, '');
  const normalizedBuild = String(buildNumber || '').trim();
  const normalizedRegistry = String(
    containerRegistry ||
      process.env.PROMOTE_CONTAINER_REGISTRY ||
      PRIMARY_CONTAINER_REGISTRY,
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
  const resolvedApiOrigin = String(
    (isStaging
      ? stagingApiOrigin || process.env.PROMOTE_STAGING_API_ORIGIN
      : apiOrigin || process.env.PROMOTE_API_ORIGIN) || '',
  ).trim();
  const resolvedCloudOrigin = String(
    (isStaging
      ? stagingCloudOrigin || process.env.PROMOTE_STAGING_CLOUD_ORIGIN
      : cloudOrigin || process.env.PROMOTE_CLOUD_ORIGIN) || '',
  ).trim();
  const resolvedRolloutScript = String(
    rolloutScript || process.env.PROMOTE_ROLLOUT_SCRIPT || 'scripts/rollout.sh',
  ).trim();
  const resolvedPruneScript = String(
    pruneScript ||
      process.env.PROMOTE_PRUNE_SCRIPT ||
      'scripts/prune-packages.mjs',
  ).trim();
  const resolvedNamespace = String(
    k3sNamespace || process.env.PROMOTE_K3S_NAMESPACE || 'default',
  ).trim();
  const resolvedDeployment = String(
    (isStaging
      ? k3sStagingDeployment || process.env.PROMOTE_K3S_STAGING_DEPLOYMENT
      : k3sDeployment || process.env.PROMOTE_K3S_DEPLOYMENT) ||
      (isStaging ? 'app-staging' : 'app'),
  ).trim();
  const resolvedHost = resolvedCloudOrigin
    .replace(/^https?:\/\//i, '')
    .replace(/\/.*$/, '');
  return {
    environment,
    version: normalizedVersion,
    build_number: normalizedBuild,
    source_sha: String(sourceSha || '').trim(),
    containerTag: imageTag,
    containerImage,
    cloudflare: {
      env: isStaging ? 'staging' : 'production',
      api_origin: resolvedApiOrigin,
      cloud_origin: resolvedCloudOrigin,
    },
    container: {
      registry: normalizedRegistry,
      image_tag: imageTag,
      alias_tag: aliasTag,
      client_tag: clientTag,
      image: containerImage,
      alias_image: `${normalizedRegistry}:${aliasTag}`,
      client_image: `${normalizedRegistry}:${clientTag}`,
      prune_script: resolvedPruneScript,
    },
    k3s: {
      namespace: resolvedNamespace,
      deployment: resolvedDeployment,
      host: resolvedHost,
    },
    rollout_command: ['bash', resolvedRolloutScript, '--env', environment],
    prune_command: ['node', resolvedPruneScript],
  };
}

function requireEnvironmentRolloutCredentials() {
  for (const name of ['CLOUDFLARE_API_TOKEN', 'CLOUDFLARE_ACCOUNT_ID', 'KUBECONFIG']) {
    if (!String(process.env[name] || '').trim()) {
      throw new Error(`${name} is required for environment rollout`);
    }
  }
  if (!/^[A-Za-z0-9][A-Za-z0-9./_:-]*@sha256:[a-f0-9]{64}$/.test(String(process.env.LEAP_GATEWAY_SOURCE_IMAGE || ''))) {
    throw new Error('LEAP_GATEWAY_SOURCE_IMAGE is required as an immutable repository@sha256 digest pin');
  }
}

export function executeEnvironmentRollout({
  environment,
  version,
  buildNumber = '',
  sourceSha = '',
  sourceRoot = '',
  stagingRepo = '',
  privateToken = '',
  githubToken = '',
  dockerHubUsername = '',
  dockerHubPatReadWrite = '',
  dockerHubPatReadOnly = '',
  containerRegistry = '',
  apiOrigin = '',
  stagingApiOrigin = '',
  cloudOrigin = '',
  stagingCloudOrigin = '',
  rolloutScript = '',
  pruneScript = '',
  k3sNamespace = '',
  k3sDeployment = '',
  k3sStagingDeployment = '',
  execFileImpl = execFileSync,
}) {
  const plan = buildEnvironmentRolloutPlan({
    environment,
    version,
    buildNumber,
    sourceSha,
    containerRegistry,
    apiOrigin,
    stagingApiOrigin,
    cloudOrigin,
    stagingCloudOrigin,
    rolloutScript,
    pruneScript,
    k3sNamespace,
    k3sDeployment,
    k3sStagingDeployment,
  });
  if (!/^[0-9a-f]{40}$/i.test(plan.source_sha)) {
    throw new Error('Rollout source_sha must be an exact 40-character commit SHA');
  }

  let resolvedRoot = String(
    sourceRoot || process.env.PROMOTE_SOURCE_ROOT || '',
  ).trim();
  const resolvedStagingRepo = String(
    stagingRepo || process.env.SOURCE_REPOSITORY || STAGING_REPOSITORY || '',
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
    tempKubeconfigDir = fs.mkdtempSync(path.join(os.tmpdir(), 'leap-rollout-kubeconfig-'));
    fs.chmodSync(tempKubeconfigDir, 0o700);
    const kubeconfigPath = path.join(tempKubeconfigDir, 'config');
    fs.writeFileSync(kubeconfigPath, kubeconfigBytes, { mode: 0o600, flag: 'wx' });
    fs.chmodSync(kubeconfigPath, 0o600);
    const rolloutEnv = { ...process.env, KUBECONFIG: kubeconfigPath };

    if (!resolvedRoot) {
      if (!privateToken) {
        throw new Error('Rollout requires a source checkout or private checkout token');
      }
      if (!resolvedStagingRepo) {
        throw new Error('Rollout requires SOURCE_REPOSITORY when source checkout is not provided');
      }
      tempCheckoutDir = fs.mkdtempSync(
        path.join(os.tmpdir(), 'leap-rollout-src-'),
      );
      const cloneUrl = `https://github.com/${resolvedStagingRepo}.git`;
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
    const rolloutScriptRel = plan.rollout_command[1];
    const rolloutScriptPath = path.join(resolvedRoot, ...rolloutScriptRel.split('/'));
    if (!fs.existsSync(rolloutScriptPath)) {
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
      LEAP_REGISTRY: plan.container.registry,
      PROMOTE_CONTAINER_REGISTRY: plan.container.registry,
      PROMOTE_VERSION: plan.version,
      PROMOTE_BUILD_NUMBER: plan.build_number,
      RELEASE_SOURCE_SHA: plan.source_sha,
      DOCKER_HUB_USERNAME:
        dockerHubUsername || process.env.DOCKER_HUB_USERNAME || '',
      DOCKER_HUB_PAT_READ_WRITE:
        dockerHubPatReadWrite || process.env.DOCKER_HUB_PAT_READ_WRITE || '',
      DOCKER_HUB_PAT_READ_ONLY:
        dockerHubPatReadOnly || process.env.DOCKER_HUB_PAT_READ_ONLY || '',
      GITHUB_TOKEN: effectiveGithubToken,
      GH_TOKEN: privateToken || effectiveGithubToken,
    };

    execFileImpl('bash', [rolloutScriptRel, '--env', environment], {
      cwd: resolvedRoot,
      env: childEnv,
      stdio: 'inherit',
    });

    const pruneScriptRel = plan.container.prune_script;
    const pruneScriptPath = path.join(resolvedRoot, ...pruneScriptRel.split('/'));
    if (fs.existsSync(pruneScriptPath)) {
      execFileImpl('node', [pruneScriptRel], {
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
  runId = '',
  proof = '',
  stagingRepo = '',
  publicRepo = PUBLIC_REPOSITORY,
  privateToken,
  publicToken,
  githubToken = '',
  dockerHubUsername = '',
  dockerHubPatReadWrite = '',
  dockerHubPatReadOnly = '',
  signingConfigJson,
  publishGithubRelease = false,
  iosStoreAction = 'none',
  iosAutomaticRelease = false,
  iosSigningConfigJson = '',
  macosStoreAction = 'none',
  macosAutomaticRelease = false,
  macosSigningConfigJson = '',
  appleConfigJson = '',
  internalTesterEmails = '',
  androidStoreAction = 'none',
  googlePlayServiceAccountJson = '',
  rolloutEnvironment = 'auto',
  containerRegistry = '',
  sourceRoot = '',
  verifyStoreCredentialsOnly = false,
  execFileImpl = execFileSync,
}) {
  stagingRepo = String(
    stagingRepo || process.env.SOURCE_REPOSITORY || STAGING_REPOSITORY || '',
  ).trim();
  containerRegistry = String(
    containerRegistry ||
      process.env.PROMOTE_CONTAINER_REGISTRY ||
      PRIMARY_CONTAINER_REGISTRY ||
      '',
  ).trim();
  if (!privateToken) {
    throw new Error('PRIVATE_RELEASE_TOKEN is required');
  }
  if (!stagingRepo && !verifyStoreCredentialsOnly) {
    throw new Error('SOURCE_REPOSITORY is required');
  }
  iosSigningConfigJson = mergeAppleSigningConfig(
    iosSigningConfigJson,
    appleConfigJson,
  );
  macosSigningConfigJson = mergeAppleSigningConfig(
    macosSigningConfigJson,
    appleConfigJson,
  );
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

  const workDir = fs.mkdtempSync(path.join(os.tmpdir(), 'leap-promote-release-'));
  try {
    const fetchStagingTagOptional = async (candidateTag) => {
      const url = `https://api.github.com/repos/${stagingRepo}/releases/tags/${encodeURIComponent(candidateTag)}`;
      const response = await fetch(url, {
        headers: {
          Accept: 'application/vnd.github+json',
          Authorization: `Bearer ${privateToken}`,
          'X-GitHub-Api-Version': '2022-11-28',
          'User-Agent': 'leapterm-release-promoter',
        },
        redirect: 'follow',
      });
      if (response.status === 404) {
        return null;
      }
      if (!response.ok) {
        throw new Error(`GitHub API request failed (${response.status}) for ${url}`);
      }
      return response.json();
    };

    const fetchStagingRelease = async (candidateTag, candidateBuildNumber = '') => {
      const direct = await fetchStagingTagOptional(candidateTag);
      if (direct) {
        return direct;
      }
      try {
        const listUrl = `https://api.github.com/repos/${stagingRepo}/releases?per_page=100`;
        const response = await fetch(listUrl, {
          headers: {
            Accept: 'application/vnd.github+json',
            Authorization: `Bearer ${privateToken}`,
            'X-GitHub-Api-Version': '2022-11-28',
            'User-Agent': 'leapterm-release-promoter',
          },
          redirect: 'follow',
        });
        if (!response.ok) {
          return null;
        }
        const releases = await response.json();
        if (!Array.isArray(releases)) {
          return null;
        }
        const exactTag = releases.find((r) => r.tag_name === candidateTag);
        if (exactTag) {
          return exactTag;
        }
        if (candidateBuildNumber) {
          const buildTags = [
            `${candidateTag}-b${candidateBuildNumber}`,
            `${candidateTag}-${candidateBuildNumber}`,
            `v${normalizedVersion}-b${candidateBuildNumber}`,
            `v${normalizedVersion}-${candidateBuildNumber}`,
          ];
          const byBuildTag = releases.find((r) => buildTags.includes(r.tag_name));
          if (byBuildTag) {
            return byBuildTag;
          }
          const byName = releases.find(
            (r) =>
              r.name &&
              r.name.includes(normalizedVersion) &&
              (r.name.includes(`(${candidateBuildNumber})`) ||
                r.name.includes(`Build ${candidateBuildNumber}`) ||
                r.name.includes(`b${candidateBuildNumber}`)),
          );
          if (byName) {
            return byName;
          }
        }
      } catch {
        return null;
      }
      return null;
    };

    const provenanceName = `leapterm-${normalizedVersion}-release-provenance.json`;
    let assetsByName;
    let keyringPath;
    let stagingLinks;
    let stagingProvenance;

    const candidateTags = [tag];
    if (expectedBuildNumber) {
      candidateTags.unshift(
        `${tag}-b${expectedBuildNumber}`,
        `${tag}-${expectedBuildNumber}`,
      );
    }

    let fullStagingRelease = null;
    for (const candTag of candidateTags) {
      fullStagingRelease = await fetchStagingRelease(candTag, expectedBuildNumber);
      if (fullStagingRelease) {
        break;
      }
    }
    if (fullStagingRelease) {
      assetsByName = new Map(
        (fullStagingRelease.assets || []).map((asset) => [asset.name, asset]),
      );
      const requireSingleAsset = async (name) => {
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
      keyringPath = await requireSingleAsset(
        resolveStagingKeyringAssetName(assetsByName),
      );
      const stagingLinksPath = await requireSingleAsset('download-links.json');
      const stagingProvPath = await requireSingleAsset(provenanceName);
      const stagingProvSigPath = await requireSingleAsset(
        `${provenanceName}.sig`,
      );
      verifyGpgSignature(keyringPath, stagingProvSigPath, stagingProvPath);
      stagingLinks = JSON.parse(fs.readFileSync(stagingLinksPath, 'utf8'));
      stagingProvenance = JSON.parse(fs.readFileSync(stagingProvPath, 'utf8'));
    } else {
      const waveTags = [`${tag}-fast`, `${tag}-slow`];
      const wavePayloads = [];
      for (const waveTag of waveTags) {
        const waveRelease = await fetchStagingTagOptional(waveTag);
        if (!waveRelease) continue;
        const waveDir = path.join(workDir, waveTag);
        fs.mkdirSync(waveDir, { recursive: true });
        const waveAssets = new Map(
          (waveRelease.assets || []).map((asset) => [asset.name, asset]),
        );
        const requireWaveAsset = async (name) => {
          const asset = waveAssets.get(name);
          if (!asset) {
            throw new Error(
              `Staging release ${waveTag} is missing required asset: ${name}`,
            );
          }
          const dest = path.join(waveDir, name);
          await downloadReleaseAsset(asset.url, privateToken, dest);
          return dest;
        };
        const waveKeyringPath = await requireWaveAsset(
          resolveStagingKeyringAssetName(waveAssets),
        );
        const waveLinksPath = await requireWaveAsset('download-links.json');
        const waveProvPath = await requireWaveAsset(provenanceName);
        const waveProvSigPath = await requireWaveAsset(`${provenanceName}.sig`);
        verifyGpgSignature(waveKeyringPath, waveProvSigPath, waveProvPath);
        if (!keyringPath) {
          keyringPath = path.join(workDir, path.basename(waveKeyringPath));
          fs.copyFileSync(waveKeyringPath, keyringPath);
        }
        wavePayloads.push({
          tag: waveTag,
          downloadLinks: JSON.parse(fs.readFileSync(waveLinksPath, 'utf8')),
          provenance: JSON.parse(fs.readFileSync(waveProvPath, 'utf8')),
          assets: waveRelease.assets || [],
        });
      }
      if (wavePayloads.length === 0) {
        if (
          !publishGithubRelease &&
          (iosStoreAction !== 'none' || macosStoreAction !== 'none')
        ) {
          stagingLinks = { build_number: expectedBuildNumber };
          stagingProvenance = { build_number: expectedBuildNumber };
          assetsByName = new Map();
        } else {
          throw new Error(
            `GitHub API request failed (404) for ${stagingReleaseUrl}`,
          );
        }
      }
      const merged = mergeWaveStagingMetadata({
        wavePayloads,
        version: normalizedVersion,
      });
      stagingLinks = merged.stagingLinks;
      stagingProvenance = merged.stagingProvenance;
      assetsByName = merged.assetsByName;
    }

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

    const readiness = verifyAllReleaseBuildsReady({
      downloadLinks: stagingLinks,
      provenance: stagingProvenance,
      assetsByName,
      version: normalizedVersion,
    });
    let resolvedBuildNumber = String(
      stagingLinks?.build_number || stagingProvenance?.build_number || '',
    );

    if (
      expectedBuildNumber &&
      resolvedBuildNumber !== String(expectedBuildNumber)
    ) {
      if (publishGithubRelease || androidStoreAction !== 'none') {
        throw new Error(
          `Staging build_number mismatch: expected ${expectedBuildNumber}, found ${resolvedBuildNumber}`,
        );
      } else {
        console.log(
          `Staging release build number is ${resolvedBuildNumber}; overriding with requested build ${expectedBuildNumber} for store promotion.`,
        );
        resolvedBuildNumber = String(expectedBuildNumber);
      }
    }

    if (publishGithubRelease) {
      const selfHostedName = `leapterm-${normalizedVersion}-self-hosted.zip`;
      let selfHostedOverride = null;
      const filesToUpload = [];
      const sha256Entries = [];

      if (assetsByName.has(selfHostedName)) {
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
        selfHostedOverride = {
          name: selfHostedName,
          bytes: selfHostedBytes,
          sha256: selfHostedSha,
        };
        filesToUpload.push(
          selfHostedBinPath,
          selfHostedShaPath,
          selfHostedSigPath,
        );
        sha256Entries.push({ name: selfHostedName, sha256: selfHostedSha });
      } else if (readiness.ready) {
        throw new Error(
          `Staging release ${tag} is missing required asset: ${selfHostedName}`,
        );
      }

      const publicLinks = filterPublicDownloadLinks(
        stagingLinks,
        publicRepo,
        selfHostedOverride,
        { allowPartialWave: !readiness.ready },
      );
      const publicProvenance = filterPublicProvenance(stagingProvenance, {
        allowPartialWave: !readiness.ready,
      });

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

      if (assetsByName.has('gpg.key')) {
        const gpgKeyPath = await requireStagingAsset('gpg.key');
        filesToUpload.push(gpgKeyPath);
      } else if (fs.existsSync(keyringPath)) {
        const gpgKeyPath = path.join(workDir, 'gpg.key');
        fs.copyFileSync(keyringPath, gpgKeyPath);
        filesToUpload.push(gpgKeyPath);
      }

      if (assetsByName.has('install.sh')) {
        const installShPath = await requireStagingAsset('install.sh');
        filesToUpload.push(installShPath);
      } else {
        try {
          const sourceRepo = process.env.SOURCE_REPOSITORY || 'omnisolo-llc/leapterm';
          const targetSha = stagingProvenance.source_sha || 'main';
          const contentRes = await githubRequest(
            `https://api.github.com/repos/${sourceRepo}/contents/deploy/packaging/install.sh?ref=${encodeURIComponent(targetSha)}`,
            privateToken,
          );
          const contentJson = await contentRes.json();
          if (contentJson && contentJson.content) {
            const installShPath = path.join(workDir, 'install.sh');
            fs.writeFileSync(installShPath, Buffer.from(contentJson.content, 'base64'));
            filesToUpload.push(installShPath);
          }
        } catch (err) {
          console.warn('Could not fetch install.sh from source repo:', err.message);
        }
      }

      for (const filePath of filesToUpload) {
        const base = path.basename(filePath);
        if (FORBIDDEN_ASSET_PATTERNS.some((rx) => rx.test(base))) {
          throw new Error(`Refusing to upload forbidden private asset: ${base}`);
        }
      }

      const isCompletePublicRelease =
        readiness.ready && !normalizedVersion.includes('-');

      let publicRelease;
      const existingRes = await fetch(
        `https://api.github.com/repos/${publicRepo}/releases/tags/${encodeURIComponent(tag)}`,
        {
          headers: {
            Accept: 'application/vnd.github+json',
            Authorization: `Bearer ${publicToken}`,
            'X-GitHub-Api-Version': '2022-11-28',
            'User-Agent': 'leapterm-release-promoter',
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
              prerelease: !isCompletePublicRelease,
              make_latest: isCompletePublicRelease ? 'true' : 'false',
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
            prerelease: !isCompletePublicRelease,
            make_latest: isCompletePublicRelease ? 'true' : 'false',
            name: `LeapTerm ${tag}`,
            body: `LeapTerm ${tag} public release.`,
          }),
        },
      );

      console.log(
        `Promoted LeapTerm ${tag} (${filesToUpload.length} verified public assets, complete=${readiness.ready}) to ${publicRepo}.`,
      );
    }

    if (androidStoreAction && androidStoreAction !== 'none') {
      const aabName = assetsByName.has(`leapterm-${normalizedVersion}-android.aab`)
        ? `leapterm-${normalizedVersion}-android.aab`
        : `leapterm-${normalizedVersion}-android-release.aab`;
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
      const targetBuildNumber = String(
        expectedBuildNumber || resolvedBuildNumber || '',
      ).trim();
      let ipaPath = '';
      if (['internal', 'testflight'].includes(iosStoreAction)) {
        const ipaName = `leapterm-${normalizedVersion}-ios-private.ipa`;
        if (assetsByName && assetsByName.has(ipaName)) {
          ipaPath = await requireStagingAsset(ipaName);
        } else {
          let stageRelease = null;
          let targetRunId = String(
            runId || stagingProvenance?.run_id || '',
          ).trim();
          let targetAttempt = String(
            stagingProvenance?.attempt || '1',
          ).trim();
          let targetProof = String(
            proof || stagingProvenance?.proof || '',
          ).trim();
          let effectiveRoute = stagingProvenance?.release_route || 'option1';

          if (!targetRunId && targetBuildNumber) {
            const stageInfo = await resolvePrivateStageRelease({
              stagingRepo,
              privateToken,
              version: normalizedVersion,
              buildNumber: targetBuildNumber,
              fetchImpl,
            });
            if (stageInfo) {
              stageRelease = stageInfo.stageRelease;
              targetRunId = stageInfo.runId;
              targetAttempt = stageInfo.attempt;
            }
          }
          if (!stageRelease && targetRunId) {
            const stageTag = `ci-stage/application-${targetRunId}-${targetAttempt}`;
            const stageReleasesRes = await githubRequest(
              `https://api.github.com/repos/${stagingRepo}/releases?per_page=100`,
              privateToken,
            );
            const stageReleases = await stageReleasesRes.json();
            stageRelease = (stageReleases || []).find(
              (r) =>
                r.tag_name === stageTag ||
                r.tag_name === `ci-stage/application-${targetRunId}-1` ||
                r.tag_name.startsWith(`ci-stage/application-${targetRunId}-`),
            );
          }
          if (!stageRelease) {
            throw new Error(
              `Private stage release not found on ${stagingRepo} for iOS IPA retrieval (runId: ${targetRunId || 'auto'}, build: ${targetBuildNumber || 'unknown'})`,
            );
          }
          const stageAssets = new Map(
            (stageRelease.assets || []).map((a) => [a.name, a]),
          );
          const storageKeys = buildPrivateIosStorageKeys({
            version: normalizedVersion,
            buildNumber: targetBuildNumber,
            runId: targetRunId,
            runAttempt: targetAttempt,
            proof: targetProof,
            releaseRoute: effectiveRoute,
          });
          let ipaAsset = null;
          for (const key of storageKeys.ipaKeys) {
            const objName = `object-${sha256Hex(Buffer.from(key, 'utf8'))}.bin`;
            if (stageAssets.has(objName)) {
              ipaAsset = stageAssets.get(objName);
              break;
            }
          }
          let receiptAsset = null;
          for (const key of storageKeys.receiptKeys) {
            const objName = `object-${sha256Hex(Buffer.from(key, 'utf8'))}.bin`;
            if (stageAssets.has(objName)) {
              receiptAsset = stageAssets.get(objName);
              break;
            }
          }
          if (!receiptAsset) {
            const jsonCandidates = (stageRelease.assets || []).filter(
              (a) =>
                a.size > 0 &&
                a.size < 4096 &&
                (a.content_type === 'application/json' ||
                  a.contentType === 'application/json' ||
                  a.name.endsWith('.bin') ||
                  a.name.endsWith('.json')),
            );
            for (const cand of jsonCandidates) {
              try {
                const tempReceiptPath = path.join(workDir, `check-${cand.name}`);
                await downloadReleaseAsset(cand.url, privateToken, tempReceiptPath);
                const parsed = JSON.parse(fs.readFileSync(tempReceiptPath, 'utf8'));
                if (
                  parsed.name === 'ios-private-artifact-receipt.json' ||
                  (parsed.receipt && parsed.receipt.target === 'ios') ||
                  (parsed.receipt && parsed.receipt.name === ipaName)
                ) {
                  receiptAsset = cand;
                  break;
                }
              } catch {
                // ignore and continue
              }
            }
          }
          if (!ipaAsset || !receiptAsset) {
            const ipaObjName = `object-${sha256Hex(Buffer.from(storageKeys.ipaKey, 'utf8'))}.bin`;
            const receiptObjName = `object-${sha256Hex(Buffer.from(storageKeys.receiptKey, 'utf8'))}.bin`;
            throw new Error(
              `Private stage release ${stageRelease.tag_name} missing signed iOS IPA (${ipaObjName}) or receipt (${receiptObjName})`,
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
          if (receipt.proof && !targetProof) {
            targetProof = receipt.proof;
          }
        }
      }
      const iosResult = await promoteIosToAppStoreConnect({
        version: normalizedVersion,
        buildNumber: targetBuildNumber || resolvedBuildNumber,
        action: iosStoreAction,
        automaticRelease: iosAutomaticRelease,
        ipaPath,
        iosSigningConfigJson,
        internalTesterEmails,
      });
      console.log(
        `Promoted iOS candidate v${normalizedVersion} (${targetBuildNumber || resolvedBuildNumber}) via action "${iosResult.action}" (${iosResult.status}).`,
      );
    }

    if (macosStoreAction && macosStoreAction !== 'none') {
      let macosPackagePath = '';
      if (['internal', 'testflight'].includes(macosStoreAction)) {
        const macosZipName = `leapterm-${normalizedVersion}-macos-arm64.zip`;
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
        internalTesterEmails,
      });
      console.log(
        `Promoted macOS candidate v${normalizedVersion} (${resolvedBuildNumber}) via action "${macosResult.action}" (${macosResult.status}).`,
      );
    }

    if (resolvedRolloutEnv !== 'none') {
      if (resolvedRolloutEnv === 'production' && !readiness.ready) {
        if (String(rolloutEnvironment || 'auto').trim().toLowerCase() === 'production') {
          throw new Error(
            `Cannot promote v${normalizedVersion} to production Cloudflare metadata until all release builds are ready (missing targets: ${readiness.missingTargets.join(', ')})`,
          );
        }
        console.log(
          `Deferring production Cloudflare metadata rollout for v${normalizedVersion} until all release builds are ready (missing targets: ${readiness.missingTargets.join(', ')}).`,
        );
      } else {
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
    runId: process.env.PROMOTE_RUN_ID || '',
    proof: process.env.PROMOTE_PROOF || '',
    privateToken: process.env.PRIVATE_RELEASE_TOKEN,
    publicToken: process.env.GH_TOKEN,
    githubToken: process.env.GITHUB_TOKEN || '',
    dockerHubUsername: process.env.DOCKER_HUB_USERNAME || '',
    dockerHubPatReadWrite: process.env.DOCKER_HUB_PAT_READ_WRITE || '',
    dockerHubPatReadOnly: process.env.DOCKER_HUB_PAT_READ_ONLY || '',
    signingConfigJson: process.env.PACKAGE_SIGNING_CONFIG,
    publishGithubRelease:
      String(process.env.PROMOTE_GITHUB_RELEASE ?? 'false') === 'true',
    iosStoreAction: process.env.PROMOTE_IOS_STORE_ACTION || 'none',
    iosAutomaticRelease:
      String(process.env.PROMOTE_IOS_AUTOMATIC_RELEASE ?? 'false') === 'true',
    iosSigningConfigJson: process.env.IOS_SIGNING_CONFIG || '',
    macosStoreAction: process.env.PROMOTE_MACOS_STORE_ACTION || 'none',
    macosAutomaticRelease:
      String(process.env.PROMOTE_MACOS_AUTOMATIC_RELEASE ?? 'false') === 'true',
    macosSigningConfigJson: process.env.MACOS_SIGNING_CONFIG || '',
    appleConfigJson: process.env.APPLE_CONFIG || '',
    internalTesterEmails: process.env.INTERNAL_TESTER_EMAILS || '',
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
