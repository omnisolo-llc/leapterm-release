#!/usr/bin/env node
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const SCCACHE_VERSION = '0.18.0';
export const SCCACHE_SPECS = Object.freeze({
  Linux: {
    archive: 'sccache-v0.18.0-x86_64-unknown-linux-musl.tar.gz',
    folder: 'sccache-v0.18.0-x86_64-unknown-linux-musl',
    sha256: '45f1447fbe231e3037bde351ef70677dd212216c8d62ae7ca409fecc4d6acc89',
    binary: 'sccache',
  },
  macOS: {
    archive: 'sccache-v0.18.0-aarch64-apple-darwin.tar.gz',
    folder: 'sccache-v0.18.0-aarch64-apple-darwin',
    sha256: '308184519b646f5125289e8515b36f6ca65a13a041923994aebe702348674e8e',
    binary: 'sccache',
  },
  Windows: {
    archive: 'sccache-v0.18.0-x86_64-pc-windows-msvc.tar.gz',
    folder: 'sccache-v0.18.0-x86_64-pc-windows-msvc',
    sha256: '1a63c1be2beab3f04d27e4cc145443e092e02d3dd83a51030989829d7023091b',
    binary: 'sccache.exe',
  },
});

export const BUILD_CACHE_DIRS = Object.freeze([
  'sccache',
  'flutter-sdk-cache',
  'pub-cache',
  'android-ndk-cache',
  'mobile-freerdp-cache',
  'mobile-sdk-archives',
]);

export const SCCACHE_DEFAULT_DISK_SIZE_BYTES = 1073741824; // 1.0 GB
export const SCCACHE_DISK_SIZES_BYTES = Object.freeze({
  windows: 1887436800,        // 1.8 GB
  macos: 1572864000,          // 1.5 GB
  ios: 1572864000,            // 1.5 GB
  linux: 1073741824,          // 1.0 GB
  android: 838860800,         // 800 MB
  web: 524288000,             // 500 MB
  'windows-sdk': 524288000,   // 500 MB
});

export async function installSccache({
  runnerOs = process.env.RUNNER_OS || '',
  runnerTemp = process.env.RUNNER_TEMP || '',
  githubOutput = process.env.GITHUB_OUTPUT || '',
  target = process.env.SCCACHE_TARGET || process.env.RELEASE_TARGET || '',
  fetchImpl = fetch,
  execFileImpl = execFileSync,
  specs = SCCACHE_SPECS,
} = {}) {
  if (!runnerTemp) {
    throw new Error('RUNNER_TEMP is required');
  }
  const spec = specs[runnerOs];
  if (!spec) {
    throw new Error(`Unsupported RUNNER_OS for sccache: ${runnerOs}`);
  }
  for (const dirName of BUILD_CACHE_DIRS) {
    fs.mkdirSync(path.join(runnerTemp, dirName), { recursive: true });
  }
  const sccacheDir = path.join(runnerTemp, 'sccache');
  const confPath = path.join(sccacheDir, 'sccache-config.toml');
  const cachedConfPath = path.join(sccacheDir, 'sccache-cached-config.toml');
  const distCacheDir = path.join(sccacheDir, 'dist');
  fs.mkdirSync(distCacheDir, { recursive: true });
  const diskCacheDir = path.join(sccacheDir, 'disk');
  fs.mkdirSync(diskCacheDir, { recursive: true });
  const normalizedTarget = (target || '').toLowerCase();
  const cacheSizeBytes = SCCACHE_DISK_SIZES_BYTES[normalizedTarget] || SCCACHE_DEFAULT_DISK_SIZE_BYTES;
  const tomlContent = [
    '[cache.disk]',
    `dir = ${JSON.stringify(diskCacheDir)}`,
    `size = ${cacheSizeBytes}`,
    '',
    '[dist]',
    `cache_dir = ${JSON.stringify(distCacheDir)}`,
    '',
  ].join('\n');
  fs.writeFileSync(confPath, tomlContent);
  fs.writeFileSync(cachedConfPath, tomlContent);
  const installRoot = path.join(runnerTemp, 'sccache-bin');
  fs.mkdirSync(installRoot, { recursive: true });
  const binaryPath = path.join(installRoot, spec.folder, spec.binary);
  if (!fs.existsSync(binaryPath)) {
    const url = `https://github.com/mozilla/sccache/releases/download/v${SCCACHE_VERSION}/${spec.archive}`;
    const response = await fetchImpl(url, { redirect: 'follow' });
    if (!response.ok) {
      throw new Error(`Failed downloading sccache (${response.status}) from ${url}`);
    }
    const bytes = Buffer.from(await response.arrayBuffer());
    const actualSha = crypto.createHash('sha256').update(bytes).digest('hex');
    if (actualSha !== spec.sha256) {
      throw new Error(
        `sccache SHA256 mismatch for ${spec.archive}: expected ${spec.sha256}, got ${actualSha}`,
      );
    }
    const archivePath = path.join(installRoot, spec.archive);
    fs.writeFileSync(archivePath, bytes);
    execFileImpl('tar', ['-xzf', spec.archive], { cwd: installRoot, stdio: 'inherit' });
    fs.rmSync(archivePath, { force: true });
  }
  if (!fs.existsSync(binaryPath)) {
    throw new Error(`Extracted sccache binary missing at ${binaryPath}`);
  }
  if (runnerOs !== 'Windows') {
    fs.chmodSync(binaryPath, 0o755);
  }
  const resolvedBinary = fs.realpathSync(binaryPath);
  if (githubOutput) {
    fs.appendFileSync(githubOutput, `wrapper=${resolvedBinary}\n`);
    fs.appendFileSync(githubOutput, `sccache_conf=${confPath}\n`);
    fs.appendFileSync(githubOutput, `sccache_cached_conf=${cachedConfPath}\n`);
    fs.appendFileSync(githubOutput, `sccache_cache_size=${cacheSizeBytes}\n`);
  }
  return resolvedBinary;
}

if (
  process.argv[1] &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  const cliTarget = process.argv[2] || '';
  installSccache({ target: cliTarget || undefined }).catch((err) => {
    console.error(err instanceof Error ? err.message : String(err));
    process.exit(1);
  });
}
