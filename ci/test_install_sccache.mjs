import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {
  BUILD_CACHE_DIRS,
  SCCACHE_SPECS,
  installSccache,
} from './install-sccache.mjs';

function makeTempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'sccache-test-'));
}

test('installSccache extracts archive using relative filename and cwd to avoid Windows GNU tar colon issues', async () => {
  const runnerTemp = makeTempDir();
  const githubOutput = path.join(runnerTemp, 'github_output.txt');
  const payload = Buffer.from('fake-sccache-tarball');
  const payloadSha = crypto.createHash('sha256').update(payload).digest('hex');

  const fakeSpec = {
    ...SCCACHE_SPECS.Windows,
    sha256: payloadSha,
  };

  const tarCalls = [];
  const fakeExec = (cmd, args, opts) => {
    tarCalls.push({ cmd, args, opts });
    const extractedDir = path.join(opts.cwd, fakeSpec.folder);
    fs.mkdirSync(extractedDir, { recursive: true });
    fs.writeFileSync(path.join(extractedDir, fakeSpec.binary), 'binary-bytes');
  };
  const fakeFetch = async () => ({
    ok: true,
    status: 200,
    arrayBuffer: async () => payload,
  });

  const resolved = await installSccache({
    runnerOs: 'Windows',
    runnerTemp,
    githubOutput,
    fetchImpl: fakeFetch,
    execFileImpl: fakeExec,
    specs: { Windows: fakeSpec },
  });

  assert.equal(tarCalls.length, 1);
  assert.equal(tarCalls[0].cmd, 'tar');
  assert.deepEqual(tarCalls[0].args, ['-xzf', fakeSpec.archive]);
  assert.equal(tarCalls[0].opts.cwd, path.join(runnerTemp, 'sccache-bin'));
  assert.equal(path.basename(resolved), 'sccache.exe');
  assert.match(fs.readFileSync(githubOutput, 'utf8'), /^wrapper=/);

  for (const dirName of BUILD_CACHE_DIRS) {
    assert.ok(fs.existsSync(path.join(runnerTemp, dirName)));
  }

  fs.rmSync(runnerTemp, { recursive: true, force: true });
});

test('installSccache skips download when cached binary already exists and rejects SHA256 mismatches', async () => {
  const linuxTemp = makeTempDir();
  const linuxSpec = SCCACHE_SPECS.Linux;
  const preseededDir = path.join(linuxTemp, 'sccache-bin', linuxSpec.folder);
  fs.mkdirSync(preseededDir, { recursive: true });
  fs.writeFileSync(path.join(preseededDir, linuxSpec.binary), 'cached');

  const resolvedCached = await installSccache({
    runnerOs: 'Linux',
    runnerTemp: linuxTemp,
    fetchImpl: async () => {
      throw new Error('fetch should not run when binary is already cached');
    },
    execFileImpl: () => {
      throw new Error('tar should not run when binary is already cached');
    },
  });
  assert.equal(path.basename(resolvedCached), 'sccache');
  fs.rmSync(linuxTemp, { recursive: true, force: true });

  const mismatchTemp = makeTempDir();
  await assert.rejects(
    () =>
      installSccache({
        runnerOs: 'Windows',
        runnerTemp: mismatchTemp,
        fetchImpl: async () => ({
          ok: true,
          status: 200,
          arrayBuffer: async () => Buffer.from('bad-bytes'),
        }),
        execFileImpl: () => {
          throw new Error('tar should not run on SHA256 mismatch');
        },
      }),
    /SHA256 mismatch/,
  );
  fs.rmSync(mismatchTemp, { recursive: true, force: true });
});

test('installSccache bounds sccache disk cache size per target to prevent repository cache eviction', async () => {
  const runnerTemp = makeTempDir();
  const githubOutput = path.join(runnerTemp, 'github_output.txt');
  const linuxSpec = SCCACHE_SPECS.Linux;
  const preseededDir = path.join(runnerTemp, 'sccache-bin', linuxSpec.folder);
  fs.mkdirSync(preseededDir, { recursive: true });
  fs.writeFileSync(path.join(preseededDir, linuxSpec.binary), 'cached');

  await installSccache({
    runnerOs: 'Linux',
    runnerTemp,
    githubOutput,
    target: 'windows',
    fetchImpl: async () => { throw new Error('unused'); },
    execFileImpl: () => { throw new Error('unused'); },
  });

  const confContent = fs.readFileSync(path.join(runnerTemp, 'sccache', 'sccache-config.toml'), 'utf8');
  assert.match(confContent, /size = 1887436800/);
  const outputContent = fs.readFileSync(githubOutput, 'utf8');
  assert.match(outputContent, /sccache_cache_size=1887436800/);

  // Test android target bound
  await installSccache({
    runnerOs: 'Linux',
    runnerTemp,
    githubOutput,
    target: 'android',
    fetchImpl: async () => { throw new Error('unused'); },
    execFileImpl: () => { throw new Error('unused'); },
  });

  const androidConf = fs.readFileSync(path.join(runnerTemp, 'sccache', 'sccache-config.toml'), 'utf8');
  assert.match(androidConf, /size = 838860800/);

  fs.rmSync(runnerTemp, { recursive: true, force: true });
});
