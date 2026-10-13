// Build-path contracts supplement, never replace, real HTTP/3 acceptance.
import test from 'node:test';
import assert from 'node:assert/strict';
import {cp, mkdir, mkdtemp, readFile, rm, stat, symlink, utimes, writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {dirname, join} from 'node:path';
import {nativeBuildPath, requireLoadedAddon} from '../scripts/native-build-identity.mjs';
import * as nativeIdentity from '../scripts/native-build-identity.mjs';

test('receipt identifies the platform addon the upstream loader actually uses', () => {
  assert.equal(nativeBuildPath('/owned/adapter', 'linux', 'x64'),
    '/owned/adapter/build_linux_x64/Release/webtransport.node');
  assert.equal(nativeBuildPath('/owned/adapter', 'linux', 'arm64'),
    '/owned/adapter/build_linux_arm64/Release/webtransport.node');
  assert.throws(() => nativeBuildPath('/owned/adapter', '../escape', 'x64'));
});

test('a generic prebuilt, debug addon or second addon cannot certify the patched build', () => {
  const expected = nativeBuildPath('/owned/adapter', 'linux', 'x64');
  assert.doesNotThrow(() => requireLoadedAddon(expected, [expected]));
  for (const paths of [[], ['/owned/adapter/build/Release/webtransport.node'],
    ['/owned/adapter/build_linux_x64/Debug/webtransport.node'], [expected, '/other/webtransport.node']]) {
    assert.throws(() => requireLoadedAddon(expected, paths), /native_addon_identity_mismatch/);
  }
});

test('fresh native builds disable upstream Python discovery and Python-only tests', async () => {
  const source = await readFile(new URL('../scripts/build-patched-webtransport.mjs', import.meta.url), 'utf8');
  assert.match(source, /--CDgtest_build_tests=OFF/);
  assert.match(source, /--CDCMAKE_DISABLE_FIND_PACKAGE_Python3=TRUE/);
  assert.match(source, /--CDCMAKE_DISABLE_FIND_PACKAGE_Python=TRUE/);
});

test('npm lifecycle scripts cannot run the upstream unpinned addon build', async () => {
  const packageJson = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8'));
  assert.equal(packageJson.scripts.postinstall, undefined);
  assert.equal(packageJson.scripts['native-build'], 'node scripts/build-patched-webtransport.mjs');
  const npmPolicy = await readFile(new URL('../.npmrc', import.meta.url), 'utf8');
  assert.match(npmPolicy, /^ignore-scripts=true$/m);

  for (const workflowName of ['contracts', 'release']) {
    const workflow = await readFile(
      new URL(`../../../.github/workflows/${workflowName}.yml`, import.meta.url), 'utf8');
    const install = workflow.indexOf('npm ci --ignore-scripts --prefix relay/moq');
    const build = workflow.indexOf('npm run native-build --prefix relay/moq');
    const test = workflow.indexOf('npm test --prefix relay/moq');
    assert.ok(install >= 0, `${workflowName}: lifecycle scripts must be disabled`);
    assert.ok(build > install, `${workflowName}: native build must follow install`);
    assert.ok(test > build, `${workflowName}: MoQ tests must follow native build`);
  }
});

const patchSources = ['src/session.cc', 'lib/client.js'];
const upstreamSources = ['upstream native close\n', 'upstream client close\n'];
const patchedSources = ['exact native close patch\n', 'exact client close patch\n'];

async function writeSources(root, sources) {
  for (const [index, path] of patchSources.entries()) {
    await mkdir(dirname(join(root, path)), {recursive: true});
    await writeFile(join(root, path), sources[index]);
  }
}

async function sourceFixture(t, installedSources = upstreamSources) {
  const directory = await mkdtemp(join(tmpdir(), 'omniterm-moq-native-source-'));
  t.after(() => rm(directory, {recursive: true, force: true}));
  const pristineRoot = join(directory, 'verified-tarball');
  const adapterRoot = join(directory, 'installed');
  await writeSources(pristineRoot, upstreamSources);
  await writeFile(join(pristineRoot, 'package.json'), '{"version":"1.6.8"}\n');
  await cp(pristineRoot, adapterRoot, {recursive: true});
  await writeSources(adapterRoot, installedSources);
  return {adapterRoot, pristineRoot, patchSources,
    applyPatches: () => writeSources(pristineRoot, patchedSources)};
}

test('verified pristine adapter receives the exact tracked source patches', async t => {
  const fixture = await sourceFixture(t);
  assert.equal(typeof nativeIdentity.prepareAdapterSource, 'function',
    'native builder needs exact pristine-or-patched source classification');
  const prepared = await nativeIdentity.prepareAdapterSource(fixture);
  assert.equal(prepared.state, 'pristine');
  assert.notEqual(prepared.upstreamSourceDigest, prepared.expectedPatchedSourceDigest);
  assert.equal(await nativeIdentity.treeDigest(fixture.adapterRoot, {excludeBuildOutput: true}),
    prepared.expectedPatchedSourceDigest);
  for (const [index, path] of patchSources.entries()) {
    assert.equal(await readFile(join(fixture.adapterRoot, path), 'utf8'), patchedSources[index]);
  }
});

test('interrupted native build resumes an exact patched tree without recopying or changing source timestamps',
  async t => {
    const fixture = await sourceFixture(t, patchedSources);
    const cache = join(fixture.adapterRoot, 'build_linux_x64/CMakeCache.txt');
    const object = join(fixture.adapterRoot, 'build_linux_x64/partial/session.cc.o');
    const thirdParty = join(fixture.adapterRoot, 'third_party/quiche/source.cc');
    for (const path of [cache, object, thirdParty]) {
      await mkdir(dirname(path), {recursive: true});
      await writeFile(path, 'retained partial native build\n');
    }
    const sourcePaths = patchSources.map(path => join(fixture.adapterRoot, path));
    for (const path of [...sourcePaths, cache, object, thirdParty]) await utimes(path, 1000, 1000);
    const before = await Promise.all(sourcePaths.map(path => stat(path, {bigint: true})));
    assert.equal(typeof nativeIdentity.prepareAdapterSource, 'function',
      'an interrupted build must accept its exact already patched source');
    const prepared = await nativeIdentity.prepareAdapterSource(fixture);
    assert.equal(prepared.state, 'patched');
    const after = await Promise.all(sourcePaths.map(path => stat(path, {bigint: true})));
    assert.deepEqual(after.map(value => [value.ino, value.mtimeNs, value.ctimeNs]),
      before.map(value => [value.ino, value.mtimeNs, value.ctimeNs]),
      'warm retry recopied source and invalidated native build timestamps');
    for (const path of [cache, object, thirdParty]) {
      assert.equal(await readFile(path, 'utf8'), 'retained partial native build\n');
      assert.equal((await stat(path)).mtimeMs, 1000000);
    }
  });

test('resumed Quiche source keeps tracked files and regenerates only known protocol outputs', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'omniterm-quiche-resume-'));
  t.after(() => rm(directory, {recursive: true, force: true}));
  const pristineRoot = join(directory, 'pinned');
  const installedRoot = join(directory, 'installed');
  const tracked = 'quiche/quiche/quic/core/proto/source_address_token.proto';
  await mkdir(dirname(join(pristineRoot, tracked)), {recursive: true});
  await writeFile(join(pristineRoot, tracked), 'pinned proto source\n');
  await cp(pristineRoot, installedRoot, {recursive: true});
  const before = await stat(join(installedRoot, tracked), {bigint: true});
  for (const path of nativeIdentity.generatedProtoPaths) {
    await writeFile(join(installedRoot, path), 'generated bytes to replace\n');
  }
  assert.equal(await nativeIdentity.prepareThirdPartySource({pristineRoot, installedRoot}), 'reused');
  const after = await stat(join(installedRoot, tracked), {bigint: true});
  assert.deepEqual([after.ino, after.mtimeNs, after.ctimeNs],
    [before.ino, before.mtimeNs, before.ctimeNs]);
  for (const path of nativeIdentity.generatedProtoPaths) {
    await assert.rejects(stat(join(installedRoot, path)), {code: 'ENOENT'});
  }
  await writeFile(join(installedRoot, 'quiche/quiche/quic/core/proto/unexpected.pb.cc'), 'unknown\n');
  assert.equal(await nativeIdentity.prepareThirdPartySource({pristineRoot, installedRoot}), 'replaced');
  await assert.rejects(stat(join(installedRoot, 'quiche/quiche/quic/core/proto/unexpected.pb.cc')),
    {code: 'ENOENT'});
});

for (const tamper of ['extra_file', 'changed_patch', 'changed_metadata', 'partial_patch', 'symlink']) {
  test(`native source identity rejects ${tamper} without rewriting installed files`, async t => {
    const fixture = await sourceFixture(t, patchedSources);
    switch (tamper) {
      case 'extra_file': await writeFile(join(fixture.adapterRoot, 'unknown.cc'), 'untrusted\n'); break;
      case 'changed_patch': await writeFile(join(fixture.adapterRoot, patchSources[0]), 'untrusted native patch\n'); break;
      case 'changed_metadata': await writeFile(join(fixture.adapterRoot, 'package.json'), '{"version":"9.9.9"}\n'); break;
      case 'partial_patch': await writeFile(join(fixture.adapterRoot, patchSources[1]), upstreamSources[1]); break;
      case 'symlink':
        await rm(join(fixture.adapterRoot, patchSources[0]));
        await symlink(join(fixture.pristineRoot, patchSources[0]), join(fixture.adapterRoot, patchSources[0]));
        break;
    }
    const bytesBefore = await readFile(join(fixture.adapterRoot, patchSources[1]));
    const timestampBefore = await stat(join(fixture.adapterRoot, patchSources[1]), {bigint: true});
    assert.equal(typeof nativeIdentity.prepareAdapterSource, 'function',
      'retry source verification must reject all unknown source identities');
    await assert.rejects(nativeIdentity.prepareAdapterSource(fixture), /Installed adapter source differs/);
    assert.deepEqual(await readFile(join(fixture.adapterRoot, patchSources[1])), bytesBefore);
    assert.equal((await stat(join(fixture.adapterRoot, patchSources[1]), {bigint: true})).mtimeNs,
      timestampBefore.mtimeNs);
  });
}
