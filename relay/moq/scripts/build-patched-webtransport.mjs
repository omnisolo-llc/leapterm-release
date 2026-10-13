import {createHash} from 'node:crypto';
import {existsSync} from 'node:fs';
import {
  mkdir, mkdtemp, readFile, rm, writeFile,
} from 'node:fs/promises';
import {delimiter, dirname, join, resolve} from 'node:path';
import {tmpdir} from 'node:os';
import {fileURLToPath} from 'node:url';
import {nativeBuildPath, prepareAdapterSource, prepareThirdPartySource, requireLoadedAddon, treeDigest} from './native-build-identity.mjs';
import {runOwned} from './run-owned-command.mjs';

const adapterCommit = '212ef743f0cf52adb234d60d5b41c48257e967b4';
const quicheCommit = '80bf9559d3a4c08dde4b85abc46d190a88ffef64';
const adapterPackageName = '@fails-components/webtransport-transport-http3-quiche';
const adapterLockName = `node_modules/${adapterPackageName}`;
const adapterVersion = '1.6.8';
const submodules = [
  'transports/http3-quiche/third_party/boringssl/src',
  'transports/http3-quiche/third_party/abseil-cpp',
  'transports/http3-quiche/third_party/quiche',
  'transports/http3-quiche/third_party/zlib',
  'transports/http3-quiche/third_party/googleurl',
  'transports/http3-quiche/third_party/protobuf',
];
const adapterPatchSources = [
  'lib/clientsocket.js',
  'src/http3serversession.cc',
  'src/http3serversession.h',
  'src/http3wtsessionvisitor.cc',
  'src/http3wtsessionvisitor.h',
];

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function runtimeBinaryPath(adapterRoot) {
  const platformDirectory = join(adapterRoot, `build_${process.platform}_${process.arch}`);
  let buildDirectory = platformDirectory;
  if (!existsSync(buildDirectory)) buildDirectory = join(adapterRoot, 'build');
  let binaryPath = join(buildDirectory, 'Release', 'webtransport.node');
  if (process.env.NODE_ENV !== 'production' &&
      existsSync(join(buildDirectory, 'Debug', 'webtransport.node'))) {
    binaryPath = join(buildDirectory, 'Debug', 'webtransport.node');
  }
  return resolve(binaryPath);
}

async function main() {
  if (process.env.BUILDARCH && process.env.BUILDARCH !== process.arch) {
    throw new Error('Build the MoQ addon on its target architecture');
  }
  const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
  const lock = JSON.parse(await readFile(join(packageRoot, 'package-lock.json'), 'utf8'));
  const lockedAdapter = lock.packages?.[adapterLockName];
  const expectedTarball = `https://registry.npmjs.org/${adapterPackageName}/-/${adapterPackageName.split('/')[1]}-${adapterVersion}.tgz`;
  if (lockedAdapter?.version !== adapterVersion || lockedAdapter.resolved !== expectedTarball ||
      !/^sha512-[A-Za-z0-9+/]+={0,2}$/.test(lockedAdapter.integrity ?? '')) {
    throw new Error('The locked WebTransport adapter tarball pin is missing or unsupported');
  }

  const adapterEntry = fileURLToPath(import.meta.resolve(adapterPackageName));
  const adapterRoot = resolve(dirname(adapterEntry), '..');
  const adapterMetadata = JSON.parse(await readFile(join(adapterRoot, 'package.json'), 'utf8'));
  if (adapterMetadata.version !== adapterVersion) {
    throw new Error(`Unsupported WebTransport adapter version: ${adapterMetadata.version}`);
  }

  const quichePatchFile = join(packageRoot, 'patches', 'quiche-server-close-ack.patch');
  const sessionPatchFile = join(packageRoot, 'patches', 'webtransport-server-connection-close.patch');
  const clientPatchFile = join(packageRoot, 'patches', 'webtransport-client-close.patch');
  const quichePatchDigest = sha256(await readFile(quichePatchFile));
  const sessionPatchDigest = sha256(await readFile(sessionPatchFile));
  const clientPatchDigest = sha256(await readFile(clientPatchFile));
  const runtimeRelativePath = `build_${process.platform}_${process.arch}/Release/webtransport.node`;
  const runtimeBuildRoot = join(adapterRoot, `build_${process.platform}_${process.arch}`);
  const legacyBuildRoot = join(adapterRoot, 'build');
  const runtimeBinary = join(adapterRoot, runtimeRelativePath);
  const markerPath = join(runtimeBuildRoot, '.omniterm-quiche-close-ack');
  const markerPrefix = `omniterm-quiche-close-ack-v5\nnpm_tarball_integrity=${lockedAdapter.integrity}\nadapter_gitlink_parent=${adapterCommit}\nquiche_gitlink=${quicheCommit}\nquiche_patch_sha256=${quichePatchDigest}\nsession_patch_sha256=${sessionPatchDigest}\nclient_patch_sha256=${clientPatchDigest}\nruntime_binary=${runtimeRelativePath}\n`;
  const loaderSource = await readFile(join(adapterRoot, 'lib', 'index.js'), 'utf8');
  if (!loaderSource.includes("let buildpath = '../build_' + binplatform") ||
      !loaderSource.includes("if (!existsSync(path.join(dirname, buildpath))) buildpath = '../build'") ||
      !loaderSource.includes("let wtpath = buildpath + '/Release/webtransport.node'")) {
    throw new Error('Unsupported WebTransport native binary loader contract');
  }
  const inspectLoaded = async () => {
    const output = await runOwned(process.execPath, ['--input-type=module', '-e',
      "import {createRequire} from 'node:module';await import('@fails-components/webtransport-transport-http3-quiche');console.log('LOADED '+JSON.stringify(Object.keys(createRequire(import.meta.url).cache).filter(p=>p.endsWith('webtransport.node'))));"],
      {cwd: packageRoot, capture: true});
    const line = output.split('\n').find(line => line.startsWith('LOADED '));
    requireLoadedAddon(nativeBuildPath(adapterRoot), JSON.parse(line?.slice(7) ?? 'null'));
  };

  try {
    const marker = await readFile(markerPath, 'utf8');
    const [sourceDigest, quicheDigest, binaryDigest] = [
      await treeDigest(adapterRoot, {excludeBuildOutput: true}),
      await treeDigest(join(adapterRoot, 'third_party'), {ignoreGeneratedMarker: true}),
      sha256(await readFile(runtimeBinary)),
    ];
    if (!existsSync(legacyBuildRoot) && runtimeBinaryPath(adapterRoot) === resolve(runtimeBinary) &&
        marker === `${markerPrefix}adapter_source_sha256=${sourceDigest}\nquiche_tree_sha256=${quicheDigest}\nbinary_sha256=${binaryDigest}\n`) {
      await inspectLoaded();
      process.stdout.write('Verified patched WebTransport native adapter\n');
      return;
    }
  } catch {}

  if (process.argv.includes('--verify-only')) {
    throw Error('Patched native addon is absent or stale; run make moq-setup');
  }

  const tempRoot = await mkdtemp(join(tmpdir(), 'omniterm-webtransport-source-'));
  const sourceRoot = join(tempRoot, 'webtransport');
  const tarballRoot = join(tempRoot, 'adapter-tarball');
  try {
    const response = await fetch(lockedAdapter.resolved, {signal: AbortSignal.timeout(120000)});
    if (!response.ok) throw new Error(`Could not fetch pinned WebTransport tarball: ${response.status}`);
    const tarball = Buffer.from(await response.arrayBuffer());
    if (tarball.byteLength > 128 * 1024 * 1024) throw new Error('WebTransport tarball exceeds size limit');
    const actualIntegrity = `sha512-${createHash('sha512').update(tarball).digest('base64')}`;
    if (actualIntegrity !== lockedAdapter.integrity) {
      throw new Error('WebTransport tarball integrity does not match package-lock.json');
    }
    await mkdir(tarballRoot, {recursive: true});
    const tarballPath = join(tempRoot, 'webtransport-adapter.tgz');
    await writeFile(tarballPath, tarball, {mode: 0o600});
    await runOwned('tar', ['-xzf', tarballPath, '-C', tarballRoot, '--no-same-owner', '--no-same-permissions']);
    const compiledPackageRoot = join(tarballRoot, 'package');
    const compiledPackage = JSON.parse(await readFile(join(compiledPackageRoot, 'package.json'), 'utf8'));
    if (compiledPackage.version !== adapterVersion) throw new Error('Verified adapter tarball version mismatch');

    const preparedAdapter = await prepareAdapterSource({adapterRoot,
      pristineRoot: compiledPackageRoot, patchSources: adapterPatchSources,
      applyPatches: async () => {
        await runOwned('git', ['init', compiledPackageRoot]);
        await runOwned('git', ['-C', compiledPackageRoot, 'apply', '--unidiff-zero', '--check', sessionPatchFile]);
        await runOwned('git', ['-C', compiledPackageRoot, 'apply', '--unidiff-zero', sessionPatchFile]);
        await runOwned('git', ['-C', compiledPackageRoot, 'apply', '--unidiff-zero', '-p3', '--check', clientPatchFile]);
        await runOwned('git', ['-C', compiledPackageRoot, 'apply', '--unidiff-zero', '-p3', clientPatchFile]);
      }});
    if (preparedAdapter.state === 'patched') {
      process.stdout.write('Resuming exact patched adapter source without recopying\n');
    }

    await runOwned('git', ['init', sourceRoot]);
    await runOwned('git', ['-C', sourceRoot, 'remote', 'add', 'origin',
      'https://github.com/fails-components/webtransport.git']);
    await runOwned('git', ['-C', sourceRoot, 'fetch', '--depth=1', 'origin', adapterCommit]);
    await runOwned('git', ['-C', sourceRoot, 'checkout', '--detach', 'FETCH_HEAD']);
    const checkedOutAdapter = await runOwned('git', ['-C', sourceRoot, 'rev-parse', 'HEAD'],
      {capture: true});
    if (checkedOutAdapter !== adapterCommit) {
      throw new Error('WebTransport gitlink parent revision mismatch');
    }

    for (const path of submodules) {
      await runOwned('git', ['-C', sourceRoot, 'submodule', 'update', '--init', '--recursive',
        '--depth=1', '--', path]);
    }

    const quichePath = 'transports/http3-quiche/third_party/quiche';
    const gitlink = await runOwned('git', ['-C', sourceRoot, 'ls-tree', 'HEAD', '--', quichePath],
      {capture: true});
    if (!gitlink.includes(`commit ${quicheCommit}\t${quichePath}`)) {
      throw new Error('Pinned WebTransport source points to an unexpected Quiche revision');
    }
    const quicheRoot = join(sourceRoot, quichePath);
    const checkedOutQuiche = await runOwned('git', ['-C', quicheRoot, 'rev-parse', 'HEAD'],
      {capture: true});
    if (checkedOutQuiche !== quicheCommit) throw new Error('Quiche source revision mismatch');
    await runOwned('git', ['-C', quicheRoot, 'apply', '--check', quichePatchFile]);
    await runOwned('git', ['-C', quicheRoot, 'apply', quichePatchFile]);

    const preparedThirdParty = join(sourceRoot, 'transports/http3-quiche/third_party');
    const installedThirdParty = join(adapterRoot, 'third_party');
    if (await prepareThirdPartySource({pristineRoot: preparedThirdParty,
      installedRoot: installedThirdParty}) === 'reused') {
      process.stdout.write('Resuming exact patched Quiche source without recopying\n');
    }

    const patchedSourceDigest = await treeDigest(adapterRoot, {excludeBuildOutput: true});
    if (patchedSourceDigest !== preparedAdapter.expectedPatchedSourceDigest) {
      throw new Error('Installed adapter source does not match the patched tarball source');
    }

    const buildEnv = {
      ...process.env,
      CMAKE_BUILD_PARALLEL_LEVEL: process.env.CMAKE_BUILD_PARALLEL_LEVEL ?? '2',
      npm_config_build_from_source: 'true',
      NODE_PATH: [process.env.NODE_PATH, join(packageRoot, 'node_modules')].filter(Boolean).join(delimiter),
      PATH: [join(adapterRoot, 'node_modules', '.bin'),
        join(packageRoot, 'node_modules', '.bin'), process.env.PATH].filter(Boolean).join(delimiter),
    };
    // Build patched source directly; upstream install may accept a prebuilt addon.
    const buildDirectory = runtimeBuildRoot;
    try {
      const cache = await readFile(join(buildDirectory, 'CMakeCache.txt'), 'utf8');
      if (!cache.includes(`CMAKE_HOME_DIRECTORY:INTERNAL=${adapterRoot}\n`)) {
        await rm(buildDirectory, {recursive: true, force: true});
      }
    } catch (error) { if (error.code !== 'ENOENT') throw error; }

    await rm(legacyBuildRoot, {recursive: true, force: true});
    await rm(join(buildDirectory, 'Debug'), {recursive: true, force: true});
    const cmake = fileURLToPath(import.meta.resolve('cmake-js/bin/cmake-js'));
    await runOwned(process.execPath, [cmake, 'build', '--CDnapi_build_version=6',
      '--CDgtest_build_tests=OFF', '--CDCMAKE_DISABLE_FIND_PACKAGE_Python3=TRUE',
      '--CDCMAKE_DISABLE_FIND_PACKAGE_Python=TRUE', '-O', buildDirectory],
      {cwd: adapterRoot, env: buildEnv, timeout: 3600000});
    if (!(await readFile(runtimeBinary)).byteLength) {
      throw new Error('Native build produced an empty platform addon');
    }

    await rm(legacyBuildRoot, {recursive: true, force: true});
    await rm(join(runtimeBuildRoot, 'Debug'), {recursive: true, force: true});
    if (runtimeBinaryPath(adapterRoot) !== resolve(runtimeBinary)) {
      throw new Error('Installed addon is not the exact binary path selected by the runtime loader');
    }
    await inspectLoaded();
    const installedBinary = await readFile(runtimeBinary);
    const quicheDigest = await treeDigest(installedThirdParty, {ignoreGeneratedMarker: true});
    const sourceDigest = await treeDigest(adapterRoot, {excludeBuildOutput: true});
    await writeFile(markerPath, `${markerPrefix}adapter_source_sha256=${sourceDigest}\nquiche_tree_sha256=${quicheDigest}\nbinary_sha256=${sha256(installedBinary)}\n`,
      {mode: 0o644});
    process.stdout.write(`Built WebTransport with peer-confirmed server closure: ${installedBinary.byteLength} bytes\n`);
  } finally {
    await rm(tempRoot, {recursive: true, force: true});
  }
}

await main();
