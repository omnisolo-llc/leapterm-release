import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  DIRECT_WINDOWS_AGENT_IMPORTS,
  REQUIRED_LINUX_LIBS,
  REQUIRED_MACOS_DYLIBS,
  REQUIRED_WINDOWS_DLLS,
  auditLinuxAgentBundle,
  auditMacosAgentBundle,
  auditWindowsAgentBundle,
  parseCliArgs,
  parseElfDynamic,
  parseMachOImports,
  parsePeImports,
} from './verify-agent-install-e2e.mjs';

function buildSyntheticPe64(importedDlls = []) {
  const buf = Buffer.alloc(0x600, 0);
  // DOS header
  buf.writeUInt16LE(0x5a4d, 0);
  const peOff = 0x80;
  buf.writeUInt32LE(peOff, 0x3c);
  // PE signature + COFF header
  buf.writeUInt32LE(0x00004550, peOff);
  buf.writeUInt16LE(0x8664, peOff + 4); // AMD64
  buf.writeUInt16LE(1, peOff + 6); // 1 section (.idata)
  const optSize = 240;
  buf.writeUInt16LE(optSize, peOff + 20);
  // Optional header PE32+
  const optOff = peOff + 24;
  buf.writeUInt16LE(0x20b, optOff); // PE32+
  buf.writeUInt32LE(16, optOff + 108); // NumberOfRvaAndSizes
  // DataDirectory[1] = Import Table at RVA 0x1000
  const secRva = 0x1000;
  const secRawOff = 0x200;
  const secRawSize = 0x400;
  if (importedDlls.length > 0) {
    buf.writeUInt32LE(secRva, optOff + 112 + 8);
    buf.writeUInt32LE((importedDlls.length + 1) * 20, optOff + 112 + 12);
  }
  // Section header
  const secHdrOff = optOff + optSize;
  buf.write('.idata\0\0', secHdrOff, 'utf8');
  buf.writeUInt32LE(secRawSize, secHdrOff + 8); // VirtualSize
  buf.writeUInt32LE(secRva, secHdrOff + 12); // VirtualAddress
  buf.writeUInt32LE(secRawSize, secHdrOff + 16); // SizeOfRawData
  buf.writeUInt32LE(secRawOff, secHdrOff + 20); // PointerToRawData

  let strCursor = secRawOff + (importedDlls.length + 1) * 20;
  importedDlls.forEach((dllName, idx) => {
    const descOff = secRawOff + idx * 20;
    const nameRva = secRva + (strCursor - secRawOff);
    buf.writeUInt32LE(nameRva, descOff + 12); // Name RVA
    buf.writeUInt32LE(nameRva, descOff + 16); // FirstThunk
    buf.write(`${dllName}\0`, strCursor, 'utf8');
    strCursor += Buffer.byteLength(dllName, 'utf8') + 1;
  });
  return buf;
}

function buildSyntheticElf64({ needed = [], rpath = null, runpath = null, soname = null } = {}) {
  const baseVaddr = 0x400000;
  const buf = Buffer.alloc(0x500, 0);
  // ELF64 little-endian header
  buf.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1], 0);
  buf.writeUInt16LE(soname ? 3 : 2, 16); // ET_DYN or ET_EXEC
  buf.writeUInt16LE(0x3e, 18); // EM_X86_64
  buf.writeUInt32LE(1, 20);
  buf.writeBigUInt64LE(BigInt(baseVaddr + 0x400), 24);
  buf.writeBigUInt64LE(64n, 32); // e_phoff
  buf.writeUInt16LE(64, 52);
  buf.writeUInt16LE(56, 54);
  buf.writeUInt16LE(2, 56); // 2 program headers: PT_LOAD + PT_DYNAMIC

  const strtabOffset = 0x280;
  const dynOffset = 0x100;
  let strCursor = 1; // byte 0 is NUL
  const dynEntries = [[5n, BigInt(baseVaddr + strtabOffset)], [10n, 0n]];

  function addStr(str) {
    const off = strCursor;
    buf.write(`${str}\0`, strtabOffset + off, 'utf8');
    strCursor += Buffer.byteLength(str, 'utf8') + 1;
    return BigInt(off);
  }

  for (const dep of needed) {
    dynEntries.push([1n, addStr(dep)]); // DT_NEEDED
  }
  if (soname) {
    dynEntries.push([14n, addStr(soname)]); // DT_SONAME
  }
  if (rpath) {
    dynEntries.push([15n, addStr(rpath)]); // DT_RPATH
  }
  if (runpath) {
    dynEntries.push([29n, addStr(runpath)]); // DT_RUNPATH
  }
  dynEntries[1][1] = BigInt(strCursor); // DT_STRSZ
  dynEntries.push([0n, 0n]); // DT_NULL

  // Program header 0: PT_LOAD covering whole file
  buf.writeUInt32LE(1, 64); // PT_LOAD
  buf.writeUInt32LE(5, 68); // PF_R | PF_X
  buf.writeBigUInt64LE(0n, 72); // p_offset
  buf.writeBigUInt64LE(BigInt(baseVaddr), 80); // p_vaddr
  buf.writeBigUInt64LE(BigInt(baseVaddr), 88); // p_paddr
  buf.writeBigUInt64LE(BigInt(buf.length), 96); // p_filesz
  buf.writeBigUInt64LE(BigInt(buf.length), 104); // p_memsz
  buf.writeBigUInt64LE(0x1000n, 112);

  // Program header 1: PT_DYNAMIC
  const dynBytes = BigInt(dynEntries.length * 16);
  buf.writeUInt32LE(2, 120); // PT_DYNAMIC
  buf.writeUInt32LE(4, 124); // PF_R
  buf.writeBigUInt64LE(BigInt(dynOffset), 128);
  buf.writeBigUInt64LE(BigInt(baseVaddr + dynOffset), 136);
  buf.writeBigUInt64LE(BigInt(baseVaddr + dynOffset), 144);
  buf.writeBigUInt64LE(dynBytes, 152);
  buf.writeBigUInt64LE(dynBytes, 160);
  buf.writeBigUInt64LE(8n, 168);

  dynEntries.forEach(([tag, val], idx) => {
    buf.writeBigInt64LE(tag, dynOffset + idx * 16);
    buf.writeBigUInt64LE(val, dynOffset + idx * 16 + 8);
  });
  return buf;
}

function buildSyntheticMachO64({ dylibs = [], hasCodeSignature = true } = {}) {
  const commands = [];
  for (const dylib of dylibs) {
    const strBytes = Buffer.from(`${dylib}\0`, 'utf8');
    const cmdsize = Math.ceil((24 + strBytes.length) / 8) * 8;
    const cmdBuf = Buffer.alloc(cmdsize, 0);
    cmdBuf.writeUInt32LE(0x0c, 0); // LC_LOAD_DYLIB
    cmdBuf.writeUInt32LE(cmdsize, 4);
    cmdBuf.writeUInt32LE(24, 8); // name offset
    strBytes.copy(cmdBuf, 24);
    commands.push(cmdBuf);
  }
  const cmdsBeforeSigSize = commands.reduce((acc, b) => acc + b.length, 0);
  const sigDataOff = 32 + cmdsBeforeSigSize + (hasCodeSignature ? 16 : 0);
  if (hasCodeSignature) {
    const sigCmd = Buffer.alloc(16, 0);
    sigCmd.writeUInt32LE(0x1d, 0); // LC_CODE_SIGNATURE
    sigCmd.writeUInt32LE(16, 4);
    sigCmd.writeUInt32LE(sigDataOff, 8);
    sigCmd.writeUInt32LE(32, 12);
    commands.push(sigCmd);
  }
  const allCmds = Buffer.concat(commands);
  const header = Buffer.alloc(32, 0);
  header.writeUInt32LE(0xfeedfacf, 0); // MH_MAGIC_64
  header.writeUInt32LE(0x0100000c, 4); // CPU_TYPE_ARM64
  header.writeUInt32LE(2, 12); // MH_EXECUTE
  header.writeUInt32LE(commands.length, 16);
  header.writeUInt32LE(allCmds.length, 20);
  return Buffer.concat([header, allCmds, Buffer.alloc(64, 0xaa)]);
}

test('Windows PE import audit passes complete bundle and fails when libfido2-1.dll or transitive DLL is missing', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'leapterm-win-pe-audit-'));
  try {
    // Write all required Windows DLLs + transitive krb5_64.dll
    for (const dll of [...REQUIRED_WINDOWS_DLLS, 'krb5_64.dll']) {
      const transitive = dll === 'freerdp3.dll' ? ['krb5_64.dll', 'KERNEL32.dll'] : ['KERNEL32.dll'];
      fs.writeFileSync(path.join(root, dll), buildSyntheticPe64(transitive));
    }
    fs.writeFileSync(
      path.join(root, 'leap-agent.exe'),
      buildSyntheticPe64([...DIRECT_WINDOWS_AGENT_IMPORTS, 'KERNEL32.dll', 'WS2_32.dll']),
    );

    const parsed = parsePeImports(fs.readFileSync(path.join(root, 'leap-agent.exe')));
    assert.ok(parsed.imports.includes('libfido2-1.dll'));
    const ok = auditWindowsAgentBundle(root);
    assert.ok(ok.verifiedFiles >= DIRECT_WINDOWS_AGENT_IMPORTS.length + 2);

    // Removing libfido2-1.dll must fail immediately
    fs.rmSync(path.join(root, 'libfido2-1.dll'));
    assert.throws(() => auditWindowsAgentBundle(root), /missing required sibling runtime library: libfido2-1\.dll/);

    // Restore libfido2-1.dll, remove transitive krb5_64.dll -> must fail transitive closure check
    fs.writeFileSync(path.join(root, 'libfido2-1.dll'), buildSyntheticPe64(['KERNEL32.dll']));
    fs.rmSync(path.join(root, 'krb5_64.dll'));
    assert.throws(() => auditWindowsAgentBundle(root), /freerdp3\.dll -> krb5_64\.dll/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('Linux ELF dynamic audit passes complete bundle and fails when libfido2.so.1 is missing or RPATH is invalid', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'leapterm-linux-elf-audit-'));
  try {
    const libDir = path.join(root, 'lib');
    fs.mkdirSync(libDir, { recursive: true });
    for (const lib of [...REQUIRED_LINUX_LIBS, 'libcbor.so.0.10']) {
      fs.writeFileSync(
        path.join(libDir, lib),
        buildSyntheticElf64({ needed: ['libc.so.6'], rpath: '$ORIGIN', soname: lib }),
      );
    }
    fs.writeFileSync(
      path.join(root, 'leap-agent'),
      buildSyntheticElf64({
        needed: ['libfreerdp3.so.3', 'libfido2.so.1', 'libc.so.6'],
        rpath: '$ORIGIN/lib',
      }),
    );

    const parsed = parseElfDynamic(fs.readFileSync(path.join(root, 'leap-agent')));
    assert.equal(parsed.rpath, '$ORIGIN/lib');
    assert.ok(parsed.needed.includes('libfido2.so.1'));
    const ok = auditLinuxAgentBundle(root);
    assert.equal(ok.libraries, REQUIRED_LINUX_LIBS.length + 1);

    // Removing libfido2.so.1 must fail
    fs.rmSync(path.join(libDir, 'libfido2.so.1'));
    assert.throws(() => auditLinuxAgentBundle(root), /missing required runtime library: libfido2\.so\.1/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('macOS Mach-O audit passes complete bundle and fails when libfido2.1.dylib or code signature is missing', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'leapterm-macos-macho-audit-'));
  try {
    const macosDir = path.join(root, 'MacOS');
    const frameworksDir = path.join(root, 'Frameworks');
    fs.mkdirSync(macosDir, { recursive: true });
    fs.mkdirSync(frameworksDir, { recursive: true });

    for (const dylib of [...REQUIRED_MACOS_DYLIBS, 'libcbor.0.10.dylib']) {
      fs.writeFileSync(
        path.join(frameworksDir, dylib),
        buildSyntheticMachO64({ dylibs: ['/usr/lib/libSystem.B.dylib'], hasCodeSignature: true }),
      );
    }
    fs.writeFileSync(
      path.join(macosDir, 'leap-agent'),
      buildSyntheticMachO64({
        dylibs: [
          '@loader_path/../Frameworks/libfreerdp3.3.dylib',
          '@loader_path/../Frameworks/libfido2.1.dylib',
          '/usr/lib/libSystem.B.dylib',
        ],
        hasCodeSignature: true,
      }),
    );

    const parsed = parseMachOImports(fs.readFileSync(path.join(macosDir, 'leap-agent')));
    assert.equal(parsed.hasCodeSignature, true);
    assert.ok(parsed.dylibs.includes('@loader_path/../Frameworks/libfido2.1.dylib'));
    const ok = auditMacosAgentBundle(root);
    assert.equal(ok.frameworks, REQUIRED_MACOS_DYLIBS.length + 1);

    // Removing libfido2.1.dylib must fail
    fs.rmSync(path.join(frameworksDir, 'libfido2.1.dylib'));
    assert.throws(() => auditMacosAgentBundle(root), /missing required Frameworks library: libfido2\.1\.dylib/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('parseCliArgs supports --local-dir, --release-dir, --version, and --installer', () => {
  const parsed = parseCliArgs([
    '--version',
    'v0.1.3',
    '--local-dir',
    '/tmp/outputs',
    '--installer',
    '/tmp/install.sh',
  ]);
  assert.equal(parsed.version, '0.1.3');
  assert.equal(parsed.localDir, '/tmp/outputs');
  assert.equal(parsed.installerPath, '/tmp/install.sh');
});
