#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const REQUIRED_WINDOWS_DLLS = Object.freeze([
  'libfido2-1.dll',
  'libcbor.dll',
  'libcrypto-3-x64.dll',
  'libssl-3-x64.dll',
  'freerdp3.dll',
  'freerdp-client3.dll',
  'winpr3.dll',
  'winpr-pkinit-kdc.dll',
  'winpr-pkinit-proxy.dll',
]);

export const DIRECT_WINDOWS_AGENT_IMPORTS = Object.freeze([
  'libfido2-1.dll',
  'libcbor.dll',
  'libcrypto-3-x64.dll',
  'libssl-3-x64.dll',
  'freerdp3.dll',
  'freerdp-client3.dll',
  'winpr3.dll',
]);

export const WINDOWS_SYSTEM_DLLS = new Set([
  'advapi32.dll',
  'bcrypt.dll',
  'bcryptprimitives.dll',
  'cfgmgr32.dll',
  'combase.dll',
  'credui.dll',
  'crypt32.dll',
  'cryptdll.dll',
  'd3d11.dll',
  'dbghelp.dll',
  'dnsapi.dll',
  'dwmapi.dll',
  'dxgi.dll',
  'gdi32.dll',
  'hid.dll',
  'imm32.dll',
  'iphlpapi.dll',
  'kernel32.dll',
  'mfplat.dll',
  'msvcp140.dll',
  'msvcrt.dll',
  'ncrypt.dll',
  'netapi32.dll',
  'ntdll.dll',
  'ole32.dll',
  'oleaut32.dll',
  'pdh.dll',
  'powrprof.dll',
  'propsys.dll',
  'psapi.dll',
  'rpcrt4.dll',
  'runtimeobject.dll',
  'secur32.dll',
  'setupapi.dll',
  'shcore.dll',
  'shell32.dll',
  'shlwapi.dll',
  'synchronization.dll',
  'ucrtbase.dll',
  'user32.dll',
  'userenv.dll',
  'uxtheme.dll',
  'vcruntime140.dll',
  'vcruntime140_1.dll',
  'version.dll',
  'wevtapi.dll',
  'winhttp.dll',
  'winmm.dll',
  'winscard.dll',
  'winspool.drv',
  'wintrust.dll',
  'wkscli.dll',
  'wlanapi.dll',
  'wldap32.dll',
  'ws2_32.dll',
  'wsock32.dll',
  'wtsapi32.dll',
  'xmllite.dll',
]);

export const REQUIRED_LINUX_LIBS = Object.freeze([
  'libfreerdp3.so.3',
  'libfreerdp-client3.so.3',
  'libwinpr3.so.3',
  'libfido2.so.1',
  'libssl.so.3',
  'libcrypto.so.3',
  'libgssapi_krb5.so.2',
  'libkrb5.so.3',
  'libk5crypto.so.3',
  'libkrb5support.so.0',
  'libcom_err.so.2',
  'winpr-pkinit-proxy.so',
  'winpr-pkinit-kdc.so',
]);

export const LINUX_SYSTEM_LIBS = new Set([
  'ld-linux-x86-64.so.2',
  'ld-linux-aarch64.so.1',
  'libc.so.6',
  'libm.so.6',
  'libdl.so.2',
  'libpthread.so.0',
  'librt.so.1',
  'libresolv.so.2',
  'libutil.so.1',
  'libanl.so.1',
]);

export const REQUIRED_MACOS_DYLIBS = Object.freeze([
  'libfreerdp3.3.dylib',
  'libfreerdp-client3.3.dylib',
  'libwinpr3.3.dylib',
  'libfido2.1.dylib',
  'libssl.3.dylib',
  'libcrypto.3.dylib',
  'winpr-pkinit-proxy.dylib',
  'winpr-pkinit-kdc.dylib',
]);

export function isWindowsSystemDll(name) {
  const lower = String(name || '').toLowerCase();
  return (
    WINDOWS_SYSTEM_DLLS.has(lower) ||
    lower.startsWith('api-ms-win-') ||
    lower.startsWith('ext-ms-win-')
  );
}

function readAsciiCString(buf, offset, maxLen = 512) {
  if (offset < 0 || offset >= buf.length) {
    throw new Error(`String offset ${offset} out of bounds (${buf.length})`);
  }
  const end = Math.min(buf.length, offset + maxLen);
  let idx = offset;
  while (idx < end && buf[idx] !== 0) idx += 1;
  if (idx >= end && buf[idx] !== 0) {
    throw new Error(`Unterminated string at offset ${offset}`);
  }
  return buf.subarray(offset, idx).toString('utf8');
}

export function parsePeImports(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 0x100) {
    throw new Error('Buffer is too small to be a valid PE image');
  }
  if (buf.readUInt16LE(0) !== 0x5a4d) {
    throw new Error('Invalid DOS MZ magic in PE image');
  }
  const peOffset = buf.readUInt32LE(0x3c);
  if (peOffset < 0x40 || peOffset + 24 > buf.length) {
    throw new Error('Invalid e_lfanew PE header offset');
  }
  if (buf.readUInt32LE(peOffset) !== 0x00004550) {
    throw new Error('Invalid PE\\0\\0 signature');
  }
  const machine = buf.readUInt16LE(peOffset + 4);
  const numberOfSections = buf.readUInt16LE(peOffset + 6);
  const sizeOfOptionalHeader = buf.readUInt16LE(peOffset + 20);
  const optOffset = peOffset + 24;
  if (optOffset + sizeOfOptionalHeader > buf.length) {
    throw new Error('Optional header exceeds PE image bounds');
  }
  const magic = buf.readUInt16LE(optOffset);
  const isPe32Plus = magic === 0x20b;
  const isPe32 = magic === 0x10b;
  if (!isPe32Plus && !isPe32) {
    throw new Error(`Unsupported PE optional header magic: 0x${magic.toString(16)}`);
  }
  const numRvaAndSizesOffset = optOffset + (isPe32Plus ? 108 : 92);
  const dataDirOffset = optOffset + (isPe32Plus ? 112 : 96);
  const numDataDirs = buf.readUInt32LE(numRvaAndSizesOffset);

  const sectionTableOffset = optOffset + sizeOfOptionalHeader;
  const sections = [];
  for (let i = 0; i < numberOfSections; i += 1) {
    const secOff = sectionTableOffset + i * 40;
    if (secOff + 40 > buf.length) {
      throw new Error('Section header table exceeds PE image bounds');
    }
    const virtualSize = buf.readUInt32LE(secOff + 8);
    const virtualAddress = buf.readUInt32LE(secOff + 12);
    const sizeOfRawData = buf.readUInt32LE(secOff + 16);
    const pointerToRawData = buf.readUInt32LE(secOff + 20);
    sections.push({
      virtualSize,
      virtualAddress,
      sizeOfRawData,
      pointerToRawData,
    });
  }

  function rvaToOffset(rva) {
    for (const sec of sections) {
      const span = Math.max(sec.virtualSize, sec.sizeOfRawData);
      if (rva >= sec.virtualAddress && rva < sec.virtualAddress + span) {
        const delta = rva - sec.virtualAddress;
        if (delta >= sec.sizeOfRawData) return null;
        const fileOff = sec.pointerToRawData + delta;
        return fileOff < buf.length ? fileOff : null;
      }
    }
    return null;
  }

  const imports = [];
  if (numDataDirs >= 2) {
    const importDirRva = buf.readUInt32LE(dataDirOffset + 8);
    const importDirSize = buf.readUInt32LE(dataDirOffset + 12);
    if (importDirRva !== 0 && importDirSize !== 0) {
      let descOff = rvaToOffset(importDirRva);
      if (descOff === null) {
        throw new Error(`Cannot map PE import directory RVA 0x${importDirRva.toString(16)}`);
      }
      while (descOff + 20 <= buf.length) {
        const originalFirstThunk = buf.readUInt32LE(descOff);
        const nameRva = buf.readUInt32LE(descOff + 12);
        const firstThunk = buf.readUInt32LE(descOff + 16);
        if (originalFirstThunk === 0 && nameRva === 0 && firstThunk === 0) {
          break;
        }
        const nameOff = rvaToOffset(nameRva);
        if (nameOff === null) {
          throw new Error(`Cannot map imported DLL name RVA 0x${nameRva.toString(16)}`);
        }
        const dllName = readAsciiCString(buf, nameOff, 260);
        imports.push(dllName);
        descOff += 20;
      }
    }
  }

  return {
    machine,
    isPe32Plus,
    imports,
  };
}

export function auditWindowsAgentBundle(bundleDir) {
  const exePath = path.join(bundleDir, 'leap-agent.exe');
  if (!fs.existsSync(exePath) || !fs.statSync(exePath).isFile()) {
    throw new Error(`Windows bundle is missing leap-agent.exe in ${bundleDir}`);
  }
  const entries = fs.readdirSync(bundleDir);
  const filesByLower = new Map();
  for (const entry of entries) {
    const full = path.join(bundleDir, entry);
    const st = fs.lstatSync(full);
    if (st.isSymbolicLink()) {
      throw new Error(`Windows bundle contains unsupported symbolic link: ${entry}`);
    }
    if (st.isFile()) {
      if (st.size === 0) {
        throw new Error(`Windows bundle contains empty file: ${entry}`);
      }
      filesByLower.set(entry.toLowerCase(), entry);
    }
  }

  for (const requiredDll of REQUIRED_WINDOWS_DLLS) {
    if (!filesByLower.has(requiredDll.toLowerCase())) {
      throw new Error(
        `Windows bundle is missing required sibling runtime library: ${requiredDll}`,
      );
    }
  }

  const exeInfo = parsePeImports(fs.readFileSync(exePath));
  if (!exeInfo.isPe32Plus || (exeInfo.machine !== 0x8664 && exeInfo.machine !== 0xaa64)) {
    throw new Error(`leap-agent.exe is not a 64-bit PE32+ executable (machine=0x${exeInfo.machine.toString(16)})`);
  }
  const directLower = new Set(exeInfo.imports.map((d) => d.toLowerCase()));
  for (const directRequired of DIRECT_WINDOWS_AGENT_IMPORTS) {
    if (!directLower.has(directRequired.toLowerCase())) {
      throw new Error(
        `leap-agent.exe PE import table is missing expected direct import: ${directRequired}`,
      );
    }
  }

  // Walk transitive PE import closure across leap-agent.exe and all bundled DLLs
  const queue = ['leap-agent.exe'];
  const visited = new Set();
  const missingClosure = [];

  while (queue.length > 0) {
    const current = queue.shift();
    const currentLower = current.toLowerCase();
    if (visited.has(currentLower)) continue;
    visited.add(currentLower);

    const actualName = filesByLower.get(currentLower);
    if (!actualName) continue;
    const fullPath = path.join(bundleDir, actualName);
    const pe = parsePeImports(fs.readFileSync(fullPath));
    for (const importedDll of pe.imports) {
      const importedLower = importedDll.toLowerCase();
      if (isWindowsSystemDll(importedLower)) continue;
      if (!filesByLower.has(importedLower)) {
        missingClosure.push(`${actualName} -> ${importedDll}`);
      } else if (!visited.has(importedLower)) {
        queue.push(filesByLower.get(importedLower));
      }
    }
  }

  if (missingClosure.length > 0) {
    throw new Error(
      `Windows bundle has unresolved non-system PE DLL imports: ${missingClosure.join(', ')}`,
    );
  }

  return {
    executable: exePath,
    directImports: exeInfo.imports,
    verifiedFiles: visited.size,
  };
}

export function parseElfDynamic(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 64) {
    throw new Error('Buffer is too small to be an ELF64 image');
  }
  if (
    buf[0] !== 0x7f ||
    buf[1] !== 0x45 ||
    buf[2] !== 0x4c ||
    buf[3] !== 0x46 ||
    buf[4] !== 2 ||
    buf[5] !== 1
  ) {
    throw new Error('Invalid ELF64 little-endian header');
  }
  const machine = buf.readUInt16LE(18);
  const phoff = Number(buf.readBigUInt64LE(32));
  const phentsize = buf.readUInt16LE(54);
  const phnum = buf.readUInt16LE(56);
  const loads = [];
  let dynOff = 0;
  let dynSize = 0;

  for (let i = 0; i < phnum; i += 1) {
    const off = phoff + i * phentsize;
    if (off + phentsize > buf.length) {
      throw new Error('ELF program header exceeds file bounds');
    }
    const pType = buf.readUInt32LE(off);
    const pOffset = Number(buf.readBigUInt64LE(off + 8));
    const pVaddr = Number(buf.readBigUInt64LE(off + 16));
    const pFilesz = Number(buf.readBigUInt64LE(off + 32));
    if (pType === 1) {
      loads.push({ pOffset, pVaddr, pFilesz });
    } else if (pType === 2) {
      dynOff = pOffset;
      dynSize = pFilesz;
    }
  }

  function vaddrToOffset(vaddr) {
    for (const seg of loads) {
      if (vaddr >= seg.pVaddr && vaddr < seg.pVaddr + seg.pFilesz) {
        return seg.pOffset + (vaddr - seg.pVaddr);
      }
    }
    return null;
  }

  const needed = [];
  let rpath = null;
  let runpath = null;
  let soname = null;

  if (dynOff > 0 && dynSize >= 16) {
    const entries = [];
    let strtabVaddr = null;
    for (let pos = dynOff; pos + 16 <= dynOff + dynSize && pos + 16 <= buf.length; pos += 16) {
      const tag = Number(buf.readBigInt64LE(pos));
      const val = Number(buf.readBigUInt64LE(pos + 8));
      if (tag === 0) break;
      entries.push({ tag, val });
      if (tag === 5) strtabVaddr = val;
    }
    if (strtabVaddr !== null) {
      const strtabOff = vaddrToOffset(strtabVaddr);
      if (strtabOff === null) {
        throw new Error('Cannot resolve ELF DT_STRTAB virtual address');
      }
      for (const entry of entries) {
        if (entry.tag === 1) {
          needed.push(readAsciiCString(buf, strtabOff + entry.val));
        } else if (entry.tag === 14) {
          soname = readAsciiCString(buf, strtabOff + entry.val);
        } else if (entry.tag === 15) {
          rpath = readAsciiCString(buf, strtabOff + entry.val);
        } else if (entry.tag === 29) {
          runpath = readAsciiCString(buf, strtabOff + entry.val);
        }
      }
    }
  }

  return { machine, needed, rpath, runpath, soname };
}

export function auditLinuxAgentBundle(bundleDir) {
  const agentPath = path.join(bundleDir, 'leap-agent');
  const libDir = path.join(bundleDir, 'lib');
  if (!fs.existsSync(agentPath) || !fs.statSync(agentPath).isFile()) {
    throw new Error(`Linux bundle is missing leap-agent in ${bundleDir}`);
  }
  if (!fs.existsSync(libDir) || !fs.statSync(libDir).isDirectory()) {
    throw new Error(`Linux bundle is missing lib/ directory in ${bundleDir}`);
  }

  const libFiles = new Set(fs.readdirSync(libDir).filter((f) => fs.statSync(path.join(libDir, f)).isFile()));
  for (const req of REQUIRED_LINUX_LIBS) {
    if (!libFiles.has(req)) {
      throw new Error(`Linux bundle is missing required runtime library: ${req}`);
    }
  }
  if (!libFiles.has('libcbor.so.0.10') && !libFiles.has('libcbor.so.0.8')) {
    throw new Error('Linux bundle is missing required runtime library: libcbor.so.0.10 or libcbor.so.0.8');
  }

  const agentElf = parseElfDynamic(fs.readFileSync(agentPath));
  if (agentElf.runpath !== null) {
    throw new Error(`Linux leap-agent must use DT_RPATH, not DT_RUNPATH (${agentElf.runpath})`);
  }
  if (agentElf.rpath !== '$ORIGIN/lib') {
    throw new Error(`Linux leap-agent must have DT_RPATH=$ORIGIN/lib, got ${agentElf.rpath}`);
  }
  if (!agentElf.needed.includes('libfido2.so.1')) {
    throw new Error('Linux leap-agent DT_NEEDED is missing libfido2.so.1');
  }

  const imagesToCheck = [
    { name: 'leap-agent', filePath: agentPath, expectedRpath: '$ORIGIN/lib' },
  ];
  const runnerPath = path.join(bundleDir, 'leapterm-command-runner');
  if (fs.existsSync(runnerPath)) {
    imagesToCheck.push({ name: 'leapterm-command-runner', filePath: runnerPath, expectedRpath: '$ORIGIN/lib' });
  }
  for (const libName of libFiles) {
    imagesToCheck.push({ name: `lib/${libName}`, filePath: path.join(libDir, libName), expectedRpath: '$ORIGIN' });
  }

  const missingNeeded = [];
  for (const img of imagesToCheck) {
    const info = parseElfDynamic(fs.readFileSync(img.filePath));
    if (info.runpath !== null) {
      throw new Error(`${img.name} has forbidden DT_RUNPATH: ${info.runpath}`);
    }
    if (info.rpath !== img.expectedRpath) {
      throw new Error(`${img.name} has unexpected DT_RPATH: ${info.rpath} (expected ${img.expectedRpath})`);
    }
    for (const dep of info.needed) {
      if (LINUX_SYSTEM_LIBS.has(dep)) continue;
      if (!libFiles.has(dep)) {
        missingNeeded.push(`${img.name} -> ${dep}`);
      }
    }
  }

  if (missingNeeded.length > 0) {
    throw new Error(`Linux bundle has unresolved DT_NEEDED imports: ${missingNeeded.join(', ')}`);
  }

  return {
    executable: agentPath,
    libraries: libFiles.size,
  };
}

export function parseMachOImports(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 32) {
    throw new Error('Buffer is too small to be a Mach-O64 image');
  }
  const magic = buf.readUInt32LE(0);
  if (magic !== 0xfeedfacf) {
    throw new Error(`Invalid Mach-O64 little-endian magic: 0x${magic.toString(16)}`);
  }
  const cputype = buf.readUInt32LE(4);
  const ncmds = buf.readUInt32LE(16);
  const sizeofcmds = buf.readUInt32LE(20);
  if (32 + sizeofcmds > buf.length) {
    throw new Error('Mach-O load commands exceed buffer bounds');
  }

  const dylibs = [];
  const rpaths = [];
  let hasCodeSignature = false;
  let offset = 32;

  for (let i = 0; i < ncmds; i += 1) {
    if (offset + 8 > 32 + sizeofcmds) {
      throw new Error('Truncated Mach-O load command');
    }
    const cmd = buf.readUInt32LE(offset);
    const cmdsize = buf.readUInt32LE(offset + 4);
    if (cmdsize < 8 || offset + cmdsize > 32 + sizeofcmds) {
      throw new Error('Invalid Mach-O load command size');
    }
    // LC_LOAD_DYLIB (0xc), LC_LOAD_WEAK_DYLIB (0x80000018), LC_REEXPORT_DYLIB (0x8000001f)
    if (cmd === 0x0c || cmd === 0x80000018 || cmd === 0x8000001f) {
      const strOffset = buf.readUInt32LE(offset + 8);
      if (strOffset < cmdsize) {
        dylibs.push(readAsciiCString(buf, offset + strOffset, cmdsize - strOffset));
      }
    } else if (cmd === 0x8000001c) {
      // LC_RPATH
      const strOffset = buf.readUInt32LE(offset + 8);
      if (strOffset < cmdsize) {
        rpaths.push(readAsciiCString(buf, offset + strOffset, cmdsize - strOffset));
      }
    } else if (cmd === 0x1d) {
      // LC_CODE_SIGNATURE
      const dataoff = buf.readUInt32LE(offset + 8);
      const datasize = buf.readUInt32LE(offset + 12);
      if (datasize > 0 && dataoff + datasize <= buf.length) {
        hasCodeSignature = true;
      }
    }
    offset += cmdsize;
  }

  return { cputype, dylibs, rpaths, hasCodeSignature };
}

export function auditMacosAgentBundle(contentsDir) {
  const agentPath = path.join(contentsDir, 'MacOS', 'leap-agent');
  const frameworksDir = path.join(contentsDir, 'Frameworks');
  if (!fs.existsSync(agentPath) || !fs.statSync(agentPath).isFile()) {
    throw new Error(`macOS bundle is missing MacOS/leap-agent in ${contentsDir}`);
  }
  if (!fs.existsSync(frameworksDir) || !fs.statSync(frameworksDir).isDirectory()) {
    throw new Error(`macOS bundle is missing Frameworks/ directory in ${contentsDir}`);
  }

  const dylibFiles = new Set(
    fs.readdirSync(frameworksDir).filter((f) => fs.statSync(path.join(frameworksDir, f)).isFile()),
  );
  for (const req of REQUIRED_MACOS_DYLIBS) {
    if (!dylibFiles.has(req)) {
      throw new Error(`macOS bundle is missing required Frameworks library: ${req}`);
    }
  }
  if (![...dylibFiles].some((f) => /^libcbor(?:\.[0-9]+)*\.dylib$/.test(f))) {
    throw new Error('macOS bundle is missing required Frameworks library: libcbor*.dylib');
  }

  const agentMach = parseMachOImports(fs.readFileSync(agentPath));
  if (!agentMach.hasCodeSignature) {
    throw new Error('macOS MacOS/leap-agent is missing LC_CODE_SIGNATURE');
  }
  if (!agentMach.dylibs.some((d) => d.endsWith('/libfido2.1.dylib'))) {
    throw new Error('macOS MacOS/leap-agent Mach-O imports are missing libfido2.1.dylib');
  }

  const images = [{ name: 'MacOS/leap-agent', filePath: agentPath, isExec: true }];
  const runnerPath = path.join(contentsDir, 'MacOS', 'leapterm-command-runner');
  if (fs.existsSync(runnerPath)) {
    images.push({ name: 'MacOS/leapterm-command-runner', filePath: runnerPath, isExec: true });
  }
  for (const dylib of dylibFiles) {
    images.push({
      name: `Frameworks/${dylib}`,
      filePath: path.join(frameworksDir, dylib),
      isExec: false,
    });
  }

  const missingImports = [];
  for (const img of images) {
    const info = parseMachOImports(fs.readFileSync(img.filePath));
    for (const dep of info.dylibs) {
      if (dep.startsWith('/usr/lib/') || dep.startsWith('/System/Library/')) {
        continue;
      }
      const prefix = img.isExec ? '@loader_path/../Frameworks/' : '@loader_path/';
      const altPrefix = '@loader_path/../Frameworks/';
      let targetName = null;
      if (dep.startsWith(prefix)) {
        targetName = dep.slice(prefix.length);
      } else if (dep.startsWith(altPrefix)) {
        targetName = dep.slice(altPrefix.length);
      }
      if (!targetName || !dylibFiles.has(targetName)) {
        missingImports.push(`${img.name} -> ${dep}`);
      }
    }
  }

  if (missingImports.length > 0) {
    throw new Error(`macOS bundle has unresolved Mach-O dylib imports: ${missingImports.join(', ')}`);
  }

  return {
    executable: agentPath,
    frameworks: dylibFiles.size,
  };
}

export function redactSensitiveCommandOutput(value) {
  let text = String(value ?? '');
  for (const envKey of [
    'PRIVATE_RELEASE_TOKEN',
    'GH_TOKEN',
    'GITHUB_TOKEN',
    'CLOUDFLARE_API_TOKEN',
    'SOURCE_REPOSITORY',
  ]) {
    const secretVal = String(process.env[envKey] || '').trim();
    if (secretVal && secretVal.length >= 4) {
      text = text.split(secretVal).join('[redacted]');
    }
  }
  const publicOrg = 'omnisolo-llc';
  const publicRepoName = 'leapterm-release';
  const privateRepoPattern = new RegExp(
    `(?:${publicOrg}\\/(?!${publicRepoName}\\b)|example-org\\/private-)[A-Za-z0-9._/-]+`,
    'gi',
  );
  return text
    .replace(
      /\b(?:gh[pousr]_[A-Za-z0-9_]+|github_pat_[A-Za-z0-9_]+)\b/g,
      '[redacted-token]',
    )
    .replace(/x-access-token:[^\s@"']+/gi, 'x-access-token:[redacted]')
    .replace(/Bearer\s+[A-Za-z0-9._-]+/gi, 'Bearer [redacted]')
    .replace(privateRepoPattern, '[redacted-repo]')
    .replace(/\bcloud\/deploy\/[A-Za-z0-9._/-]*/g, '[redacted-path]')
    .replace(/\/(?:home|Users)\/[^\s:'"]+/g, '[redacted-host-path]')
    .replace(/[A-Za-z]:\\Users\\[^\s:'"]+/g, '[redacted-host-path]');
}

function runCommandChecked(cmd, args, options = {}) {
  const isWinBatch = process.platform === 'win32' && /\.(cmd|bat)$/i.test(cmd);
  const execCmd = isWinBatch ? (process.env.ComSpec || 'cmd.exe') : cmd;
  const execArgs = isWinBatch ? ['/d', '/s', '/c', cmd, ...args] : args;
  const res = spawnSync(execCmd, execArgs, { encoding: 'utf8', ...options });
  if (res.status !== 0) {
    const safeArgs = args.map((a) => redactSensitiveCommandOutput(a)).join(' ');
    const safeStdout = redactSensitiveCommandOutput(res.stdout);
    const safeStderr = redactSensitiveCommandOutput(res.stderr);
    throw new Error(
      `Command failed (${cmd} ${safeArgs}): status=${res.status}\nstdout=${safeStdout}\nstderr=${safeStderr}`,
    );
  }
  return res;
}

function opensslExecutable() {
  if (process.platform === 'win32') {
    const candidates = [
      path.join(process.env.ProgramFiles || 'C:\\Program Files', 'Git', 'usr', 'bin', 'openssl.exe'),
      path.join(process.env.ProgramFiles || 'C:\\Program Files', 'OpenSSL-Win64', 'bin', 'openssl.exe'),
    ];
    for (const candidate of candidates) {
      if (fs.existsSync(candidate)) {
        return candidate;
      }
    }
  }
  return 'openssl';
}

function tarExecutable() {
  if (process.platform === 'win32') {
    const sysTar = path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'tar.exe');
    if (fs.existsSync(sysTar)) {
      return sysTar;
    }
  }
  return 'tar';
}

function extractZipArchive(zipPath, destDir, includePatterns = []) {
  if (process.platform === 'win32') {
    runCommandChecked(tarExecutable(), ['-xf', zipPath, '-C', destDir, ...includePatterns]);
  } else {
    runCommandChecked('unzip', ['-q', zipPath, '-d', destDir]);
  }
}

export function extractReleaseArchivesAndAuditAllPlatforms({ releaseDir, version }) {
  const workRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'leapterm-agent-audit-'));
  try {
    const results = {};

    // 1. Audit Windows archive (leapterm-<version>-windows-x64.zip)
    const winZip = path.join(releaseDir, `leapterm-${version}-windows-x64.zip`);
    if (!fs.existsSync(winZip)) {
      throw new Error(`Missing Windows release archive: ${winZip}`);
    }
    const winExtractDir = path.join(workRoot, 'windows');
    fs.mkdirSync(winExtractDir, { recursive: true });
    extractZipArchive(winZip, winExtractDir);
    results.windows = auditWindowsAgentBundle(winExtractDir);

    // 2. Audit macOS archive (leapterm-<version>-macos-arm64.zip)
    const macZip = path.join(releaseDir, `leapterm-${version}-macos-arm64.zip`);
    if (!fs.existsSync(macZip)) {
      throw new Error(`Missing macOS release archive: ${macZip}`);
    }
    const macExtractDir = path.join(workRoot, 'macos');
    fs.mkdirSync(macExtractDir, { recursive: true });
    extractZipArchive(macZip, macExtractDir, [
      '*/Contents/MacOS/*',
      '*/Contents/Frameworks/*.dylib',
    ]);
    const macContents = [
      path.join(macExtractDir, 'leapterm.app', 'Contents'),
      path.join(macExtractDir, 'LeapTerm.app', 'Contents'),
      path.join(macExtractDir, 'Contents'),
    ].find((p) => fs.existsSync(p));
    if (!macContents) {
      throw new Error(`Missing .app/Contents in macOS archive: ${macZip}`);
    }
    results.macos = auditMacosAgentBundle(macContents);

    // 3. Audit Linux .deb archive (leapterm-<version>-agent-linux-amd64.deb)
    const linuxDeb = path.join(releaseDir, `leapterm-${version}-agent-linux-amd64.deb`);
    if (!fs.existsSync(linuxDeb)) {
      throw new Error(`Missing Linux Debian package: ${linuxDeb}`);
    }
    const debExtractDir = path.join(workRoot, 'linux-deb');
    fs.mkdirSync(debExtractDir, { recursive: true });
    const dataTarPath = path.join(debExtractDir, 'data.tar');
    const dpkgDebCheck = spawnSync('dpkg-deb', ['--version'], { encoding: 'utf8' });
    if (dpkgDebCheck.status === 0) {
      const fsys = spawnSync('dpkg-deb', ['--fsys-tarfile', linuxDeb], {
        maxBuffer: 256 * 1024 * 1024,
      });
      if (fsys.status !== 0) {
        throw new Error(
          `dpkg-deb --fsys-tarfile failed: ${redactSensitiveCommandOutput(fsys.stderr?.toString())}`,
        );
      }
      fs.writeFileSync(dataTarPath, fsys.stdout);
    } else if (process.platform === 'win32') {
      runCommandChecked(tarExecutable(), ['-xf', linuxDeb, '-C', debExtractDir]);
      const dataFile = fs.readdirSync(debExtractDir).find((f) => f.startsWith('data.tar'));
      if (!dataFile) {
        throw new Error(`No data.tar* member in ${linuxDeb}`);
      }
      runCommandChecked(tarExecutable(), ['-xf', path.join(debExtractDir, dataFile), '-C', debExtractDir]);
    } else {
      const arMembers = runCommandChecked('ar', ['t', linuxDeb]).stdout.trim().split(/\r?\n/);
      const dataMember = arMembers.find((m) => m.startsWith('data.tar'));
      if (!dataMember) {
        throw new Error(`No data.tar* member in ${linuxDeb}`);
      }
      const rawData = spawnSync('ar', ['p', linuxDeb, dataMember], {
        maxBuffer: 256 * 1024 * 1024,
      });
      if (rawData.status !== 0) {
        throw new Error(`ar p failed on ${linuxDeb}`);
      }
      const rawPath = `${dataTarPath}.${dataMember.split('.').pop()}`;
      fs.writeFileSync(rawPath, rawData.stdout);
      runCommandChecked(tarExecutable(), ['-xf', rawPath, '-C', debExtractDir]);
    }
    if (fs.existsSync(dataTarPath)) {
      runCommandChecked(tarExecutable(), ['-xf', dataTarPath, '-C', debExtractDir]);
    }
    const linuxNativeRoot = path.join(debExtractDir, 'usr', 'libexec', 'leapterm');
    results.linux = auditLinuxAgentBundle(linuxNativeRoot);

    return results;
  } finally {
    fs.rmSync(workRoot, { recursive: true, force: true });
  }
}

export function buildIsolatedHomeEnv(baseEnv, homeDir) {
  const appData = path.join(homeDir, 'AppData', 'Roaming');
  const localAppData = path.join(homeDir, 'AppData', 'Local');
  const xdgConfig = path.join(homeDir, '.config');
  const xdgState = path.join(homeDir, '.local', 'state');
  const logDir = path.join(xdgState, 'leap-agent', 'logs');
  for (const dir of [homeDir, appData, localAppData, xdgConfig, xdgState, logDir]) {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  }
  const env = {
    ...baseEnv,
    HOME: homeDir,
    USERPROFILE: homeDir,
    APPDATA: appData,
    LOCALAPPDATA: localAppData,
    XDG_CONFIG_HOME: xdgConfig,
    XDG_STATE_HOME: xdgState,
    CONNECTOR_DIAGNOSTIC_LOG_UPLOAD: 'false',
    LEAP_AGENT_SKIP_AUTORUN: '1',
  };
  if (process.platform !== 'win32') {
    env.CONNECTOR_AGENT_LOG_DIR = logDir;
    env.PATH = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin';
  }
  return env;
}

export function locateEnrolledAgentEnv(homeDir) {
  const candidates = [
    path.join(homeDir, '.config', 'leapterm', 'agent.env'),
    path.join(homeDir, 'AppData', 'Roaming', 'LeapTerm', 'agent.env'),
    path.join(homeDir, 'Library', 'Application Support', 'LeapTerm', 'agent.env'),
  ];
  return candidates.find((p) => fs.existsSync(p)) || candidates[0];
}

export function verifyLiveAgentLifecycleAndZeroSshJoin({ agentBin, baseEnv, workRoot }) {
  const helpOut = runCommandChecked(agentBin, ['--help'], { env: baseEnv }).stdout;
  const statusHelp = spawnSync(agentBin, ['status', '--help'], {
    env: baseEnv,
    encoding: 'utf8',
  });
  if (
    !helpOut.includes('self-install') ||
    statusHelp.status !== 0 ||
    !String(statusHelp.stdout || '').includes('--json')
  ) {
    return {
      skipped: true,
      reason: 'binary predates status --json and self-install subcommands',
    };
  }

  // 1. Verify self-install -> self-uninstall -> self-install lifecycle
  if (process.platform === 'win32') {
    const lifecycleHome = path.join(workRoot, 'win-lifecycle-home');
    const lifecycleInstallDir = path.join(workRoot, 'win-self-install-dir');
    fs.mkdirSync(lifecycleInstallDir, { recursive: true });
    const lifecycleEnv = buildIsolatedHomeEnv(baseEnv, lifecycleHome);

    runCommandChecked(
      agentBin,
      ['self-install', '--user', '--force', '--install-dir', lifecycleInstallDir],
      { env: lifecycleEnv },
    );
    const installedExe = path.join(lifecycleInstallDir, 'leap-agent.exe');
    const receiptPath = path.join(lifecycleInstallDir, 'leap-agent.receipt.json');
    if (!fs.existsSync(installedExe) || !fs.existsSync(receiptPath)) {
      throw new Error('Windows self-install did not produce leap-agent.exe and leap-agent.receipt.json');
    }
    if (fs.existsSync(path.join(path.dirname(agentBin), 'libfido2-1.dll'))) {
      auditWindowsAgentBundle(lifecycleInstallDir);
    }

    runCommandChecked(
      installedExe,
      ['self-uninstall', '--user', '--purge', '--install-dir', lifecycleInstallDir],
      { env: lifecycleEnv },
    );
    if (fs.existsSync(installedExe) || fs.existsSync(receiptPath)) {
      throw new Error('Windows self-uninstall --purge did not remove leap-agent.exe and receipt');
    }

    runCommandChecked(
      agentBin,
      ['self-install', '--user', '--force', '--install-dir', lifecycleInstallDir],
      { env: lifecycleEnv },
    );
    if (!fs.existsSync(installedExe) || !fs.existsSync(receiptPath)) {
      throw new Error('Windows reinstall via self-install failed');
    }
  } else {
    runCommandChecked(agentBin, ['self-install', '--help'], { env: baseEnv });
    runCommandChecked(agentBin, ['self-uninstall', '--help'], { env: baseEnv });
  }

  // 2. Verify pre-enrollment `leap-agent status --json` in a fresh home without .ssh
  const flagHome = path.join(workRoot, 'zero-ssh-flag-home');
  const flagEnv = buildIsolatedHomeEnv(baseEnv, flagHome);
  if (fs.existsSync(path.join(flagHome, '.ssh'))) {
    throw new Error('Isolated flagHome unexpectedly contained .ssh before join');
  }
  const preStatusRaw = runCommandChecked(agentBin, ['status', '--json'], {
    env: {
      ...flagEnv,
      CONNECTOR_ENVIRONMENT_FILE: path.join(flagHome, 'missing-agent.env'),
    },
  }).stdout;
  const preStatus = JSON.parse(preStatusRaw);
  if (preStatus.enrolled !== false) {
    throw new Error(`Expected pre-join status enrolled=false, got: ${preStatusRaw}`);
  }

  // 3. Verify token-only zero-SSH `leap-agent join --token <TOKEN>` and positional `leap-agent join <TOKEN>`
  const opensslCheck = spawnSync(opensslExecutable(), ['version'], { encoding: 'utf8' });
  if (opensslCheck.status !== 0) {
    return {
      selfInstallVerified: true,
      preStatusVerified: true,
      zeroSshJoinSkipped: 'openssl unavailable on host',
    };
  }
  const tlsDir = path.join(workRoot, 'zero-ssh-tls');
  fs.mkdirSync(tlsDir, { recursive: true, mode: 0o700 });
  const keyPath = path.join(tlsDir, 'key.pem');
  const certPath = path.join(tlsDir, 'cert.pem');
  const opensslCnf = path.join(tlsDir, 'openssl.cnf');
  fs.writeFileSync(
    opensslCnf,
    [
      '[req]',
      'distinguished_name = dn',
      'x509_extensions = v3_ext',
      'prompt = no',
      '[dn]',
      'CN = 127.0.0.1',
      '[v3_ext]',
      'subjectAltName = IP:127.0.0.1,DNS:localhost',
      '',
    ].join('\n'),
    'utf8',
  );
  runCommandChecked(opensslExecutable(), [
    'req',
    '-x509',
    '-newkey',
    'ec',
    '-pkeyopt',
    'ec_paramgen_curve:prime256v1',
    '-nodes',
    '-keyout',
    keyPath,
    '-out',
    certPath,
    '-days',
    '1',
    '-config',
    opensslCnf,
    '-extensions',
    'v3_ext',
  ]);

  const posHome = path.join(workRoot, 'zero-ssh-pos-home');
  const posEnv = buildIsolatedHomeEnv(baseEnv, posHome);
  const runnerScript = path.join(tlsDir, 'run-zero-ssh-join.mjs');
  fs.writeFileSync(
    runnerScript,
    `import { spawn } from 'node:child_process';
import fs from 'node:fs';
import https from 'node:https';

const [agentBin, keyPath, certPath, flagEnvJson, posEnvJson] = process.argv.slice(2);
const flagEnv = JSON.parse(flagEnvJson);
const posEnv = JSON.parse(posEnvJson);
const key = fs.readFileSync(keyPath);
const cert = fs.readFileSync(certPath);
const requests = [];

function spawnAsync(cmd, args, options) {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, { ...options, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => { stdout += d.toString(); });
    child.stderr.on('data', (d) => { stderr += d.toString(); });
    child.on('error', reject);
    child.on('close', (code) => {
      resolve({ status: code, stdout, stderr });
    });
  });
}

const server = https.createServer({ key, cert }, (req, res) => {
  let body = '';
  req.on('data', (chunk) => { body += chunk; });
  req.on('end', () => {
    const parsed = JSON.parse(body || '{}');
    requests.push({ url: req.url, method: req.method, body: parsed });
    const suffix = parsed.pairing_token === 'ptk_vm_e2e_pos_token' ? 'pos' : 'flag';
    const port = server.address().port;
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({
      status: 'paired',
      connector_id: \`conn-vm-e2e-\${suffix}\`,
      target_id: \`host-vm-e2e-\${suffix}\`,
      tenant_id: 'tenant-vm-e2e',
      endpoint: \`wss://127.0.0.1:\${port}/v1/connectors/stream\`,
    }));
  });
});

server.listen(0, '127.0.0.1', async () => {
  const port = server.address().port;
  const origin = \`https://127.0.0.1:\${port}\`;
  try {
    for (const [envObj, args] of [
      [flagEnv, ['join', '--token', 'ptk_vm_e2e_flag_token', '--ca-cert', certPath]],
      [posEnv, ['join', 'ptk_vm_e2e_pos_token', '--ca-cert', certPath]],
    ]) {
      const res = await spawnAsync(agentBin, args, {
        env: {
          ...envObj,
          LEAPTERM_API_ORIGIN: origin,
          CONNECTOR_CA_CERT: certPath,
          SSL_CERT_FILE: certPath,
          CURL_CA_BUNDLE: certPath,
        },
      });
      if (res.status !== 0) {
        console.error(res.stdout || '');
        console.error(res.stderr || '');
        process.exit(res.status || 1);
      }
    }
    if (requests.length !== 2) {
      console.error('Expected 2 pairing requests, got ' + requests.length);
      process.exit(1);
    }
  } finally {
    server.close();
  }
});
`,
    'utf8',
  );

  runCommandChecked(process.execPath, [
    runnerScript,
    agentBin,
    keyPath,
    certPath,
    JSON.stringify(flagEnv),
    JSON.stringify(posEnv),
  ]);

  for (const [label, home] of [
    ['flag', flagHome],
    ['positional', posHome],
  ]) {
    for (const sshFile of ['id_ed25519', 'id_ed25519.pub', 'authorized_keys']) {
      const full = path.join(home, '.ssh', sshFile);
      if (!fs.existsSync(full) || !fs.statSync(full).isFile()) {
        throw new Error(`Zero-SSH ${label} join did not auto-generate ${full}`);
      }
    }
  }

  const flagAgentEnv = locateEnrolledAgentEnv(flagHome);
  if (!fs.existsSync(flagAgentEnv)) {
    throw new Error(`Zero-SSH flag join did not write agent.env at ${flagAgentEnv}`);
  }
  const posAgentEnv = locateEnrolledAgentEnv(posHome);
  if (!fs.existsSync(posAgentEnv)) {
    throw new Error(`Zero-SSH positional join did not write agent.env at ${posAgentEnv}`);
  }

  // 4. Verify post-enrollment `leap-agent status --json` and human-readable `leap-agent status`
  const postStatusRaw = runCommandChecked(agentBin, ['status', '--json'], {
    env: {
      ...flagEnv,
      CONNECTOR_ENVIRONMENT_FILE: flagAgentEnv,
    },
  }).stdout;
  const postStatus = JSON.parse(postStatusRaw);
  if (
    postStatus.enrolled !== true ||
    postStatus.connector_id !== 'conn-vm-e2e-flag' ||
    postStatus.tenant_id !== 'tenant-vm-e2e' ||
    !Array.isArray(postStatus.configured_targets) ||
    postStatus.configured_targets.length === 0
  ) {
    throw new Error(`Unexpected post-join status --json output: ${postStatusRaw}`);
  }

  const humanStatus = runCommandChecked(agentBin, ['status'], {
    env: {
      ...flagEnv,
      CONNECTOR_ENVIRONMENT_FILE: flagAgentEnv,
    },
  }).stdout;
  if (!humanStatus.includes('Enrollment State: Enrolled') || !humanStatus.includes('conn-vm-e2e-flag')) {
    throw new Error(`Unexpected human-readable status output: ${humanStatus}`);
  }

  return {
    selfInstallVerified: true,
    zeroSshFlagJoinVerified: true,
    zeroSshPositionalJoinVerified: true,
    statusJsonVerified: true,
  };
}

export function verifyCurrentHostLiveInstall({ releaseDir, version, installerPath }) {
  const workRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'leapterm-live-install-'));
  try {
    const homeDir = path.join(workRoot, 'home');
    const localBin = path.join(homeDir, '.local', 'bin');
    fs.mkdirSync(localBin, { recursive: true, mode: 0o700 });

    if (process.platform === 'win32') {
      const winZip = path.join(releaseDir, `leapterm-${version}-windows-x64.zip`);
      if (!fs.existsSync(winZip)) {
        throw new Error(`Missing Windows release archive: ${winZip}`);
      }
      const winInstallDir = path.join(homeDir, 'AppData', 'Local', 'Programs', 'LeapTerm');
      fs.mkdirSync(winInstallDir, { recursive: true });
      runCommandChecked(tarExecutable(), ['-xf', winZip, '-C', winInstallDir]);
      auditWindowsAgentBundle(winInstallDir);

      // Write standard launcher shim in ~/.local/bin and verify execution from C:\ with scrubbed PATH
      const shimCmd = path.join(localBin, 'leap-agent.cmd');
      fs.writeFileSync(
        shimCmd,
        `@echo off\r\n"${winInstallDir}\\leap-agent.exe" %*\r\n`,
        'utf8',
      );
      const systemRoot = process.env.SystemRoot || 'C:\\Windows';
      const cleanWinEnv = {
        ...process.env,
        PATH: `${path.join(systemRoot, 'System32')};${systemRoot};${path.join(systemRoot, 'System32', 'Wbem')}`,
        Path: `${path.join(systemRoot, 'System32')};${systemRoot};${path.join(systemRoot, 'System32', 'Wbem')}`,
      };
      const directVer = runCommandChecked(path.join(winInstallDir, 'leap-agent.exe'), ['--version'], {
        cwd: path.parse(winInstallDir).root || 'C:\\',
        env: cleanWinEnv,
      });
      if (directVer.stdout.trim() !== `leap-agent ${version}`) {
        throw new Error(`Unexpected Windows direct version output: ${directVer.stdout}`);
      }
      runCommandChecked(path.join(winInstallDir, 'leap-agent.exe'), ['--help'], {
        cwd: path.parse(winInstallDir).root || 'C:\\',
        env: cleanWinEnv,
      });
      const shimVer = runCommandChecked('cmd.exe', ['/c', shimCmd, '--version'], {
        cwd: path.parse(winInstallDir).root || 'C:\\',
        env: cleanWinEnv,
      });
      if (shimVer.stdout.trim() !== `leap-agent ${version}`) {
        throw new Error(`Unexpected Windows shim version output: ${shimVer.stdout}`);
      }
      const lifecycle = verifyLiveAgentLifecycleAndZeroSshJoin({
        agentBin: path.join(winInstallDir, 'leap-agent.exe'),
        baseEnv: cleanWinEnv,
        workRoot,
      });
      return { platform: 'win32', verifiedVersion: directVer.stdout.trim(), lifecycle };
    }

    if (process.platform === 'darwin') {
      const macZip = path.join(releaseDir, `leapterm-${version}-macos-arm64.zip`);
      if (!fs.existsSync(macZip)) {
        throw new Error(`Missing macOS release archive: ${macZip}`);
      }
      const macStage = path.join(workRoot, 'mac-stage');
      fs.mkdirSync(macStage, { recursive: true });
      runCommandChecked('unzip', ['-q', macZip, '-d', macStage]);
      const contentsDir = [
        path.join(macStage, 'leapterm.app', 'Contents'),
        path.join(macStage, 'LeapTerm.app', 'Contents'),
        path.join(macStage, 'Contents'),
      ].find((p) => fs.existsSync(p));
      if (!contentsDir) {
        throw new Error(`Missing .app/Contents in macOS archive: ${macZip}`);
      }
      auditMacosAgentBundle(contentsDir);

      const cleanMacEnv = { ...process.env };
      delete cleanMacEnv.DYLD_LIBRARY_PATH;
      delete cleanMacEnv.DYLD_FALLBACK_LIBRARY_PATH;
      const agentBin = path.join(contentsDir, 'MacOS', 'leap-agent');
      const verOut = runCommandChecked(agentBin, ['--version'], { env: cleanMacEnv }).stdout.trim();
      if (verOut !== `leap-agent ${version}`) {
        throw new Error(`Unexpected macOS leap-agent version output: ${verOut}`);
      }
      runCommandChecked(agentBin, ['--help'], { env: cleanMacEnv });
      const lifecycle = verifyLiveAgentLifecycleAndZeroSshJoin({
        agentBin,
        baseEnv: cleanMacEnv,
        workRoot,
      });
      return { platform: 'darwin', verifiedVersion: verOut, lifecycle };
    }

    if (process.platform === 'linux') {
      const linuxDeb = path.join(releaseDir, `leapterm-${version}-agent-linux-amd64.deb`);
      if (!fs.existsSync(linuxDeb)) {
        throw new Error(`Missing Linux Debian package: ${linuxDeb}`);
      }
      const debStage = path.join(workRoot, 'linux-stage');
      fs.mkdirSync(debStage, { recursive: true });
      runCommandChecked('dpkg-deb', ['-x', linuxDeb, debStage]);
      const nativeRoot = path.join(debStage, 'usr', 'libexec', 'leapterm');
      auditLinuxAgentBundle(nativeRoot);

      const agentBin = path.join(nativeRoot, 'leap-agent');
      const env = { ...process.env };
      delete env.LD_LIBRARY_PATH;
      const verOut = runCommandChecked(agentBin, ['--version'], { env }).stdout.trim();
      if (verOut !== `leap-agent ${version}`) {
        throw new Error(`Unexpected Linux leap-agent version output: ${verOut}`);
      }
      runCommandChecked(agentBin, ['--help'], { env });
      const lddOut = runCommandChecked('ldd', [agentBin], { env }).stdout;
      if (lddOut.includes('not found')) {
        throw new Error(`Linux leap-agent has unresolved shared libraries in ldd:\n${lddOut}`);
      }
      if (installerPath && fs.existsSync(installerPath)) {
        // Also verify stage_linux_deb_native_bundle in install.sh
        const source = fs.readFileSync(installerPath, 'utf8');
        const helpers = source.slice(
          source.indexOf('linux_system_library() {'),
          source.indexOf('stage_binary_bundle() {'),
        );
        const installerStage = path.join(workRoot, 'installer-deb-stage');
        fs.mkdirSync(installerStage, { recursive: true });
        runCommandChecked('bash', [
          '-c',
          `set -euo pipefail\n${helpers}\nRPM_ARCH=x86_64\nstage_linux_deb_native_bundle "$1" "$2"\n`,
          'verify-deb-stage',
          linuxDeb,
          installerStage,
        ]);
      }
      const lifecycle = verifyLiveAgentLifecycleAndZeroSshJoin({
        agentBin,
        baseEnv: env,
        workRoot,
      });
      return { platform: 'linux', verifiedVersion: verOut, lifecycle };
    }

    throw new Error(`Unsupported host platform: ${process.platform}`);
  } finally {
    fs.rmSync(workRoot, { recursive: true, force: true });
  }
}

export function parseCliArgs(argv) {
  const opts = {
    version: '',
    repo: process.env.LEAPTERM_REPO || 'omnisolo-llc/leapterm-release',
    releaseDir: '',
    localDir: '',
    installerPath: '',
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--version' && argv[i + 1]) {
      opts.version = argv[++i].replace(/^v/, '');
    } else if (arg === '--repo' && argv[i + 1]) {
      opts.repo = argv[++i];
    } else if (arg === '--release-dir' && argv[i + 1]) {
      opts.releaseDir = argv[++i];
    } else if (arg === '--local-dir' && argv[i + 1]) {
      opts.localDir = argv[++i];
    } else if (arg === '--installer' && argv[i + 1]) {
      opts.installerPath = argv[++i];
    }
  }
  return opts;
}

function downloadReleaseAssets(repo, version, destDir) {
  const tag = `v${version.replace(/^v/, '')}`;
  const assets = [
    'SHA256SUMS',
    `leapterm-${version}-windows-x64.zip`,
    `leapterm-${version}-macos-arm64.zip`,
    `leapterm-${version}-agent-linux-amd64.deb`,
  ];
  for (const name of assets) {
    const outPath = path.join(destDir, name);
    const url = `https://github.com/${repo}/releases/download/${tag}/${name}`;
    runCommandChecked('curl', ['-fsSL', '-L', '--retry', '3', url, '-o', outPath]);
  }
  const sumsContent = fs.readFileSync(path.join(destDir, 'SHA256SUMS'), 'utf8');
  const expectedByAsset = new Map();
  for (const line of sumsContent.trim().split(/\r?\n/)) {
    const [hash, file] = line.trim().split(/\s+/);
    if (hash && file) expectedByAsset.set(file, hash.toLowerCase());
  }
  for (const name of assets.slice(1)) {
    const expected = expectedByAsset.get(name);
    if (!expected) {
      throw new Error(`Asset ${name} is missing from SHA256SUMS`);
    }
    const actual = crypto
      .createHash('sha256')
      .update(fs.readFileSync(path.join(destDir, name)))
      .digest('hex');
    if (actual !== expected) {
      throw new Error(`SHA-256 mismatch for ${name}: expected ${expected}, got ${actual}`);
    }
  }
}

async function main() {
  const opts = parseCliArgs(process.argv.slice(2));
  if (!opts.version) {
    throw new Error(
      'Usage: verify-agent-install-e2e.mjs --version <x.y.z> [--repo <owner/repo>] [--release-dir <dir>] [--local-dir <dir>] [--installer <path>]',
    );
  }
  if (opts.localDir) {
    const live = verifyCurrentHostLiveInstall({
      releaseDir: opts.localDir,
      version: opts.version,
      installerPath: opts.installerPath,
    });
    console.log(
      JSON.stringify(
        {
          ok: true,
          version: opts.version,
          mode: 'local-host-only',
          liveHost: live,
        },
        null,
        2,
      ),
    );
    return;
  }
  let tempReleaseDir = '';
  let releaseDir = opts.releaseDir;
  try {
    if (!releaseDir) {
      tempReleaseDir = fs.mkdtempSync(path.join(os.tmpdir(), 'leapterm-e2e-assets-'));
      releaseDir = tempReleaseDir;
      downloadReleaseAssets(opts.repo, opts.version, releaseDir);
    }
    const audited = extractReleaseArchivesAndAuditAllPlatforms({
      releaseDir,
      version: opts.version,
    });
    const live = verifyCurrentHostLiveInstall({
      releaseDir,
      version: opts.version,
      installerPath: opts.installerPath,
    });
    console.log(
      JSON.stringify(
        {
          ok: true,
          version: opts.version,
          auditedPlatforms: Object.keys(audited),
          liveHost: live,
        },
        null,
        2,
      ),
    );
  } finally {
    if (tempReleaseDir) {
      fs.rmSync(tempReleaseDir, { recursive: true, force: true });
    }
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((err) => {
    console.error(redactSensitiveCommandOutput(err.stack || err.message || String(err)));
    process.exit(1);
  });
}
