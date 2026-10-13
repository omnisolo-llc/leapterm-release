import test from 'node:test';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {mkdtemp, readFile, rm, stat} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {setTimeout as delay} from 'node:timers/promises';
import {runOwned} from '../scripts/run-owned-command.mjs';

test('native subprocess capture keeps exact output and rejects failures', async () => {
  assert.equal(await runOwned(process.execPath, ['-e', "process.stdout.write('exact\\n')"],
    {capture: true, timeout: 2000}), 'exact');
  await assert.rejects(runOwned(process.execPath, ['-e', "process.stderr.write('failed');process.exit(7)"],
    {capture: true, timeout: 2000}), /failed \(7\): failed/);
});

test('timeout drains only its owned descendant tree before returning', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'omniterm-owned-process-'));
  const ownedFile = join(directory, 'owned');
  const independentFile = join(directory, 'independent');
  const writer = file => `const fs=require('node:fs');setInterval(()=>fs.appendFileSync(${JSON.stringify(file)},'x'),10)`;
  const independent = spawn(process.execPath, ['-e', writer(independentFile)],
    {detached: true, stdio: 'ignore'});
  independent.unref();
  t.after(async () => {
    independent.kill('SIGKILL');
    await delay(100);
    await rm(directory, {recursive: true, force: true});
  });
  const parent = `const {spawn}=require('node:child_process');` +
    `spawn(process.execPath,['-e',${JSON.stringify(writer(ownedFile))}],{stdio:'ignore'});` +
    `setInterval(()=>{},1000)`;
  await assert.rejects(runOwned(process.execPath, ['-e', parent],
    {capture: true, timeout: 350}), {code: 'ETIMEDOUT'});
  const ownedBefore = (await stat(ownedFile)).size;
  const independentBefore = (await stat(independentFile)).size;
  await delay(200);
  assert.equal((await stat(ownedFile)).size, ownedBefore,
    'timed-out descendant still writes after source reuse may begin');
  assert((await stat(independentFile)).size > independentBefore,
    'timeout signaled a process outside the owned tree');
  assert((await readFile(ownedFile)).length > 0);
});
