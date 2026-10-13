import {spawn, spawnSync} from 'node:child_process';
import {setTimeout as delay} from 'node:timers/promises';

function groupExists(pid) {
  try { process.kill(-pid, 0); return true; }
  catch (error) {
    if (error.code === 'ESRCH') return false;
    throw error;
  }
}

function signalGroup(pid, signal) {
  try { process.kill(-pid, signal); }
  catch (error) { if (error.code !== 'ESRCH') throw error; }
}

async function waitForGroup(pid, milliseconds) {
  const deadline = Date.now() + milliseconds;
  while (groupExists(pid) && Date.now() < deadline) await delay(50);
  return !groupExists(pid);
}

async function stopOwnedTree(child, closed) {
  if (!child.pid) throw Error('Owned native process has no identity');
  if (process.platform === 'win32') {
    const result = spawnSync('taskkill.exe', ['/PID', String(child.pid), '/T', '/F'],
      {stdio: 'ignore', windowsHide: true, timeout: 10000});
    if (result.error || result.status !== 0) throw Error('Owned Windows process tree did not stop');
  } else {
    signalGroup(child.pid, 'SIGTERM');
    if (!await waitForGroup(child.pid, 1000)) {
      signalGroup(child.pid, 'SIGKILL');
      if (!await waitForGroup(child.pid, 5000)) throw Error('Owned process group did not stop');
    }
  }
  let timer;
  try {
    await Promise.race([closed, new Promise((_, reject) => {
      timer = setTimeout(() => reject(Error('Owned native process did not drain')), 5000);
    })]);
  } finally { clearTimeout(timer); }
}

export async function runOwned(command, args, options = {}) {
  const capture = options.capture === true;
  const child = spawn(command, args, {
    cwd: options.cwd,
    env: options.env ?? process.env,
    detached: process.platform !== 'win32',
    windowsHide: true,
    stdio: capture ? ['ignore', 'pipe', 'pipe'] : ['ignore', 'inherit', 'inherit'],
  });
  let spawnError;
  let buffered = 0;
  let overflow = false;
  const stdout = [];
  const stderr = [];
  const collect = (chunks, data) => {
    buffered += data.length;
    if (buffered > 16 * 1024 * 1024) overflow = true;
    else chunks.push(data);
  };
  if (capture) {
    child.stdout.on('data', data => collect(stdout, data));
    child.stderr.on('data', data => collect(stderr, data));
  }
  child.once('error', error => { spawnError = error; });
  const closed = new Promise(resolve => child.once('close', (status, signal) => resolve({status, signal})));
  let timer;
  const timedOut = new Promise(resolve => {
    timer = setTimeout(() => resolve(true), options.timeout ?? 1800000);
  });
  const result = await Promise.race([closed, timedOut]);
  clearTimeout(timer);
  if (result === true) {
    await stopOwnedTree(child, closed);
    const error = Error(`${command} ${args.join(' ')} failed (ETIMEDOUT)`);
    error.code = 'ETIMEDOUT';
    throw error;
  }
  if (spawnError) throw spawnError;
  if (overflow) throw Error('Native command output exceeds its bound');
  const output = capture ? Buffer.concat(stdout).toString('utf8').trim() : '';
  if (result.status !== 0) {
    const detail = capture ? Buffer.concat(stderr).toString('utf8') || output : '';
    throw Error(`${command} ${args.join(' ')} failed (${result.status ?? result.signal}): ${detail}`);
  }
  return output;
}
