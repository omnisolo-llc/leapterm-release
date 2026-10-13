import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createRequire } from 'node:module';
import test from 'node:test';
import { createRelayOwner } from '../relay/native/src/owner.js';
import { encodeFrame, FrameDecoder, SCOPED_DESTINATION_CAPABILITY } from '../relay/cloudflare/src/connector-wire.js';

const nativeRoot = new URL('../relay/native/', import.meta.url);
const { WebSocket } = createRequire(new URL('package.json', nativeRoot))('ws');
const credentials = {
  RELAY_AUTH_TOKEN: 'Native-Relay-Workload-2026!Credential',
  RELAY_MANAGEMENT_TOKEN: 'Native-Relay-Operator-2026!Credential',
  RELAY_PUBLIC_ORIGIN: 'https://relay.example.test',
};

test('native relay package runtime dependencies match its pinned lockfile', async () => {
  const manifest = JSON.parse(await readFile(new URL('package.json', nativeRoot), 'utf8'));
  const lock = JSON.parse(await readFile(new URL('package-lock.json', nativeRoot), 'utf8'));
  assert.equal(manifest.name, 'omniterm-self-hosted-origin');
  assert.equal(manifest.version, '1.0.0');
  assert.equal(manifest.engines.node, '>=24.21.0');
  assert.equal(manifest.scripts.start, 'node src/cli.js');
  assert.deepEqual(lock.packages[''].dependencies, manifest.dependencies);
  assert.deepEqual(lock.packages[''].engines, manifest.engines);
  assert.equal(lock.packages['node_modules/ws'].version, manifest.dependencies.ws);
});

function connectorSocket(t, origin, path) {
  const socket = new WebSocket(origin.replace('http:', 'ws:') + path, {
    headers: {'x-workload-token': credentials.RELAY_AUTH_TOKEN},
  });
  const decoder = new FrameDecoder(), queued = [], waiting = [], frames = [];
  const closed = new Promise(resolve => socket.once('close', (code, reason) => {
    for (const waiter of waiting.splice(0)) {
      clearTimeout(waiter.timer); waiter.reject(Error('connector_closed'));
    }
    resolve({code, reason: reason.toString()});
  }));
  socket.on('message', (data, binary) => {
    if (!binary) return;
    for (const frame of decoder.push(data)) {
      frames.push(frame);
      const waiter = waiting.shift();
      if (waiter) { clearTimeout(waiter.timer); waiter.resolve(frame); }
      else queued.push(frame);
    }
  });
  const opened = new Promise((resolve, reject) => {
    socket.once('open', resolve); socket.once('error', reject);
  });
  t.after(() => socket.terminate());
  return {socket, opened, closed, frames, next() {
    if (queued.length) return Promise.resolve(queued.shift());
    return new Promise((resolve, reject) => {
      const waiter = {resolve, reject};
      waiter.timer = setTimeout(() => {
        const at = waiting.indexOf(waiter); if (at >= 0) waiting.splice(at, 1);
        reject(Error('connector_frame_deadline'));
      }, 5000);
      waiting.push(waiter);
    });
  }};
}

async function scopedOwner(t, env = {}) {
  const directory = await mkdtemp(join(tmpdir(), 'omniterm-scoped-public-relay-'));
  const owner = await createRelayOwner({env: {...credentials, ...env},
    statePath: join(directory, 'relay.sqlite'), port: 0});
  t.after(async () => { await owner.close(); await rm(directory, {recursive: true, force: true}); });
  return owner;
}

async function hello(t, owner, connector, version = 2) {
  const agent = connectorSocket(t, owner.origin, '/relay/api/v1/connect?connector_id=' + connector);
  await agent.opened;
  const challenge = await agent.next();
  assert.equal(challenge.type, 'HelloChallenge');
  agent.socket.send(encodeFrame({type: 'Hello', version, connector_id: connector,
    tenant_id: 'tenant', nonce: challenge.nonce, signature: new Uint8Array(64)}));
  return agent;
}

async function capabilities(agent) {
  const accepted = await agent.next(), offered = await agent.next();
  assert.equal(accepted.type, 'HelloAccepted');
  assert.equal(accepted.version, 2);
  assert.deepEqual(offered, {type: 'Capabilities', capabilities: SCOPED_DESTINATION_CAPABILITY});
  agent.socket.send(encodeFrame({type: 'Capabilities', capabilities: SCOPED_DESTINATION_CAPABILITY}));
  agent.socket.send(encodeFrame({type: 'Ping', value: 47n}));
  assert.deepEqual(await agent.next(), {type: 'Pong', value: 47n});
}

async function clientDial(t, owner, connector) {
  const client = connectorSocket(t, owner.origin, `/internal/v1/connectors/${connector}/dial-stream`);
  await client.opened;
  // Only the local broker socket is opened. This peer receives metadata and
  // never connects to the named destination or exercises Agent DNS policy.
  client.socket.send(JSON.stringify({connector_id: connector, tenant_id: 'tenant', subject_id: 'free-self-host',
    target_id: 'target', hostname: '8.8.8.8', port: 22, expires_at_epoch: Math.floor(Date.now() / 1000) + 60,
    allow_private_network: true, allowed_network_cidrs: ['0.0.0.0/0'],
    destination_scope: {scope_version: 1, allow_private_network: true, allowed_network_cidrs: ['0.0.0.0/0']}}));
  return client;
}

for (const [flag, allowPrivate] of [[undefined, false], ['true', true]]) {
  test(`native public socket carries only immutable operator scope: ${allowPrivate}`, {timeout: 20000}, async t => {
    const owner = await scopedOwner(t, flag === undefined ? {} : {OMNITERM_ALLOW_LOCAL_NETWORK: flag});
    const connector = 'scoped-native';
    const agent = await hello(t, owner, connector);
    await capabilities(agent);
    const client = await clientDial(t, owner, connector);
    assert.deepEqual(await agent.next(), {type: 'DialScoped', stream_id: 1, target_id: 'target',
      hostname: '8.8.8.8', port: 22, scope_version: 1,
      allow_private_network: allowPrivate, allowed_network_cidrs: []});
    assert.equal(agent.frames.some(frame => frame.type === 'Dial'), false);
    const revoked = await fetch(`${owner.origin}/internal/v1/connectors/${connector}/revoke`, {
      method: 'POST', headers: {'x-relay-management-token': credentials.RELAY_MANAGEMENT_TOKEN},
    });
    assert.equal(revoked.status, 204);
    await Promise.all([agent.closed, client.closed]);
  });
}

test('native public sockets refuse legacy Hello and missing scoped capability without fallback', {timeout: 20000}, async t => {
  const owner = await scopedOwner(t);
  const old = await hello(t, owner, 'legacy-native', 1);
  assert.equal((await old.closed).code, 1008);
  assert.equal(old.frames.some(frame => frame.type === 'HelloAccepted'), false);

  const incapable = await hello(t, owner, 'incapable-native');
  assert.equal((await incapable.next()).type, 'HelloAccepted');
  assert.equal((await incapable.next()).capabilities, SCOPED_DESTINATION_CAPABILITY);
  incapable.socket.send(encodeFrame({type: 'Capabilities', capabilities: 0}));
  assert.equal((await incapable.closed).code, 1008);
  assert.equal(incapable.frames.some(frame => ['Dial', 'DialScoped'].includes(frame.type)), false);
});

test('native public dial waits for scoped negotiation and allocates nothing on refusal', {timeout: 20000}, async t => {
  const owner = await scopedOwner(t), connector = 'negotiate-native';
  const agent = await hello(t, owner, connector);
  assert.equal((await agent.next()).type, 'HelloAccepted');
  assert.equal((await agent.next()).capabilities, SCOPED_DESTINATION_CAPABILITY);
  const early = await clientDial(t, owner, connector);
  assert.equal((await early.closed).reason, 'scoped_destination_required');
  assert.equal(agent.frames.some(frame => ['Dial', 'DialScoped'].includes(frame.type)), false);
  agent.socket.send(encodeFrame({type: 'Capabilities', capabilities: SCOPED_DESTINATION_CAPABILITY}));
  agent.socket.send(encodeFrame({type: 'Ping', value: 47n}));
  assert.equal((await agent.next()).type, 'Pong');
  await clientDial(t, owner, connector);
  const dial = await agent.next();
  assert.equal(dial.type, 'DialScoped');
  assert.equal(dial.stream_id, 1);
});

test('native owner enforces loopback and independent credentials and persists revocation', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'omniterm-native-relay-contract-'));
  const statePath = join(directory, 'relay.sqlite');
  let owner;
  t.after(async () => {
    if (owner) await owner.close();
    await rm(directory, {recursive: true, force: true});
  });

  await assert.rejects(
    createRelayOwner({env: credentials, statePath, host: '0.0.0.0'}),
    /loopback_relay_listener_required/,
  );
  await assert.rejects(
    createRelayOwner({
      env: {...credentials, RELAY_MANAGEMENT_TOKEN: credentials.RELAY_AUTH_TOKEN},
      statePath,
    }),
    /independent_relay_credentials_required/,
  );

  owner = await createRelayOwner({env: credentials, statePath, port: 0});
  assert.match(owner.origin, /^http:\/\/127\.0\.0\.1:/);

  const health = await fetch(`${owner.origin}/healthz`);
  assert.equal(health.status, 200);
  assert.equal(await health.text(), 'OK');
  const init = await (await fetch(`${owner.origin}/relay/api/v1/init`)).json();
  assert.deepEqual(init.transports, ['websocket']);
  assert.equal(init.native_rtc, false);

  const queryCredential = await fetch(
    `${owner.origin}/v1/connectors/stream?connector_id=relay-contract&token=${encodeURIComponent(credentials.RELAY_AUTH_TOKEN)}`,
  );
  assert.equal(queryCredential.status, 401);
  assert.equal((await queryCredential.json()).error, 'header_authentication_required');

  const connector = 'relay-contract';
  const managementPath = `/internal/v1/connectors/${connector}/revoke`;
  const workloadCannotRevoke = await fetch(`${owner.origin}${managementPath}`, {
    method: 'POST',
    headers: {'x-relay-management-token': credentials.RELAY_AUTH_TOKEN},
  });
  assert.equal(workloadCannotRevoke.status, 401);

  const revoke = await fetch(`${owner.origin}${managementPath}`, {
    method: 'POST',
    headers: {'x-relay-management-token': credentials.RELAY_MANAGEMENT_TOKEN},
  });
  assert.equal(revoke.status, 204);
  await owner.close();
  owner = undefined;

  owner = await createRelayOwner({env: credentials, statePath, port: 0});
  const deniedAfterRestart = await fetch(
    `${owner.origin}/v1/connectors/stream?connector_id=${connector}`,
    {headers: {'x-workload-token': credentials.RELAY_AUTH_TOKEN}},
  );
  assert.equal(deniedAfterRestart.status, 403);
  assert.equal((await deniedAfterRestart.json()).error, 'connector_revoked');

  const restore = await fetch(`${owner.origin}/internal/v1/connectors/${connector}/restore`, {
    method: 'POST',
    headers: {'x-relay-management-token': credentials.RELAY_MANAGEMENT_TOKEN},
  });
  assert.equal(restore.status, 204);

  if (process.platform !== 'win32') {
    for (const path of [directory, statePath, statePath + '.owner']) {
      const mode = (await stat(path)).mode & 0o777;
      assert.equal(mode & 0o077, 0, `${path} must not be accessible to group or other users`);
    }
  }
});
