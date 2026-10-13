import test from 'node:test';
import assert from 'node:assert/strict';
import {registerHooks} from 'node:module';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {request as httpsRequest} from 'node:https';
import {createServer} from 'node:net';
import {mkdtemp, readFile, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {setTimeout as delay} from 'node:timers/promises';
import {Http3Server, ProtocolTransport, FrameGroup, deferred, tracks}
  from './support/drain-protocol-fixture.js';

// Replace the two external protocol boundaries, retaining the exact provider
// module and its real HTTPS control API. No test-only production exports.
const source = new URL('../src/index.js', import.meta.url);
const protocol = new URL('./support/drain-protocol-fixture.js', import.meta.url);
const hooks = registerHooks({resolve(specifier, context, nextResolve) {
  if (context.parentURL === source.href &&
      ['@moq/net', '@fails-components/webtransport'].includes(specifier)) {
    return {url: protocol.href, shortCircuit: true};
  }
  return nextResolve(specifier, context);
}});
const {createMoqRelay} = await import(source.href);
hooks.deregister();

const controlToken = 'omniterm-unit-control-token-9f0d46c0a7e4';
const run = promisify(execFile);

async function request(origin, certificate, path, body) {
  const raw = JSON.stringify(body);
  return new Promise((resolve, reject) => {
    const outgoing = httpsRequest(new URL(path, origin), {method: 'POST', ca: certificate,
      headers: {'content-type': 'application/json', 'content-length': Buffer.byteLength(raw),
        authorization: `Bearer ${controlToken}`}}, incoming => {
      const chunks = [];
      incoming.on('data', chunk => chunks.push(chunk));
      incoming.on('end', () => resolve({status: incoming.statusCode,
        body: JSON.parse(Buffer.concat(chunks).toString('utf8'))}));
    });
    outgoing.once('error', reject);
    outgoing.end(raw);
  });
}

async function within(promise) {
  const controller = new AbortController();
  try {
    return await Promise.race([promise, delay(2000, undefined,
      {signal: controller.signal}).then(() => { throw new Error('protocol boundary was not reached'); })]);
  } finally { controller.abort(); }
}

async function assertPending(promise) {
  const controller = new AbortController();
  try {
    assert.equal(await Promise.race([
      promise.then(() => false), delay(50, true, {signal: controller.signal}),
    ]), true, 'close succeeded before the paused protocol operation drained');
  } finally { controller.abort(); }
}

async function fixture(t) {
  tracks.length = 0;
  const directory = await mkdtemp(join(tmpdir(), 'omniterm-moq-drain-'));
  const certificatePath = join(directory, 'cert.pem');
  const privateKeyPath = join(directory, 'key.pem');
  await run('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
    '-nodes', '-keyout', privateKeyPath, '-out', certificatePath, '-days', '1',
    '-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1']);
  const certificate = await readFile(certificatePath, 'utf8');
  const ports = createServer();
  await new Promise(resolve => ports.listen(0, '127.0.0.1', resolve));
  const port = ports.address().port;
  await new Promise(resolve => ports.close(resolve));
  const origin = `https://127.0.0.1:${port}`;
  const service = await createMoqRelay({controlHost: '127.0.0.1', dataHost: '127.0.0.1',
    controlPort: port, dataPort: port, publicOrigin: origin, controlToken,
    certificatePath, privateKeyPath});
  t.after(async () => { await service.close(); await rm(directory, {recursive: true, force: true}); });
  const scope = {shareId: 'MoqUnit1', epoch: 'drain-unit-epoch-0001'};
  const room = await request(origin, certificate, '/v1/relays', {
    ...scope, expiresAt: Date.now() + 60000,
  });
  assert.equal(room.status, 201);
  const issued = await request(origin, certificate, `/v1/relays/${room.body.relayId}/tokens`, {
    ...scope, role: 'publish', participantId: 'host01', expiresAt: Date.now() + 30000,
  });
  assert.equal(issued.status, 201);
  return {service, h3: Http3Server.current, track: tracks[0], scope,
    token: issued.body, control: (path, body) => request(origin, certificate, path, body),
    close: () => request(origin, certificate, '/v1/rooms/close', scope)};
}

test('cutoff drains a pending MoQ accept before installing its connection', async t => {
  const {h3, token, close, track} = await fixture(t);
  const transport = new ProtocolTransport({pauseAccept: true});
  assert.equal(await h3.admit(token.secret, transport), 200);
  await within(transport.acceptStarted.promise);
  const closing = close();
  try {
    await within(transport.closed);
    await assertPending(closing);
    transport.accepts.resolve(transport.connection);
    const result = await within(closing);
    assert.equal(result.status, 200);
    assert.deepEqual(result.body.closedTokenIds, [token.tokenId]);
    assert.equal(transport.consumed, 0);
    assert.equal(transport.published, 0);
    assert.equal(track.appended, 0);
  } finally { transport.accepts.resolve(transport.connection); }
});

test('cutoff drains a pending track info continuation before receiving groups', async t => {
  const {h3, token, close, track} = await fixture(t);
  const transport = new ProtocolTransport();
  transport.ignoreInfoClose = true;
  assert.equal(await h3.admit(token.secret, transport), 200);
  await within(transport.infoStarted.promise);
  const closing = close();
  try {
    await within(transport.closed);
    await assertPending(closing);
    transport.info.resolve({});
    assert.equal((await within(closing)).status, 200);
    assert.equal(track.appended, 0);
    assert.equal(track.writes.length, 0);
  } finally { transport.info.resolve({}); }
});

test('cutoff joins a pending group read rather than abandoning the losing promise', async t => {
  const {h3, token, close, track} = await fixture(t);
  const transport = new ProtocolTransport();
  transport.info.resolve({});
  transport.ignoreGroupClose = true;
  assert.equal(await h3.admit(token.secret, transport), 200);
  await within(transport.readsStarted.promise);
  const closing = close();
  const group = new FrameGroup();
  try {
    await within(transport.closed);
    await assertPending(closing);
    transport.nextGroup.resolve(group);
    assert.equal((await within(closing)).status, 200);
    assert.equal(track.appended, 0, 'a late group installed outgoing work after cutoff');
    assert.equal(track.writes.length, 0);
  } finally { transport.nextGroup.resolve(group); }
});

test('cutoff joins a pending frame read before charging or writing its late frame', async t => {
  const {h3, token, close, track} = await fixture(t);
  const transport = new ProtocolTransport();
  const group = new FrameGroup();
  group.ignoreClose = true;
  transport.info.resolve({});
  transport.groups.push(group);
  assert.equal(await h3.admit(token.secret, transport), 200);
  await within(group.readStarted.promise);
  const closing = close();
  try {
    await within(transport.closed);
    await assertPending(closing);
    group.nextFrame.resolve({payload: new Uint8Array([1, 2, 3])});
    assert.equal((await within(closing)).status, 200);
    assert.equal(track.writes.length, 0, 'a late frame was forwarded after cutoff');
  } finally { group.nextFrame.resolve(undefined); }
});

test('cutoff drains token stream cancellation before confirming a token with no sessions', async t => {
  const {h3, close} = await fixture(t);
  const cancelled = deferred();
  h3.streamCancel = cancelled;
  const closing = close();
  try {
    await assertPending(closing);
    cancelled.resolve();
    assert.equal((await within(closing)).status, 200);
    assert.equal(h3.streams.size, 0);
  } finally { cancelled.resolve(); }
});

test('owner close retry retains previously confirmed lease IDs while another native close is unconfirmed',
  {timeout: 15000}, async t => {
    const {h3, token, scope, control, service} = await fixture(t);
    const viewer = await control(`/v1/relays/${token.relayId}/tokens`, {
      ...scope, role: 'subscribe', participantId: 'viewer01', expiresAt: Date.now() + 30000,
    });
    assert.equal(viewer.status, 201);
    const transport = new ProtocolTransport();
    transport.close = () => {};
    assert.equal(await h3.admit(viewer.body.secret, transport), 200);
    await within(transport.acceptStarted.promise);
    const tokenIds = [token.tokenId, viewer.body.tokenId].sort();
    const body = {...scope, tokenIds, endRoom: true};
    const path = `/v1/relays/${token.relayId}/sessions/close`;
    try {
      const failed = await control(path, body);
      assert.equal(failed.status, 503);
      assert.deepEqual(failed.body.closedTokenIds, [token.tokenId]);
      assert.equal(service.relayCount, 1);
      transport.nativeClosed.resolve();
      const closed = await control(path, body);
      assert.equal(closed.status, 200, 'retry rejected the original exact set after partial native drain');
      assert.deepEqual(closed.body.closedTokenIds, tokenIds);
      assert.equal(service.activeSessionCount, 0);
      assert.equal(service.relayCount, 0);
    } finally { transport.nativeClosed.resolve(); }
  });
