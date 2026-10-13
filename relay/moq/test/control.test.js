import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash, X509Certificate} from 'node:crypto';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {request as httpsRequest} from 'node:https';
import {createServer as createTcpServer} from 'node:net';
import {mkdtemp, readFile, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {setTimeout as delay} from 'node:timers/promises';
import {WebTransport} from '@fails-components/webtransport';
import * as Moq from '@moq/net';
import {createMoqRelay} from '../src/index.js';

globalThis.WebTransport ??= WebTransport;

const run = promisify(execFile);
const controlToken = 'omniterm-test-control-token-9f0d46c0a7e4';

async function freePort() {
  const server = createTcpServer();
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const port = server.address().port;
  await new Promise(resolve => server.close(resolve));
  return port;
}

async function controlRequest(origin, certificate, path, {body, token = controlToken} = {}) {
  return new Promise((resolve, reject) => {
    const request = httpsRequest(new URL(path, origin), {
      method: 'POST', ca: certificate,
      headers: {'content-type': 'application/json', 'content-length': Buffer.byteLength(JSON.stringify(body)),
        ...(token ? {authorization: `Bearer ${token}`} : {})},
    }, response => {
      const parts = [];
      response.on('data', chunk => parts.push(chunk));
      response.on('end', () => {
        let value;
        try { value = JSON.parse(Buffer.concat(parts).toString('utf8')); }
        catch { value = null; }
        resolve({status: response.statusCode, value});
      });
    });
    request.once('error', reject);
    request.end(JSON.stringify(body));
  });
}

async function controlGet(origin, certificate, path, token = controlToken) {
  return new Promise((resolve, reject) => {
    const request = httpsRequest(new URL(path, origin), {method:'GET',ca:certificate,
      headers:{...(token?{authorization:`Bearer ${token}`}:{})}}, response => {
      const parts=[];
      response.on('data',chunk=>parts.push(chunk));
      response.on('end',()=>{
        let value;try{value=JSON.parse(Buffer.concat(parts).toString('utf8'));}catch{value=null;}
        resolve({status:response.statusCode,value});
      });
    });
    request.once('error',reject);request.end();
  });
}

async function fixture(t, options = {}) {
  const directory = await mkdtemp(join(tmpdir(), 'omniterm-moq-control-'));
  const certificatePath = join(directory, 'cert.pem');
  const privateKeyPath = join(directory, 'key.pem');
  await run('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
    '-keyout', privateKeyPath, '-out', certificatePath, '-days', '1',
    '-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1'], {stdio: 'ignore'});
  const certificate = await readFile(certificatePath, 'utf8');
  const port = await freePort();
  const origin = `https://127.0.0.1:${port}`;
  const service = await createMoqRelay({controlHost: '127.0.0.1', dataHost: '127.0.0.1',
    controlPort: port, dataPort: port, publicOrigin: origin, controlToken,
    certificatePath, privateKeyPath, maxRelays: 2, maxSessions: 2, ...options});
  t.after(async () => {
    await service.close();
    await rm(directory, {recursive: true, force: true});
  });
  return {origin, certificate, service};
}

async function within(promise, message, milliseconds = 5000) {
  const controller = new AbortController();
  try {
    return await Promise.race([promise, delay(milliseconds, undefined,
      {signal: controller.signal}).then(() => { throw new Error(message); })]);
  } finally { controller.abort(); }
}

async function assertPending(promise, message) {
  const controller = new AbortController();
  try {
    const pending = await Promise.race([
      promise.then(() => false), delay(100, true, {signal: controller.signal}),
    ]);
    assert.equal(pending, true, message);
  } finally { controller.abort(); }
}

async function createRoom(origin, certificate, shareId, epoch) {
  const created = await controlRequest(origin, certificate, '/v1/relays', {
    body: {shareId, epoch, expiresAt: Date.now() + 60000, maxBytes: 1000000,
      usageOrigin: 'https://api.example.test'},
  });
  assert.equal(created.status, 201);
  return created.value;
}

async function connectParticipant(t, origin, certificate, room, participantId, role) {
  const issued = await controlRequest(origin, certificate, `/v1/relays/${room.relayId}/tokens`, {
    body: {shareId: room.shareId, epoch: room.epoch, participantId, role,
      expiresAt: Date.now() + 30000},
  });
  assert.equal(issued.status, 201);
  const certificateHash = createHash('sha256').update(new X509Certificate(certificate).raw).digest();
  const connection = await Moq.Connection.connect(new URL(`/${issued.value.secret}`, origin), {
    webtransport: {serverCertificateHashes: [{algorithm: 'sha-256', value: certificateHash}]},
    websocket: {enabled: false}, discovery: false,
  });
  t.after(() => connection.close());
  return {connection, token: issued.value};
}

function usageAuthority(onUsage, onHeartbeat) {
  return async (url, init) => {
    const body = JSON.parse(init.body);
    switch (new URL(url).pathname.split('/').at(-1)) {
      case 'heartbeat':
        if (onHeartbeat) return onHeartbeat(body);
        return Response.json({status: 'active', share_id: body.share_id,
          session_epoch: body.session_epoch, heartbeat_id: body.heartbeat_id});
      case 'readyz':
        return Response.json({status: 'ready', protocol: 'omniterm-moq-usage-v1',
          probe_id: body.probe_id});
      case 'usage': return onUsage(body, init);
      default: throw new Error('unexpected_usage_operation');
    }
  };
}

const managedOptions = {usageUrl: 'https://api.example.test/internal/v1/live-share/moq/usage',
  usageToken: 'independent-worker-moq-usage-token-0001', managedUsageRequired: true,
  maxSessions: 8};

test('relay creation and token admission require the control credential and exact room scope', async t => {
  const {origin, certificate} = await fixture(t);
  const unauthorized = await controlRequest(origin, certificate, '/v1/relays', {
    body: {shareId: 'MoqScop1', epoch: 'scope-epoch-0001', expiresAt: Date.now() + 60000}, token: '',
  });
  assert.equal(unauthorized.status, 401);

  const created = await controlRequest(origin, certificate, '/v1/relays', {
    body: {shareId: 'MoqScop1', epoch: 'scope-epoch-0001', expiresAt: Date.now() + 60000},
  });
  assert.equal(created.status, 201);
  assert.equal(created.value.publicOrigin, origin);
  const relayId = created.value.relayId;

  const wrongScope = await controlRequest(origin, certificate, `/v1/relays/${relayId}/tokens`, {
    body: {shareId: 'MoqScop2', epoch: 'scope-epoch-0001', participantId: 'viewer01',
      role: 'subscribe', expiresAt: Date.now() + 30000},
  });
  assert.equal(wrongScope.status, 409);

  const invalidRole = await controlRequest(origin, certificate, `/v1/relays/${relayId}/tokens`, {
    body: {shareId: 'MoqScop1', epoch: 'scope-epoch-0001', participantId: 'viewer01',
      role: 'publish,subscribe', expiresAt: Date.now() + 30000},
  });
  assert.equal(invalidRole.status, 409);

  const token = await controlRequest(origin, certificate, `/v1/relays/${relayId}/tokens`, {
    body: {shareId: 'MoqScop1', epoch: 'scope-epoch-0001', participantId: 'viewer01',
      role: 'subscribe', expiresAt: Date.now() + 30000},
  });
  assert.equal(token.status, 201);
  assert.equal(token.value.participantId, 'viewer01');
  assert.equal(token.value.role, 'subscribe');
  assert.match(token.value.secret, /^[A-Za-z0-9_-]{40,64}$/);
});

test('viewer close is token-scoped and owner close acknowledges the exact remaining leases', async t => {
  const {origin, certificate} = await fixture(t);
  const created = await controlRequest(origin, certificate, '/v1/relays', {
    body: {shareId: 'MoqClos1', epoch: 'close-epoch-0001', expiresAt: Date.now() + 60000},
  });
  const relayId = created.value.relayId;
  const issue = async (participantId, role) => controlRequest(origin, certificate,
    `/v1/relays/${relayId}/tokens`, {body: {shareId: 'MoqClos1', epoch: 'close-epoch-0001',
      participantId, role, expiresAt: Date.now() + 30000}});
  const host = await issue('host01', 'publish');
  const viewer = await issue('viewer01', 'subscribe');
  assert.equal(host.status, 201);
  assert.equal(viewer.status, 201);

  const viewerClosed = await controlRequest(origin, certificate,
    `/v1/relays/${relayId}/sessions/close`, {body: {shareId: 'MoqClos1',
      epoch: 'close-epoch-0001', tokenIds: [viewer.value.tokenId], endRoom: false}});
  assert.equal(viewerClosed.status, 200);
  assert.deepEqual(viewerClosed.value.closedTokenIds, [viewer.value.tokenId]);

  const ended = await controlRequest(origin, certificate,
    `/v1/relays/${relayId}/sessions/close`, {body: {shareId: 'MoqClos1',
      epoch: 'close-epoch-0001', tokenIds: [host.value.tokenId], endRoom: true}});
  assert.equal(ended.status, 200);
  assert.deepEqual(ended.value.closedTokenIds, [host.value.tokenId]);
  assert.equal(ended.value.endRoom, true);

  const retried = await controlRequest(origin, certificate,
    `/v1/relays/${relayId}/sessions/close`, {body: {shareId: 'MoqClos1',
      epoch: 'close-epoch-0001', tokenIds: [host.value.tokenId], endRoom: true}});
  assert.equal(retried.status, 200);
  assert.deepEqual(retried.value.closedTokenIds, [host.value.tokenId]);
});

test('HTTP/3 owner cutoff closes the native session and rejects token replay', async t => {
  const {origin, certificate, service} = await fixture(t);
  const created = await controlRequest(origin, certificate, '/v1/relays', {
    body: {shareId: 'MoqH3Ow1', epoch: 'h3-owner-epoch-0001', expiresAt: Date.now() + 60000},
  });
  const relayId = created.value.relayId;
  const issue = (participantId) => controlRequest(origin, certificate,
    `/v1/relays/${relayId}/tokens`, {body: {shareId: 'MoqH3Ow1', epoch: 'h3-owner-epoch-0001',
      participantId, role: 'subscribe', expiresAt: Date.now() + 30000}});
  const certificateHash = createHash('sha256')
    .update(new X509Certificate(certificate).raw)
    .digest();
  const urlFor = (secret) => new URL('/' + secret, origin);
  const clientOptions = {serverCertificateHashes: [{algorithm: 'sha-256', value: certificateHash}]};
  const invalid = await issue('invalid01');
  const rejectedTransport = new WebTransport(urlFor(invalid.value.secret), {
    ...clientOptions, protocols: ['unsupported-moq-protocol'],
  });
  rejectedTransport.closed.catch(() => {});
  const rejected = await Promise.race([
    rejectedTransport.ready.then(() => false, () => true),
    new Promise(resolve => setTimeout(() => resolve(false), 5000)),
  ]);
  assert.equal(rejected, true);
  rejectedTransport.close();
  const invalidClosed = await controlRequest(origin, certificate,
    `/v1/relays/${relayId}/sessions/close`, {body: {shareId: 'MoqH3Ow1',
      epoch: 'h3-owner-epoch-0001', tokenIds: [invalid.value.tokenId], endRoom: false}});
  assert.equal(invalidClosed.status, 200);

  const firstToken = await issue('viewer001');
  const connect = (secret) => Moq.Connection.connect(urlFor(secret), {
    webtransport: clientOptions, websocket: {enabled: false}, discovery: false,
  });
  const first = await connect(firstToken.value.secret);
  assert.equal(first.version, 'moq-transport-16');
  first.close();
  await first.closed;
  const firstClosed = await controlRequest(origin, certificate,
    `/v1/relays/${relayId}/sessions/close`, {body: {shareId: 'MoqH3Ow1',
      epoch: 'h3-owner-epoch-0001', tokenIds: [firstToken.value.tokenId], endRoom: false}});
  assert.equal(firstClosed.status, 200);
  await first.closed;

  const secondToken = await issue('viewer002');
  const second = await connect(secondToken.value.secret);
  assert.equal(second.version, 'moq-transport-16');
  const ownerClosed = await controlRequest(origin, certificate, '/v1/rooms/close', {
    body: {shareId: 'MoqH3Ow1', epoch: 'h3-owner-epoch-0001'},
  });
  assert.equal(ownerClosed.status, 200);
  assert.deepEqual(ownerClosed.value.closedTokenIds, [secondToken.value.tokenId]);
  await second.closed;
  assert.equal(service.activeSessionCount, 0);

  const replay = new WebTransport(urlFor(secondToken.value.secret), clientOptions);
  replay.closed.catch(() => {});
  const replayDenied = await Promise.race([
    replay.ready.then(() => false, () => true),
    new Promise(resolve => setTimeout(() => resolve(false), 5000)),
  ]);
  assert.equal(replayDenied, true);
  replay.close();

  const cutoffRetry = await controlRequest(origin, certificate, '/v1/rooms/close', {
    body: {shareId: 'MoqH3Ow1', epoch: 'h3-owner-epoch-0001'},
  });
  assert.equal(cutoffRetry.status, 200);
  assert.deepEqual(cutoffRetry.value.closedTokenIds, [secondToken.value.tokenId]);
});

test('managed MoQ readiness requires an authenticated Worker usage authority callback',async t=>{
  const directory=await mkdtemp(join(tmpdir(),'omniterm-moq-ready-'));
  const certificatePath=join(directory,'cert.pem'),privateKeyPath=join(directory,'key.pem');
  await run('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',privateKeyPath,
    '-out',certificatePath,'-days','1','-subj','/CN=127.0.0.1','-addext','subjectAltName=IP:127.0.0.1'],{stdio:'ignore'});
  const certificate=await readFile(certificatePath,'utf8'),port=await freePort(),origin=`https://127.0.0.1:${port}`;
  const usageToken='independent-worker-moq-usage-token-0001';
  const usageCalls=[];
  let oversizedUsageResponse=false;
  const service=await createMoqRelay({controlHost:'127.0.0.1',dataHost:'127.0.0.1',controlPort:port,
    dataPort:port,publicOrigin:origin,controlToken,usageUrl:'https://api.example.test/internal/v1/live-share/moq/usage',
    usageToken,managedUsageRequired:true,usageFetcher:async(url,init)=>{
      usageCalls.push({url:new URL(url),init});
      if(oversizedUsageResponse)return new Response(new ReadableStream({start(controller){
        controller.enqueue(new Uint8Array(16*1024+1));controller.close();
      }}),{headers:{'content-type':'application/json'}});
      return Response.json({status:'ready',protocol:'omniterm-moq-usage-v1',
        probe_id:JSON.parse(init.body).probe_id});
    },certificatePath,privateKeyPath});
  t.after(async()=>{await service.close();await rm(directory,{recursive:true,force:true});});
  const response=await controlGet(origin,certificate,'/v1/readyz');
  assert.equal(response.status,200);
  assert.deepEqual(response.value,{status:'ready',protocol:'omniterm-moq-v1',
    worker_usage_metering:true,active_session_cutoff:true});
  assert.equal(usageCalls.length,1);
  assert.equal(usageCalls[0].url.href,'https://api.example.test/internal/v1/live-share/moq/readyz');
  assert.equal(usageCalls[0].init.headers['x-live-share-moq-usage-token'],usageToken);
  oversizedUsageResponse=true;
  const oversized=await controlGet(origin,certificate,'/v1/readyz');
  assert.equal(oversized.status,503);
  const unauthorized=await controlGet(origin,certificate,'/v1/readyz','');
  assert.equal(unauthorized.status,401);
});

test('managed MoQ cannot start without its separately authenticated Worker usage authority',async()=>{
  await assert.rejects(createMoqRelay({controlToken,managedUsageRequired:true}),
    /managed_worker_usage_required/);
});

test('self-hosted readiness is honest without a managed Worker account', async t => {
  const {origin,certificate} = await fixture(t);
  const response = await controlGet(origin,certificate,'/v1/readyz');
  assert.equal(response.status,200);
  assert.deepEqual(response.value,{status:'ready',protocol:'omniterm-moq-v1',
    worker_usage_metering:false,active_session_cutoff:true});
  assert.equal((await controlGet(origin,certificate,'/v1/readyz','')).status,401);
});

for (const outcome of ['charged', 'recovery_frozen']) {
  test(`room cutoff drains a paused ${outcome} usage continuation after native QUIC closure`,
    {timeout: 20000}, async t => {
      const entered = Promise.withResolvers();
      const release = Promise.withResolvers();
      t.after(() => release.resolve());
      const usageEvents = [];
      const {origin, certificate, service} = await fixture(t, {...managedOptions,
        usageFetcher: usageAuthority(async body => {
          usageEvents.push(body);
          if (body.share_id === 'MoqRace1') {
            entered.resolve(body);
            // Deliberately retain the request until its authority finishes. A
            // native transport close or an abort signal is not callback drain.
            await release.promise;
            if (outcome === 'recovery_frozen') {
              return Response.json({error: outcome}, {status: 503});
            }
          }
          return Response.json({status: 'charged', event_id: body.event_id});
        }),
      });
      const room = await createRoom(origin, certificate, 'MoqRace1', 'usage-race-epoch-0001');
      const publisher = await connectParticipant(t, origin, certificate, room, 'host01', 'publish');
      const broadcast = new Moq.Broadcast.Producer();
      const track = broadcast.createTrack('terminal', {ordered: true, latencyMax: 5000});
      publisher.connection.publish(`omniterm/${room.epoch}`, broadcast);

      const marker = 'paused-provider-usage-frame';
      let fenced = false;
      let writesAfterFence = 0;
      const writeFrame = Moq.Group.Producer.prototype.writeFrame;
      t.mock.method(Moq.Group.Producer.prototype, 'writeFrame', function(frame) {
        if (fenced && new TextDecoder().decode(frame.payload) === marker) writesAfterFence++;
        return Reflect.apply(writeFrame, this, [frame]);
      });
      const group = track.appendGroup();
      group.writeString(marker);
      group.close();
      const event = await within(entered.promise, 'publisher did not reach Worker usage authority');
      assert.equal(event.bytes, Buffer.byteLength(marker));
      assert.match(event.event_id, /^[a-f0-9]{32}$/);

      const other = await createRoom(origin, certificate, 'MoqRace2', 'usage-race-epoch-0002');
      const otherPublisher = await connectParticipant(t, origin, certificate, other, 'host02', 'publish');
      const otherBroadcast = new Moq.Broadcast.Producer();
      const otherTrack = otherBroadcast.createTrack('terminal', {ordered: true, latencyMax: 5000});
      otherPublisher.connection.publish(`omniterm/${other.epoch}`, otherBroadcast);
      const otherViewer = await connectParticipant(t, origin, certificate, other, 'viewer02', 'subscribe');
      const subscription = otherViewer.connection.consume(`omniterm/${other.epoch}`)
        .subscribe('terminal', {ordered: true, latencyMax: 5000});
      await within(subscription.info(), 'unrelated room subscription did not become ready');

      fenced = true;
      const closing = controlRequest(origin, certificate, '/v1/rooms/close', {
        body: {shareId: room.shareId, epoch: room.epoch},
      });
      try {
        await within(publisher.connection.closed, 'provider did not close the native publisher');
        await assertPending(closing, 'cutoff acknowledged before the usage continuation drained');
        assert.equal(service.relayCount, 2);

        const unaffected = otherTrack.appendGroup();
        unaffected.writeString('unrelated-room-keeps-forwarding');
        unaffected.close();
        assert.equal(await within(subscription.readString(), 'unrelated room stopped forwarding'),
          'unrelated-room-keeps-forwarding');

        release.resolve();
        const closed = await within(closing, 'cutoff did not finish after usage authority settled');
        assert.equal(closed.status, 200);
        assert.deepEqual(closed.value.closedTokenIds, [publisher.token.tokenId]);
        assert.equal(service.relayCount, 1);
        assert.equal(service.activeSessionCount, 2);
        assert.equal(writesAfterFence, 0, 'a fenced publisher attempted to install a charged frame');
        assert.equal(usageEvents.filter(value => value.share_id === room.shareId).length, 1,
          'a pending commercial event must be retained without a replacement charge');
        const retried = await controlRequest(origin, certificate, '/v1/rooms/close', {
          body: {shareId: room.shareId, epoch: room.epoch},
        });
        assert.equal(retried.status, 200);
        assert.deepEqual(retried.value, closed.value);
      } finally { release.resolve(); }
    });
}

test('room cutoff fences and drains an allocation paused in the Worker heartbeat',
  {timeout: 15000}, async t => {
    const entered = Promise.withResolvers();
    const release = Promise.withResolvers();
    t.after(() => release.resolve());
    const {origin, certificate, service} = await fixture(t, {...managedOptions,
      usageFetcher: usageAuthority(body => Response.json({status: 'charged', event_id: body.event_id}),
        async body => {
          entered.resolve();
          await release.promise;
          return Response.json({status: 'active', share_id: body.share_id,
            session_epoch: body.session_epoch, heartbeat_id: body.heartbeat_id});
        }),
    });
    const scope = {shareId: 'MoqRace3', epoch: 'allocation-race-epoch-0001'};
    const allocation = controlRequest(origin, certificate, '/v1/relays', {
      body: {...scope, expiresAt: Date.now() + 60000, maxBytes: 1000000,
        usageOrigin: 'https://api.example.test'},
    });
    await within(entered.promise, 'allocation did not reach Worker heartbeat');
    const closing = controlRequest(origin, certificate, '/v1/rooms/close', {body: scope});
    try {
      await assertPending(closing, 'provider returned an empty proof before allocation drain');
      release.resolve();
      assert.equal((await within(allocation, 'fenced allocation did not finish')).status, 410);
      const closed = await within(closing, 'scope cutoff did not finish after allocation settled');
      assert.equal(closed.status, 200);
      assert.deepEqual(closed.value, {...scope, relayId: null, closedTokenIds: [], endRoom: true});
      assert.equal(service.relayCount, 0);
      const replay = await controlRequest(origin, certificate, '/v1/relays', {
        body: {...scope, expiresAt: Date.now() + 60000, maxBytes: 1000000,
          usageOrigin: 'https://api.example.test'},
      });
      assert.equal(replay.status, 410);
      assert.deepEqual((await controlRequest(origin, certificate, '/v1/rooms/close', {body: scope})).value,
        closed.value);
    } finally { release.resolve(); }
  });

test('cutoff timeout retains a paused forwarding task and retry confirms its later drain',
  {timeout: 20000}, async t => {
    const entered = Promise.withResolvers();
    const release = Promise.withResolvers();
    t.after(() => release.resolve());
    const {origin, certificate, service} = await fixture(t, {...managedOptions,
      usageFetcher: usageAuthority(async body => {
        entered.resolve();
        await release.promise;
        return Response.json({status: 'charged', event_id: body.event_id});
      }),
    });
    const room = await createRoom(origin, certificate, 'MoqRace4', 'drain-retry-epoch-0001');
    const publisher = await connectParticipant(t, origin, certificate, room, 'host01', 'publish');
    const broadcast = new Moq.Broadcast.Producer();
    const track = broadcast.createTrack('terminal', {ordered: true, latencyMax: 5000});
    publisher.connection.publish(`omniterm/${room.epoch}`, broadcast);
    const group = track.appendGroup();
    group.writeString('usage-stays-pending-past-close-deadline');
    group.close();
    await within(entered.promise, 'publisher did not reach usage authority');
    try {
      const failed = await within(controlRequest(origin, certificate, '/v1/rooms/close', {
        body: {shareId: room.shareId, epoch: room.epoch},
      }), 'close deadline did not return failure evidence', 7000);
      assert.equal(failed.status, 503);
      assert.equal(failed.value.error, 'active_session_close_unconfirmed');
      assert.deepEqual(failed.value.closedTokenIds, []);
      assert.equal(service.relayCount, 1, 'uncertain scope was discarded before forwarding drained');
      release.resolve();
      const closed = await within(controlRequest(origin, certificate, '/v1/rooms/close', {
        body: {shareId: room.shareId, epoch: room.epoch},
      }), 'close retry did not confirm drained forwarding');
      assert.equal(closed.status, 200);
      assert.deepEqual(closed.value.closedTokenIds, [publisher.token.tokenId]);
      assert.equal(service.relayCount, 0);
      assert.equal(service.activeSessionCount, 0);
    } finally { release.resolve(); }
  });

test('a Worker usage refusal closes and drains its publisher without waiting on its own room task',
  {timeout: 15000}, async t => {
    const usageEvents = [];
    const {origin, certificate, service} = await fixture(t, {...managedOptions,
      usageFetcher: usageAuthority(body => {
        usageEvents.push(body);
        return Response.json({error: 'recovery_frozen'}, {status: 503});
      }),
    });
    const room = await createRoom(origin, certificate, 'MoqRace5', 'usage-refusal-epoch-0001');
    const publisher = await connectParticipant(t, origin, certificate, room, 'host01', 'publish');
    const broadcast = new Moq.Broadcast.Producer();
    const track = broadcast.createTrack('terminal', {ordered: true, latencyMax: 5000});
    publisher.connection.publish(`omniterm/${room.epoch}`, broadcast);
    const group = track.appendGroup();
    group.writeString('Worker-refuses-this-commercial-event');
    group.close();
    // No control cutoff has started: the usage refusal must initiate closure
    // and return from forwardPublisher so the room task can join that publisher.
    await within(publisher.connection.closed, 'usage refusal did not close the native publisher');
    const closed = await within(controlRequest(origin, certificate, '/v1/rooms/close', {
      body: {shareId: room.shareId, epoch: room.epoch},
    }), 'usage refusal left publisher waiting on its own room drain', 2000);
    assert.equal(closed.status, 200);
    assert.deepEqual(closed.value.closedTokenIds, [publisher.token.tokenId]);
    assert.equal(service.relayCount, 0);
    assert.equal(service.activeSessionCount, 0);
    assert.equal(usageEvents.length, 1);
  });
