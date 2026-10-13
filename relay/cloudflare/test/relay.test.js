import test from 'node:test';
import { actualRelay } from './relay-runtime.mjs';
import assert from 'node:assert/strict';
import worker from '../src/index.js';
import { FreeNativeConnectorRelay } from '../src/relay.js';
import { nativeConnectorId } from '../src/relay-core.js';
import { validateRelayToken } from '../src/security.js';
import { encodeFrame, FrameDecoder } from '../src/connector-wire.js';
import {
  parseBrowserTicketProtocols,
} from '../src/browser-tickets.js';

// Synthetic test-only tokens, never deployment credentials.
const token = '00000000-0000-4000-8000-000000000001';
const other = '00000000-0000-4000-8000-000000000002';
const base = 'https://relay.example/v1/connectors/stream?connector_id=test';
const tick = () => new Promise(resolve => setImmediate(resolve));

test('health is reachable without revealing configuration', async () => {
  const response = await worker.fetch(new Request('https://relay.example/healthz'), {});
  assert.equal(response.status, 200);
  assert.equal(await response.text(), 'OK');
});
test('missing server token fails closed', async () => {
  assert.equal((await worker.fetch(new Request(base), {})).status, 500);
});
test('missing or wrong client token fails closed', async () => {
  for (const headers of [{}, {'x-workload-token': other}]) {
    assert.equal((await worker.fetch(new Request(base, {headers}), {RELAY_AUTH_TOKEN: token})).status, 401);
  }
});
test('header authentication routes to the scoped object and query tokens fail closed', async t => {
  const relay = await actualRelay(t, {RELAY_AUTH_TOKEN: token});
  const path = '/v1/connectors/stream?connector_id=test';
  // A real object handles the valid header request and requires its WebSocket upgrade.
  assert.equal((await relay.fetch(path, {headers: {'x-workload-token': token}})).status, 426);
  const namespace = await relay.runtime.getDurableObjectNamespace('NATIVE_CONNECTORS', 'public-relay');
  const expected = namespace.idFromName(JSON.stringify(['free-v1', 'test'])).toString();
  const ids = await relay.runtime.listDurableObjectIds('NATIVE_CONNECTORS', 'public-relay');
  assert(ids.includes(expected));
  for (const headers of [{}, {'x-workload-token': token}]) {
    const response = await relay.fetch(path + '&token=' + token, {headers});
    assert.equal(response.status, 401);
    assert(!(await response.text()).includes(token));
  }
});

test('native RTC is advertised only for an independently configured ingress and offers fail closed without admission', async t => {
  const disabled = await actualRelay(t, {RELAY_AUTH_TOKEN: token});
  const disabledResponse = await disabled.fetch('/internal/v1/connectors/test/rtc-offer', {
    method: 'POST', headers: {'x-workload-token': token}, body: '{}'});
  assert.equal(disabledResponse.status, 503);
  assert.equal((await disabledResponse.json()).error, 'native_rtc_unavailable');
  assert.deepEqual(await disabled.runtime.listDurableObjectIds('NATIVE_CONNECTORS', 'public-relay'), []);

  const relay = await actualRelay(t, {RELAY_AUTH_TOKEN: token,
    NATIVE_PUBLIC_RTC_ENABLED: 'true', NATIVE_RTC_INGRESS: 'https://rtc.example.test',
    NATIVE_RTC_SERVICE_TOKEN: '00000000-0000-4000-8000-000000000003'});
  const init = await relay.fetch('/relay/api/v1/init');
  assert.deepEqual((await init.json()).transports, ['websocket', 'webrtc']);
  const response = await relay.fetch('/internal/v1/connectors/test/rtc-offer', {
    method: 'POST', headers: {'x-workload-token': token}, body: '{}'});
  assert.equal(response.status, 400);
  assert.equal((await response.json()).error, 'invalid_rtc_offer');
  assert.deepEqual(await relay.runtime.listDurableObjectIds('NATIVE_CONNECTORS', 'public-relay'), []);
});

test('native RTC CORS and admission run through Workerd before ingress egress', async t => {
  let ingressCalls = 0;
  const relay = await actualRelay(t, {
    RELAY_AUTH_TOKEN: token,
    RELAY_MANAGEMENT_TOKEN: other,
    NATIVE_RELAY_BROWSER_ORIGINS: 'https://app.example',
    NATIVE_PUBLIC_RTC_ENABLED: 'true',
    NATIVE_RTC_INGRESS: 'https://rtc.example.test',
    NATIVE_RTC_SERVICE_TOKEN: '00000000-0000-4000-8000-000000000003',
  }, {outboundService: async () => {
    ingressCalls++;
    return Response.json({error: 'fixture_not_expected'}, {status: 500});
  }});

  const preflight = await relay.fetch('/internal/v1/connectors/test/rtc-offer', {
    method: 'OPTIONS', headers: {
      origin: 'https://app.example',
      'access-control-request-method': 'POST',
      'access-control-request-headers': 'content-type,x-workload-token',
    },
  });
  assert.equal(preflight.status, 204);
  assert.equal(preflight.headers.get('access-control-allow-origin'), 'https://app.example');
  assert.equal(preflight.headers.get('access-control-allow-credentials'), null);

  const deniedOrigin = await relay.fetch('/internal/v1/connectors/test/rtc-offer', {
    method: 'OPTIONS', headers: {
      origin: 'https://attacker.example',
      'access-control-request-method': 'POST',
      'access-control-request-headers': 'content-type,x-workload-token',
    },
  });
  assert.equal(deniedOrigin.status, 403);
  assert.equal(deniedOrigin.headers.get('access-control-allow-origin'), null);

  const unauthorized = await relay.fetch('/internal/v1/connectors/test/rtc-offer', {
    method: 'POST', headers: {origin: 'https://app.example'}, body: '{}',
  });
  assert.equal(unauthorized.status, 401);
  assert.equal(unauthorized.headers.get('access-control-allow-origin'), 'https://app.example');

  const admissionDenied = await relay.fetch('/internal/v1/connectors/test/rtc-offer', {
    method: 'POST', headers: {
      origin: 'https://app.example', 'x-workload-token': token, 'content-type': 'application/json',
    },
    body: JSON.stringify({
      scope: {connector_id: 'test', tenant_id: 'tenant', subject_id: 'subject', target_id: 'target',
        hostname: '127.0.0.1', port: 22, expires_at_epoch: Math.floor(Date.now() / 1000) + 60,
        required_transport: 'webrtc'},
      offer: {type: 'offer', sdp: 'v=0 offer'},
    }),
  });
  assert.equal(admissionDenied.status, 503);
  assert.equal((await admissionDenied.json()).error, 'connector_unavailable');
  assert.equal(ingressCalls, 0);
});

test('browser ticket preflight rejects query strings without reflecting them', async () => {
  const response = await worker.fetch(new Request(
    'https://relay.example/internal/v1/connectors/test/browser-ticket?token=synthetic-secret', {
      method: 'OPTIONS',
      headers: {
        origin: 'https://app.example',
        'access-control-request-method': 'POST',
        'access-control-request-headers': 'authorization,content-type',
      },
    }), {NATIVE_RELAY_BROWSER_ORIGINS: 'https://app.example'});
  assert.equal(response.status, 400);
  const body = await response.text();
  assert(!body.includes('synthetic-secret'));
  assert.equal(response.headers.get('access-control-allow-origin'), null);
});
test('browser ticket handshakes are bound to one connector and consumed once', async t => {
  const relay = await actualRelay(t, {RELAY_AUTH_TOKEN: token, NATIVE_RELAY_BROWSER_ORIGINS: 'https://app.example'});
  const response = await relay.fetch('/internal/v1/connectors/test/browser-ticket', {
    method: 'POST', headers: {origin: 'https://app.example', authorization: 'Bearer ' + token}});
  assert.equal(response.status, 200);
  const ticket = await response.json();
  assert(ticket.expires_at_epoch <= Math.floor(Date.now() / 1000) + 30);
  const headers = {origin: 'https://app.example', upgrade: 'websocket',
    'sec-websocket-protocol': ticket.websocket_protocols.join(', ')};
  assert.equal((await relay.fetch('/internal/v1/connectors/other/dial-stream', {headers})).status, 401);
  assert.equal((await relay.fetch('/internal/v1/connectors/test/dial-stream', {headers})).status, 101);
  assert.equal((await relay.fetch('/internal/v1/connectors/test/dial-stream', {headers})).status, 401);
});

test('browser tickets are origin and connector bound, short-lived and consumed once', async t => {
  const relay = await actualRelay(t, {RELAY_AUTH_TOKEN: token, NATIVE_RELAY_BROWSER_ORIGINS: 'https://app.example'});
  const response = await relay.fetch('/internal/v1/connectors/test/browser-ticket', {
    method: 'POST', headers: {origin: 'https://app.example', authorization: 'Bearer ' + token}});
  assert.equal(response.status, 200);
  const value = await response.json();
  assert(value.expires_at_epoch <= Math.floor(Date.now() / 1000) + 30);
  assert(value.websocket_protocols.length === 2 && value.websocket_protocols[0] === 'omni-relay.v1');
  assert.equal(value.ticket.length, 43);
  assert.equal(parseBrowserTicketProtocols(value.websocket_protocols.join(',')).ticket, value.ticket);
  const headers = {origin: 'https://attacker.example', upgrade: 'websocket',
    'sec-websocket-protocol': value.websocket_protocols.join(', ')};
  assert.equal((await relay.fetch('/internal/v1/connectors/test/dial-stream', {headers})).status, 401);
  headers.origin = 'https://app.example';
  assert.equal((await relay.fetch('/internal/v1/connectors/test/dial-stream', {headers})).status, 101);
  assert.equal((await relay.fetch('/internal/v1/connectors/test/dial-stream', {headers})).status, 401);
});

test('self-hosted browser ticket issuance does not trust a forged forwarded Origin', async t => {
  const relay = await actualRelay(t, {RELAY_AUTH_TOKEN: token, NATIVE_RELAY_BROWSER_ORIGINS: 'https://app.example'});
  const response = await relay.direct('test', new Request('https://relay.example/internal/v1/connectors/test/browser-ticket', {
    method: 'POST', headers: {origin: 'https://attacker.example',
      'x-native-relay-browser-origin': 'https://attacker.example', 'x-workload-token': token}}));
  assert.equal(response.status, 403);
  assert.equal((await response.json()).error, 'origin_forbidden');
});

test('browser tickets expire at the deadline and concurrent replay consumes only once', {timeout: 45000}, async t => {
  const relay = await actualRelay(t, {RELAY_AUTH_TOKEN: token, NATIVE_RELAY_BROWSER_ORIGINS: 'https://app.example'});
  const issue = async () => {
    const response = await relay.fetch('/internal/v1/connectors/test/browser-ticket', {
      method: 'POST', headers: {origin: 'https://app.example', authorization: 'Bearer ' + token}});
    assert.equal(response.status, 200); return response.json();
  };
  const expired = await issue();
  const fresh = await issue();
  const headers = {origin: 'https://app.example', upgrade: 'websocket',
    'sec-websocket-protocol': fresh.websocket_protocols.join(', ')};
  const attempts = await Promise.all([
    relay.fetch('/internal/v1/connectors/test/dial-stream', {headers}),
    relay.fetch('/internal/v1/connectors/test/dial-stream', {headers}),
  ]);
  assert.deepEqual(attempts.map(response => response.status).sort(), [101, 401]);
  const remaining = expired.expires_at_epoch * 1000 - Date.now();
  if (remaining > 0) await new Promise(resolve => setTimeout(resolve, remaining + 20));
  headers['sec-websocket-protocol'] = expired.websocket_protocols.join(', ');
  assert.equal((await relay.fetch('/internal/v1/connectors/test/dial-stream', {headers})).status, 401);
});

test('duplicate connector identifiers are rejected', async () => {
  assert.equal(nativeConnectorId(new Request(base + '&connector_id=other')), null);
  const req = new Request(base + '&connector_id=other', {headers: {'x-workload-token': token}});
  assert.equal((await worker.fetch(req, {RELAY_AUTH_TOKEN: token})).status, 400);
});
test('token validation rejects whitespace and weak passwords', () => {
  assert.equal(validateRelayToken(token), null);
  for (const value of ['', 'password', token + '\n', 'abc DEF 123!']) assert.notEqual(validateRelayToken(value), null);
});
test('authenticated free streams can transfer more than handshake budget', async () => {
  const relay = new FreeNativeConnectorRelay({}, {});
  const stream = {authenticated: true, handshakeBytes: 64000};
  let total = 0; const closed = [];
  const send = relay.meteredQueue('self-host', stream, () => true, data => total += data.length, why => closed.push(why));
  for (let i=0; i<16; i++) { send(new Uint8Array(32768)); await tick(); }
  assert.equal(total, 524288);
  assert.deepEqual(closed, []);
  assert.equal(relay.queuedBytes, 0);
});
test('unauthenticated handshake remains bounded', async () => {
  const relay = new FreeNativeConnectorRelay({}, {});
  const stream = {authenticated: false, handshakeBytes: 0};
  let total = 0; const closed = [];
  const send = relay.meteredQueue('self-host', stream, () => true, data => total += data.length, why => closed.push(why));
  send(new Uint8Array(65536)); await tick(); send(new Uint8Array(1)); await tick();
  assert.equal(total, 65536); assert.deepEqual(closed, ['relay_authentication_budget_exceeded']);
});
test('backpressure rejects oversized messages even after authentication', () => {
  const relay = new FreeNativeConnectorRelay({}, {});
  let reason;
  relay.meteredQueue('self-host', {authenticated: true}, () => true, () => assert.fail(), value => reason=value)(new Uint8Array(262145));
  assert.equal(reason, 'relay_backpressure_limit');
});
test('wire codec preserves 64-bit heartbeat values', () => {
  const frames = new FrameDecoder().push(encodeFrame({type:'Ping',value:9007199254740993n}));
  assert.equal(frames[0].value, 9007199254740993n);
});
test('free relay denies datagram routes', async t => {
  const relay = await actualRelay(t, {RELAY_AUTH_TOKEN: token});
  const response = await relay.fetch('/internal/v1/connectors/test/dial-datagram', {headers: {'x-workload-token': token}});
  assert.equal(response.status, 403);
});
