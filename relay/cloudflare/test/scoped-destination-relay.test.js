import test from 'node:test';
import assert from 'node:assert/strict';
import { RelayCore } from '../src/relay-core.js';
import { encodeFrame, FrameDecoder, SCOPED_DESTINATION_CAPABILITY } from '../src/connector-wire.js';

const destination = Object.freeze({ target_id: 'target', hostname: 'registered.example.test', port: 22 });
const publicOnly = { scope_version: 1, allow_private_network: false, allowed_network_cidrs: [] };

class AuthorizedRelay extends RelayCore {
  // Timers and enrollment/identity are independent boundaries. Exercise the
  // real framing and stream admission engine with an already authorized target.
  touch() {}
  async authorizeRegistration() { return this.record; }
  async authorizeDial() { return { agent: this.agent, destination }; }
}

const activeFixtures = new Set();
test.afterEach(() => {
  for (const relay of activeFixtures) for (const agent of relay.agents.values()) {
    clearTimeout(agent.timer);
    for (const stream of agent.streams.values()) clearTimeout(stream.timer);
  }
  activeFixtures.clear();
});

function fixture(env = {}, options = {}) {
  const relay = new AuthorizedRelay({}, env), sent = [], closed = [];
  activeFixtures.add(relay);
  relay.record = { connector_id: 'connector', tenant_id: 'tenant', subject_id: 'account', ...destination };
  const socket = { readyState: 1, send: bytes => sent.push(bytes), close() {} };
  const agent = { socket, closed: false, record: relay.record, requestedId: 'connector', nonce: new Uint8Array(32),
    version: options.version ?? 2, capabilitiesReceived: options.received ?? true,
    capabilities: options.capabilities ?? SCOPED_DESTINATION_CAPABILITY,
    desktopCapabilities: 0, streams: new Map(), decoder: new FrameDecoder(), lastSeen: Date.now() };
  relay.agent = agent;
  relay.agents.set('connector', agent);
  const client = { readyState: 1, send() {}, close() {} };
  const pending = { socket: client, closed: false, request: null };
  const close = reason => closed.push(reason);
  const begin = (body = {}, request = new Request('https://relay.test/internal/v1/connectors/connector/dial-stream')) =>
    relay.beginDial('connector', JSON.stringify(body), client, pending, close, request);
  return { relay, agent, sent, closed, pending, begin, frames: () => new FrameDecoder().push(sent.at(-1)) };
}

for (const purpose of ['raw-tcp', 'raw-udp', 'ftp', 'native-ssh', 'terminal']) {
  test(`a browser ${purpose} request cannot broaden the broker-owned destination scope`, async () => {
    const f = fixture();
    await f.begin({ purpose, native_purpose: purpose, ssh_purpose: purpose, allow_private_network: true,
      allowed_network_cidrs: ['127.0.0.0/8'], destination_scope: { ...publicOnly, allow_private_network: true } },
    new Request('https://relay.test/internal/v1/connectors/connector/dial-stream', { headers: {
      origin: 'https://native.example.test', 'x-native-relay-purpose': purpose,
      'x-native-relay-origin': 'native', 'x-leapterm-allow-local-network': 'true',
    } }));
    assert.deepEqual(f.closed, []);
    assert.deepEqual(f.frames(), [{ type: 'DialScoped', stream_id: 1, ...destination, ...publicOnly }]);
    assert.equal(f.pending.stream.destinationScope, f.relay.destinationScope);
    assert.ok(Object.isFrozen(f.pending.stream.destinationScope.allowed_network_cidrs));
  });
}

for (const [value, allowed] of [[undefined, false], ['true', true], ['TRUE', true], ['TrUe', true], ['1', true],
  ['false', false], ['0', false], ['yes', false], ['true ', false], [' true', false], [true, false], [1, false]]) {
  test(`operator local-network flag ${JSON.stringify(value)} produces the exact policy ${allowed}`, async () => {
    const f = fixture({ LEAPTERM_ALLOW_LOCAL_NETWORK: value });
    await f.begin({ allow_private_network: !allowed, allowed_network_cidrs: ['0.0.0.0/0'] });
    assert.deepEqual(f.frames(), [{ type: 'DialScoped', stream_id: 1, ...destination,
      ...publicOnly, allow_private_network: allowed }]);
  });
}

test('the constructor snapshot cannot be broadened by later environment or authorization-result mutation', async () => {
  const env = { LEAPTERM_ALLOW_LOCAL_NETWORK: 'false' }, f = fixture(env);
  env.LEAPTERM_ALLOW_LOCAL_NETWORK = 'true';
  f.relay.authorizeDial = async () => ({ agent: f.agent, destination,
    destinationScope: { ...publicOnly, allow_private_network: true, allowed_network_cidrs: ['0.0.0.0/0'] } });
  assert.throws(() => { f.relay.destinationScope = { ...publicOnly, allow_private_network: true }; }, TypeError);
  await f.begin();
  assert.deepEqual(f.frames(), [{ type: 'DialScoped', stream_id: 1, ...destination, ...publicOnly }]);
});

for (const options of [{ version: 1 }, { capabilities: 0 }, { capabilities: 4096 }, { received: false }]) {
  test(`network dial denies before allocation when scoped support is absent: ${JSON.stringify(options)}`, async () => {
    const f = fixture({ NATIVE_RELAY_MODE: 'self_hosted' }, options);
    f.relay.isFreeRelay = true;
    await f.begin({ native_purpose: 'native-ssh', allow_private_network: true });
    assert.deepEqual(f.closed, ['scoped_destination_required']);
    assert.equal(f.relay.nextStream, 1);
    assert.equal(f.agent.streams.size, 0);
    assert.equal(f.pending.stream, undefined);
    assert.equal(f.sent.length, 0);
  });
}

test('v2 Hello advertises scoped support and negotiation retains only broker-supported capability bits', async () => {
  const f = fixture();
  f.agent.record = null;
  f.relay.agents.clear();
  await f.relay.agentMessage(f.agent, encodeFrame({ type: 'Hello', version: 2, connector_id: 'connector',
    tenant_id: 'tenant', nonce: new Uint8Array(32), signature: new Uint8Array(64) }));
  assert.deepEqual(new FrameDecoder().push(f.sent[1]), [{ type: 'Capabilities', capabilities: 8192 }]);
  assert.equal(f.agent.capabilities, 0);
  assert.equal(f.agent.capabilitiesReceived, false);
  await f.relay.agentMessage(f.agent, encodeFrame({ type: 'Capabilities', capabilities: 8192 + 4096 + 0x80000000 }));
  assert.equal(f.agent.capabilitiesReceived, true);
  assert.equal(f.agent.capabilities, 8192);
  assert.equal(f.agent.desktopCapabilities, 0);
  await f.begin();
  assert.equal(f.frames()[0].type, 'DialScoped');
});

test('v1 Hello and a v2 capability announcement without scoped support are rejected', async () => {
  const old = fixture(); old.agent.record = null; old.relay.agents.clear();
  await assert.rejects(old.relay.agentMessage(old.agent, encodeFrame({ type: 'Hello', version: 1,
    connector_id: 'connector', tenant_id: 'tenant', nonce: new Uint8Array(32), signature: new Uint8Array(64) })),
  /scoped_destination_required/);
  const incapable = fixture({}, { received: false, capabilities: 0 });
  await assert.rejects(incapable.relay.agentMessage(incapable.agent, encodeFrame({ type: 'Capabilities', capabilities: 4096 })),
    /scoped_destination_required/);
  assert.equal(incapable.agent.capabilities, 0);
});

test('the Agent/control direction cannot supply a scoped dial to a broker', async () => {
  const f = fixture();
  await assert.rejects(f.relay.agentMessage(f.agent, encodeFrame({ type: 'DialScoped', stream_id: 1,
    ...destination, ...publicOnly })), /unexpected_agent_frame/);
  assert.equal(f.agent.streams.size, 0);
  assert.equal(f.sent.length, 0);
});

test('capability loss across an asynchronous allocation cannot emit a network dial', async () => {
  const f = fixture();
  f.relay.allocateStreamId = async () => { f.agent.capabilities = 0; return 1; };
  await f.begin();
  assert.deepEqual(f.closed, ['scoped_destination_required']);
  assert.equal(f.agent.streams.size, 0);
  assert.equal(f.sent.length, 0);
});
