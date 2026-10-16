import test from 'node:test';
import assert from 'node:assert/strict';
import {
  encodeFrame, decodeFrame, FrameDecoder, validateDestinationScope,
  SCOPED_DESTINATION_CAPABILITY,
} from '../src/connector-wire.js';

const dial = () => ({ type: 'DialScoped', stream_id: 1, target_id: 't', hostname: 'h', port: 22,
  scope_version: 1, allow_private_network: false, allowed_network_cidrs: [] });

// Construct an independent postcard payload so decode failures do not depend
// on the producer's validation or accidentally exercise only its encoder.
function scopedPayload({ version = 1, flag = 0, cidrs = [], count = cidrs.length } = {}) {
  const out = [47, 1, 1, 116, 1, 104, 22, version, flag, count];
  for (const cidr of cidrs) {
    const bytes = new TextEncoder().encode(cidr);
    out.push(bytes.length, ...bytes);
  }
  return Uint8Array.from(out);
}

test('scoped destination uses capability 8192 and appends tag 47 in the exact field order', () => {
  assert.equal(SCOPED_DESTINATION_CAPABILITY, 8192);
  const encoded = encodeFrame(dial());
  assert.deepEqual([...encoded], [0, 0, 0, 10, 47, 1, 1, 116, 1, 104, 22, 1, 0, 0]);
  assert.deepEqual(new FrameDecoder().push(encoded), [dial()]);
  const scoped = { ...dial(), allow_private_network: true, allowed_network_cidrs: ['10.0.0.0/8'] };
  assert.deepEqual([...encodeFrame(scoped)], [0, 0, 0, 21, 47, 1, 1, 116, 1, 104, 22, 1, 1, 1,
    10, 49, 48, 46, 48, 46, 48, 46, 48, 47, 56]);
  assert.deepEqual(decodeFrame(scopedPayload({ flag: 1, cidrs: ['10.0.0.0/8'] })), scoped);
});

test('existing Dial, Capabilities and desktop tags keep their published byte vectors', () => {
  assert.deepEqual([...encodeFrame({ type: 'Dial', stream_id: 1, target_id: 't', hostname: 'h', port: 22 })],
    [0, 0, 0, 7, 2, 1, 1, 116, 1, 104, 22]);
  assert.deepEqual([...encodeFrame({ type: 'Capabilities', capabilities: 4096 })], [0, 0, 0, 3, 29, 128, 32]);
  for (const [type, tag] of [['OrdinaryDesktopSignalRequest', 44], ['OrdinaryDesktopSignalReply', 45],
    ['OrdinaryDesktopServiceRetired', 46]]) {
    assert.deepEqual([...encodeFrame({ type, payload: Uint8Array.of(7) })], [0, 0, 0, 3, tag, 1, 7]);
  }
});

test('a DialScoped requires a nonzero stream and port, explicit version and a real boolean', () => {
  for (const change of [{ stream_id: 0 }, { port: 0 }, { scope_version: 0 }, { scope_version: 2 },
    { scope_version: undefined }, { allow_private_network: undefined }, { allow_private_network: 1 },
    { allowed_network_cidrs: undefined }, { allowed_network_cidrs: Array(33).fill('10.0.0.0/8') }]) {
    assert.throws(() => encodeFrame({ ...dial(), ...change }), /invalid connector frame/);
  }
  assert.throws(() => decodeFrame(scopedPayload({ version: 2 })), /invalid connector frame/);
  assert.throws(() => decodeFrame(scopedPayload({ flag: 2 })), /invalid connector frame/);
  assert.throws(() => decodeFrame(scopedPayload({ count: 33 })), /invalid connector frame/);
  const zeroId = scopedPayload(); zeroId[1] = 0;
  assert.throws(() => decodeFrame(zeroId), /invalid connector frame/);
  const zeroPort = scopedPayload(); zeroPort[6] = 0;
  assert.throws(() => decodeFrame(zeroPort), /invalid connector frame/);
});

test('scoped CIDRs require canonical addresses, canonical prefix lengths and zero host bits', () => {
  for (const cidr of ['10.0.0.0/8', '0.0.0.0/0', '192.0.2.7/32', '::/0', '2001:db8::/32',
    '2001:db8::1/128']) {
    const frame = { ...dial(), allowed_network_cidrs: [cidr] };
    assert.deepEqual(new FrameDecoder().push(encodeFrame(frame)), [frame]);
    assert.deepEqual(decodeFrame(scopedPayload({ cidrs: [cidr] })), frame);
  }
  for (const cidr of ['', '10.0.0.1/8', '10.0.0.0/08', '010.0.0.0/8', '10.0.0.0/33',
    '256.0.0.0/8', '10.0.0.0', '10.0.0.0/8/8', ' 10.0.0.0/8', '10.0.0.0/8\n',
    '2001:DB8::/32', '2001:0db8::/32', '2001:db8:0:0:0:0:0:0/32', '2001:db8::1/32',
    '2001:db8::/129', '::ffff:c000:200/120', '::ffff:192.0.2.1/120', '[::]/0', '::%lo/0',
    ':::/0', '1::2::3/64', 'f'.repeat(44)]) {
    assert.throws(() => encodeFrame({ ...dial(), allowed_network_cidrs: [cidr] }), /invalid connector frame/, cidr);
    assert.throws(() => decodeFrame(scopedPayload({ cidrs: [cidr] })), /invalid connector frame/, cidr);
  }
});

test('scoped CIDRs reject IPv4-mapped IPv6 networks and require canonical IPv4 notation', () => {
  for (const cidr of ['::ffff:10.0.0.0/104', '::ffff:192.0.2.0/120', '::ffff:0.0.0.0/96',
    '0:0:0:0:0:ffff:a00:0/104']) {
    assert.throws(() => encodeFrame({ ...dial(), allowed_network_cidrs: [cidr] }), /invalid connector frame/, cidr);
    assert.throws(() => decodeFrame(scopedPayload({ cidrs: [cidr] })), /invalid connector frame/, cidr);
  }
  for (const cidr of ['10.0.0.0/8', '192.0.2.0/24', '0.0.0.0/0']) {
    const frame = { ...dial(), allowed_network_cidrs: [cidr] };
    assert.deepEqual(new FrameDecoder().push(encodeFrame(frame)), [frame]);
  }
});

test('32 canonical CIDRs fit the bounded scope and scope snapshots own their immutable array', () => {
  const original = { scope_version: 1, allow_private_network: false, allowed_network_cidrs: Array(32).fill('10.0.0.0/8') };
  const scope = validateDestinationScope(original);
  original.allowed_network_cidrs[0] = '127.0.0.0/8';
  original.allow_private_network = true;
  assert.equal(scope.allow_private_network, false);
  assert.equal(scope.allowed_network_cidrs[0], '10.0.0.0/8');
  assert.ok(Object.isFrozen(scope));
  assert.ok(Object.isFrozen(scope.allowed_network_cidrs));
  assert.throws(() => scope.allowed_network_cidrs.push('0.0.0.0/0'), TypeError);
  const frame = { ...dial(), ...scope, stream_id: 0xffffffff };
  assert.deepEqual(new FrameDecoder().push(encodeFrame(frame)), [frame]);
});

test('a scoped frame cannot be truncated, extended or decoded as a legacy Dial', () => {
  const payload = scopedPayload();
  assert.throws(() => decodeFrame(payload.subarray(0, payload.length - 1)), /invalid connector frame/);
  assert.throws(() => decodeFrame(Uint8Array.from([...payload, 0])), /invalid connector frame/);
  const legacyTag = Uint8Array.from(payload); legacyTag[0] = 2;
  assert.throws(() => decodeFrame(legacyTag), /invalid connector frame/);
});
