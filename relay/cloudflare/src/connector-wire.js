// Native connector-protocol postcard framing. Keep enum tags append-only and
// integer handling exact: counters and Ping/Pong values must never pass through
// a floating-point Number when they exceed JavaScript's safe integer range.
const MAX_FRAME = 1024 * 1024;
const MAX_DATA = 256 * 1024;
const MAX_IDENTIFIER = 256;
const utf8 = new TextEncoder();
const text = new TextDecoder('utf-8', { fatal: true });
const TYPES = ['Hello', 'HelloAccepted', 'Dial', 'DialAccepted', 'Data', 'WindowUpdate', 'Close', 'Telemetry', 'Ping', 'Pong', 'DatagramDial', 'DatagramDialAccepted', 'Datagram', 'DatagramClose'];
TYPES[29] = 'Capabilities';
TYPES[36] = 'HelloChallenge';
TYPES[37] = 'ClientAuthenticated';

function fail() { throw new Error('invalid connector frame'); }

function bytes(value) {
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  fail();
}

function integer(value, bits) {
  if (typeof value !== 'bigint' && !(typeof value === 'number' && Number.isSafeInteger(value))) fail();
  const n = BigInt(value);
  if (n < 0n || n >= (1n << BigInt(bits))) fail();
  return n;
}

class Reader {
  constructor(value) { this.bytes = value; this.at = 0; }
  byte() { if (this.at >= this.bytes.length) fail(); return this.bytes[this.at++]; }
  uint(bits = 32) {
    let n = 0n;
    for (let i = 0; i < Math.ceil(bits / 7); i++) {
      const b = this.byte();
      n |= BigInt(b & 127) << BigInt(i * 7);
      if (!(b & 128)) {
        if ((i && b === 0) || n >= (1n << BigInt(bits))) fail();
        return bits > 32 ? n : Number(n);
      }
    }
    fail();
  }
  blob(max) {
    const n = this.uint();
    if (!n || n > max || n > this.bytes.length - this.at) fail();
    const value = this.bytes.slice(this.at, this.at + n); this.at += n; return value;
  }
  string() {
    const value = text.decode(this.blob(MAX_IDENTIFIER));
    if (!value.trim() || value.includes('\0')) fail();
    return value;
  }
  optional() { const tag = this.byte(); if (tag > 1) fail(); return tag ? this.uint(64) : null; }
}

class Writer {
  constructor() { this.parts = []; }
  uint(value, bits = 32) {
    let n = integer(value, bits);
    do { const b = Number(n & 127n); n >>= 7n; this.parts.push(b | (n ? 128 : 0)); } while (n);
  }
  blob(value, max) {
    const b = bytes(value); if (!b.length || b.length > max) fail();
    this.uint(b.length); for (const v of b) this.parts.push(v);
  }
  string(value) { if (typeof value !== 'string' || !value.trim() || value.includes('\0')) fail(); this.blob(utf8.encode(value), MAX_IDENTIFIER); }
  optional(value) { this.parts.push(value == null ? 0 : 1); if (value != null) this.uint(value, 64); }
}

function fields(io, frame, writing) {
  const u = (key, bits = 32) => { if (writing) io.uint(frame[key], bits); else frame[key] = io.uint(bits); };
  const s = key => { if (writing) io.string(frame[key]); else frame[key] = io.string(); };
  const b = (key, max) => { if (writing) io.blob(frame[key], max); else frame[key] = io.blob(max); };
  const o = key => { if (writing) io.optional(frame[key]); else frame[key] = io.optional(); };
  switch (frame.type) {
    case 'Hello': u('version', 16); s('connector_id'); s('tenant_id'); b('nonce', 16384); b('signature', 16384); if (!frame.version) fail(); break;
    case 'HelloAccepted': u('version', 16); s('lease_id'); if (!frame.version) fail(); break;
    case 'Dial': case 'DatagramDial':
      u(frame.type === 'Dial' ? 'stream_id' : 'datagram_id'); s('target_id'); s('hostname'); u('port', 16); if (!frame.port) fail(); break;
    case 'DialAccepted': u('stream_id'); break;
    case 'ClientAuthenticated': u('stream_id'); if (!frame.stream_id) fail(); break;
    case 'Data': u('stream_id'); b('bytes', MAX_DATA); break;
    case 'WindowUpdate': u('stream_id'); u('receive_window'); if (!frame.receive_window || frame.receive_window > MAX_DATA) fail(); break;
    case 'Close': u('stream_id'); s('reason'); break;
    case 'Telemetry': {
      s('target_id'); u('sequence', 64);
      if (writing) { const n = frame.collected_at_epoch_ms; io.uint(integer(n, 63) << 1n, 64); }
      else { const n = io.uint(64); if (n & 1n) fail(); frame.collected_at_epoch_ms = n >> 1n; }
      u('cpu_percent_milli'); u('memory_used_bytes', 64); u('memory_total_bytes', 64);
      o('disk_used_bytes'); o('disk_total_bytes'); u('network_rx_bytes', 64); u('network_tx_bytes', 64);
      if (frame.cpu_percent_milli > 100000 || BigInt(frame.memory_total_bytes) === 0n || BigInt(frame.memory_used_bytes) > BigInt(frame.memory_total_bytes)) fail();
      if ((frame.disk_used_bytes == null) !== (frame.disk_total_bytes == null)) fail();
      if (frame.disk_total_bytes != null && (BigInt(frame.disk_total_bytes) === 0n || BigInt(frame.disk_used_bytes) > BigInt(frame.disk_total_bytes))) fail();
      break;
    }
    case 'Ping': case 'Pong': u('value', 64); break;
    case 'DatagramDialAccepted': u('datagram_id'); break;
    case 'Datagram': u('datagram_id'); b('bytes', 65536); break;
    case 'DatagramClose': u('datagram_id'); s('reason'); break;
    case 'Capabilities': u('capabilities'); break;
    case 'HelloChallenge': b('nonce', 32); if (frame.nonce.length !== 32) fail(); break;
    default: fail();
  }
  if (frame.type.startsWith('Datagram') && !frame.datagram_id) fail();
}

export function decodeFrame(payload) {
  const r = new Reader(bytes(payload));
  const tag = r.uint(32);
  const type = TYPES[tag];
  if (!type) fail();
  const frame = { type };
  fields(r, frame, false);
  if (r.at !== r.bytes.length) fail();
  return frame;
}

export function encodeFrame(frame) {
  const tag = TYPES.indexOf(frame.type);
  if (tag < 0) fail();
  const w = new Writer();
  w.uint(tag, 32);
  fields(w, frame, true);
  const total = w.parts.reduce((n, p) => n + (typeof p === 'number' ? 1 : p.length), 0);
  if (total > MAX_FRAME) fail();
  const out = new Uint8Array(4 + total);
  new DataView(out.buffer).setUint32(0, total);
  let at = 4;
  for (const p of w.parts) {
    if (typeof p === 'number') out[at++] = p;
    else { out.set(p, at); at += p.length; }
  }
  return out;
}

export class FrameDecoder {
  constructor() { this.buffer = new Uint8Array(0); }
  push(chunk) {
    const b = bytes(chunk);
    if (!b.length) return [];
    if (this.buffer.length + b.length > MAX_FRAME + 4) fail();
    const next = new Uint8Array(this.buffer.length + b.length);
    next.set(this.buffer); next.set(b, this.buffer.length);
    this.buffer = next;
    const frames = [];
    while (this.buffer.length >= 4) {
      const len = new DataView(this.buffer.buffer, this.buffer.byteOffset).getUint32(0);
      if (!len || len > MAX_FRAME) fail();
      if (this.buffer.length < len + 4) break;
      frames.push(decodeFrame(this.buffer.subarray(4, len + 4)));
      this.buffer = this.buffer.slice(len + 4);
    }
    return frames;
  }
}

export function helloTranscript(version, connector, tenant, nonce) {
  const domain = utf8.encode('omniterminal/connector-hello/v1\0');
  const parts = [utf8.encode(connector), utf8.encode(tenant), bytes(nonce)];
  const out = new Uint8Array(domain.length + 2 + parts.reduce((n, p) => n + 4 + p.length, 0));
  out.set(domain); const view = new DataView(out.buffer); view.setUint16(domain.length, version);
  let at = domain.length + 2;
  for (const part of parts) { view.setUint32(at, part.length); at += 4; out.set(part, at); at += part.length; }
  return out;
}

function base64(value) {
  if (!/^[A-Za-z0-9+/_-]+={0,2}$/.test(value)) fail();
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/').replace(/=+$/, '');
  const raw = atob(normalized); if (btoa(raw).replace(/=+$/, '') !== normalized) fail();
  return Uint8Array.from(raw, c => c.charCodeAt(0));
}

export function registeredEd25519Key(value) {
  if (typeof value !== 'string' || value.length > 8192) fail();
  value = value.trim();
  if (/^[a-fA-F0-9]{64}$/.test(value)) return Uint8Array.from(value.match(/../g), h => parseInt(h, 16));
  if (value.startsWith('ssh-ed25519 ')) {
    const wire = base64(value.split(/\s+/)[1]); let at = 0;
    const take = () => { if (at + 4 > wire.length) fail(); const n = new DataView(wire.buffer, wire.byteOffset).getUint32(at); at += 4; if (n > wire.length - at) fail(); const part = wire.subarray(at, at + n); at += n; return part; };
    if (text.decode(take()) !== 'ssh-ed25519') fail();
    const key = take(); if (key.length !== 32 || at !== wire.length) fail(); return key;
  }
  const key = base64(value); if (key.length !== 32) fail(); return key;
}

export async function verifyHello(frame, record, nonce) {
  try {
    nonce = bytes(nonce);
    if (frame.type !== 'Hello' || ![1, 2].includes(frame.version) || frame.connector_id !== record.connector_id || frame.tenant_id !== record.tenant_id || nonce.length !== 32 || frame.nonce.length !== 32 || frame.signature.length !== 64) return false;
    let difference = 0; for (let i = 0; i < 32; i++) difference |= nonce[i] ^ frame.nonce[i];
    if (difference) return false;
    const key = await crypto.subtle.importKey('raw', registeredEd25519Key(record.public_key), { name: 'Ed25519' }, false, ['verify']);
    return await crypto.subtle.verify('Ed25519', key, frame.signature, helloTranscript(frame.version, frame.connector_id, frame.tenant_id, nonce));
  } catch { return false; }
}
