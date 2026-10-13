// Public RTC signaling adapter. The configured native ingress owns DTLS;
// this module retains relay admission and binds every response to its offer.
import { isValidRelayToken, timingSafeEqual } from './security.js';
import { authorizedBrowserOrigin } from './browser-tickets.js';

const route = /^\/internal\/v1\/connectors\/([A-Za-z0-9_-]{1,128})\/rtc-offer$/;
const secret = value => isValidRelayToken(value);
const id = value => typeof value === 'string' && /^[A-Za-z0-9_-]{1,128}$/.test(value);
const encoder = new TextEncoder();
const error = (code, status) => Response.json({ error: code }, {
  status, headers: { 'cache-control': 'no-store' },
});

export const rtcRoute = path => route.exec(path);

function loopback(hostname) {
  const value = hostname.toLowerCase().replace(/\.$/, '');
  return value === 'localhost' || value === '[::1]' || value === '127.0.0.1';
}

export function rtcConfiguration(env, sourceOrigin, allowLoopbackIngress = false) {
  if (env.NATIVE_PUBLIC_RTC_ENABLED !== 'true') return null;
  try {
    const endpoint = new URL(env.NATIVE_RTC_INGRESS);
    const token = env.NATIVE_RTC_SERVICE_TOKEN;
    const hostname = endpoint.hostname.toLowerCase().replace(/\.+$/, '');
    const local = loopback(hostname);
    const localAlias = hostname.endsWith('.localhost') || hostname.startsWith('127.');
    const internal = hostname === 'internal' || hostname.endsWith('.internal');
    const source = sourceOrigin instanceof URL ? sourceOrigin.origin : sourceOrigin;
    if (endpoint.username || endpoint.password || endpoint.search || endpoint.hash ||
        endpoint.pathname !== '/' || endpoint.port === '0' ||
        internal || (localAlias && !local) || (local && !allowLoopbackIngress) ||
        (endpoint.protocol !== 'https:' && !(allowLoopbackIngress && local && endpoint.protocol === 'http:')) ||
        (source && endpoint.origin === source) || !secret(token) ||
        ['RELAY_AUTH_TOKEN', 'RELAY_MANAGEMENT_TOKEN', 'NATIVE_RELAY_ORIGIN_TOKEN',
          'NATIVE_RELAY_AUTHORITY_TOKEN', 'WORKLOAD_SECRET', 'CONNECTOR_MANAGEMENT_SECRET',
          'RELAY_METERING_SECRET', 'ADMIN_SECRET']
          .some(name => env[name] && timingSafeEqual(token, env[name]))) return null;
    return { endpoint, token };
  } catch {
    return null;
  }
}

export function rtcCorsHeaders(origin) {
  return {
    'access-control-allow-origin': origin,
    'cache-control': 'no-store',
    vary: 'Origin',
  };
}

export function rtcCorsPreflight(request, env) {
  const origin = authorizedBrowserOrigin(request, env);
  const requestedHeaders = new Set((request.headers.get('access-control-request-headers') || '')
    .toLowerCase().split(',').map(value => value.trim()).filter(Boolean));
  if (request.method !== 'OPTIONS' || !origin ||
      request.headers.get('access-control-request-method') !== 'POST' ||
      [...requestedHeaders].some(value => !['content-type', 'x-workload-token'].includes(value))) {
    return error('origin_forbidden', 403);
  }
  return new Response(null, { status: 204, headers: {
    ...rtcCorsHeaders(origin),
    allow: 'POST, OPTIONS',
    'access-control-allow-methods': 'POST, OPTIONS',
    'access-control-allow-headers': 'Content-Type, X-Workload-Token',
    'access-control-max-age': '300',
  } });
}

function withOrigin(response, origin) {
  if (!origin) return response;
  const headers = new Headers(response.headers);
  for (const [name, value] of Object.entries(rtcCorsHeaders(origin))) headers.set(name, value);
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

export const withRtcCors = withOrigin;

async function readBody(request) {
  const sizeHeader = request.headers.get('content-length');
  if (/^\d+$/.test(sizeHeader ?? '') && Number(sizeHeader) > 32768) return null;
  if (!request.body) return '';
  const reader = request.body.getReader();
  const chunks = [];
  let size = 0;
  try {
    for (;;) {
      const next = await reader.read();
      if (next.done) break;
      size += next.value.byteLength;
      if (size > 32768) {
        await reader.cancel();
        return null;
      }
      chunks.push(next.value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
}

function tupleBytes(domain, fields) {
  const values = [domain, ...fields].map(value => encoder.encode(value));
  const length = values.reduce((total, value) => total + 4 + value.byteLength, 0);
  const output = new Uint8Array(length);
  const view = new DataView(output.buffer);
  let offset = 0;
  for (const value of values) {
    view.setUint32(offset, value.byteLength);
    offset += 4;
    output.set(value, offset);
    offset += value.byteLength;
  }
  return output;
}

function hex(bytes) {
  return [...bytes].map(value => value.toString(16).padStart(2, '0')).join('');
}

async function digest(bytes) {
  return hex(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)));
}

async function requestDigest(scope, offer) {
  const fields = [scope.connector_id, scope.tenant_id, scope.subject_id, scope.target_id,
    scope.hostname, String(scope.port), String(scope.expires_at_epoch),
    scope.required_transport ?? '', offer.type, offer.sdp];
  return digest(tupleBytes('omniterm-native-rtc-request-v1', fields));
}

async function verifyResponse(token, connector, requestId, requestHash, answer,
  streamId, admissionId, signature) {
  if (!/^[a-f0-9]{64}$/.test(signature)) return false;
  const signatureBytes = Uint8Array.from(signature.match(/../g), value => Number.parseInt(value, 16));
  const answerHash = await digest(encoder.encode(answer.sdp));
  const message = tupleBytes('omniterm-native-rtc-response-v1', [
    connector, requestHash, String(streamId), admissionId, answerHash, requestId,
  ]);
  const key = await crypto.subtle.importKey('raw', encoder.encode(token),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
  return crypto.subtle.verify('HMAC', key, signatureBytes, message);
}

function validOffer(value, connector) {
  if (!value || Array.isArray(value) || Object.keys(value).some(key => !['scope', 'offer'].includes(key)) ||
      !value.scope || Array.isArray(value.scope) || !value.offer || Array.isArray(value.offer)) return false;
  const scope = value.scope;
  if (Object.keys(scope).some(key => !['connector_id', 'tenant_id', 'subject_id', 'target_id',
    'hostname', 'port', 'expires_at_epoch', 'required_transport'].includes(key)) ||
      !['connector_id', 'tenant_id', 'subject_id', 'target_id', 'hostname']
        .every(key => typeof scope[key] === 'string') ||
      !id(scope.connector_id) || !id(scope.tenant_id) || !id(scope.subject_id) || !id(scope.target_id) ||
      scope.connector_id !== connector || scope.hostname.length < 1 || scope.hostname.length > 253 ||
      /[\s\x00-\x1f\x7f]/.test(scope.hostname) ||
      !Number.isInteger(scope.port) || scope.port < 1 || scope.port > 65535 ||
      !Number.isSafeInteger(scope.expires_at_epoch) ||
      scope.expires_at_epoch <= Math.floor(Date.now() / 1000) ||
      scope.expires_at_epoch > Math.floor(Date.now() / 1000) + 300 ||
      (scope.required_transport !== undefined && scope.required_transport !== 'webrtc') ||
      Object.keys(value.offer).some(key => !['type', 'sdp'].includes(key)) ||
      value.offer.type !== 'offer' || typeof value.offer.sdp !== 'string' ||
      value.offer.sdp.length < 3 || value.offer.sdp.length > 16384 || !value.offer.sdp.startsWith('v=0')) return false;
  return true;
}

export async function dispatchRtc(request, configuration, core, connector, options = {}) {
  const originHeader = request.headers.get('origin');
  const origin = originHeader ? authorizedBrowserOrigin(request, options.env) : null;
  const reply = (code, status) => withOrigin(error(code, status), origin);
  if (originHeader && !origin) return error('origin_forbidden', 403);
  if (request.method !== 'POST') return reply('method_not_allowed', 405);
  if (!configuration) return reply('native_rtc_unavailable', 503);

  let value;
  try {
    const body = await readBody(request);
    if (body === null) return reply('request_too_large', 413);
    value = JSON.parse(body);
  } catch {
    return reply('invalid_rtc_offer', 400);
  }
  if (!validOffer(value, connector)) return reply('invalid_rtc_offer', 400);
  const requestHash = await requestDigest(value.scope, value.offer);
  const requestIdBytes = crypto.getRandomValues(new Uint8Array(32));
  const requestId = hex(requestIdBytes);

  // Admission remains owned by the active relay, before allocating native ICE resources.
  const preflight = new URL(request.url);
  preflight.pathname = `/internal/v1/connectors/${connector}/route`;
  preflight.search = '';
  let admission;
  try {
    admission = await core.fetch(new Request(preflight, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-workload-token': request.headers.get('x-workload-token') || '' },
      body: JSON.stringify(value.scope),
    }));
  } catch {
    return reply('rtc_preflight_failed', 503);
  }
  if (!(admission instanceof Response)) return reply('rtc_preflight_failed', 503);
  if (!admission.ok) return withOrigin(admission, origin);

  const ingressBody = JSON.stringify({
    connector,
    workload: request.headers.get('x-workload-token'),
    ...value,
    request_id: requestId,
    request_digest: requestHash,
  });
  if (encoder.encode(ingressBody).byteLength > 32768) return reply('request_too_large', 413);
  try {
    const upstream = await (options.fetcher ?? fetch)(new URL('/offer', configuration.endpoint), {
      method: 'POST',
      redirect: 'manual',
      signal: AbortSignal.timeout(20000),
      headers: {
        'content-type': 'application/json',
        'x-native-rtc-service-token': configuration.token,
      },
      body: ingressBody,
    });
    const body = await readBody(upstream);
    if (!upstream.ok) return reply(upstream.status === 429 ? 'rtc_capacity' : 'rtc_ingress_admission_failed',
      upstream.status === 429 ? 429 : 502);
    if (body === null || body.length > 32768) return reply('rtc_ingress_invalid_response', 502);
    const answer = JSON.parse(body);
    if (!answer || Array.isArray(answer) ||
        Object.keys(answer).some(key => !['answer', 'stream_id', 'admission_id', 'request_id', 'request_digest', 'signature'].includes(key)) ||
        !answer.answer || Array.isArray(answer.answer) ||
        Object.keys(answer.answer).some(key => !['type', 'sdp'].includes(key)) ||
        answer.answer.type !== 'answer' || typeof answer.answer.sdp !== 'string' ||
        answer.answer.sdp.length < 3 || answer.answer.sdp.length > 16384 || !answer.answer.sdp.startsWith('v=0') ||
        !Number.isSafeInteger(answer.stream_id) || answer.stream_id < 1 || answer.stream_id > 0xffffffff ||
        typeof answer.admission_id !== 'string' || !/^[A-Za-z0-9_-]{16,128}$/.test(answer.admission_id) ||
        answer.request_id !== requestId || answer.request_digest !== requestHash ||
        !await verifyResponse(configuration.token, connector, requestId, requestHash, answer.answer,
          answer.stream_id, answer.admission_id, answer.signature)) {
      return reply('rtc_ingress_invalid_response', 502);
    }
    return withOrigin(Response.json({
      answer: answer.answer,
      stream_id: answer.stream_id,
      admission_id: answer.admission_id,
    }, { headers: { 'cache-control': 'no-store' } }), origin);
  } catch {
    return reply('rtc_ingress_unavailable', 502);
  }
}
