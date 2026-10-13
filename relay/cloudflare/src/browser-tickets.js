export const BROWSER_RELAY_PROTOCOL = 'omni-relay.v1';
export const BROWSER_RELAY_TICKET_PREFIX = 'omni-relay-ticket.';
export const BROWSER_RELAY_TICKET_TTL_SECONDS = 30;
const STORAGE_PREFIX = 'native-relay-browser-ticket-v1:';
const RATE_PREFIX = 'native-relay-browser-ticket-window-v1:';

function base64Url(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function ticketHash(ticket) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(ticket));
  return Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, '0')).join('');
}

export function parseBrowserTicketProtocols(value) {
  if (typeof value !== 'string' || !value) return { present: false };
  if (value.length > 1024) return { present: true, valid: false };
  const protocols = value.split(',').map(protocol => protocol.trim());
  const tickets = protocols.filter(protocol => protocol.startsWith('omni-relay-ticket'));
  if (!tickets.length) return { present: false };
  if (protocols.length !== 2 || tickets.length !== 1 ||
      protocols.filter(protocol => protocol === BROWSER_RELAY_PROTOCOL).length !== 1 ||
      !tickets[0].startsWith(BROWSER_RELAY_TICKET_PREFIX)) return { present: true, valid: false };
  const ticket = tickets[0].slice(BROWSER_RELAY_TICKET_PREFIX.length);
  return /^[A-Za-z0-9_-]{43}$/.test(ticket)
    ? { present: true, valid: true, ticket }
    : { present: true, valid: false };
}

function safeOrigin(value) {
  if (typeof value !== 'string' || value.length > 512) return false;
  try {
    const parsed = new URL(value);
    return parsed.protocol === 'https:' && parsed.origin === value &&
      !parsed.username && !parsed.password && !parsed.search && !parsed.hash;
  } catch { return false; }
}

export function authorizedBrowserOrigin(request, env = {}, trustForwarded = false) {
  const origin = request.headers.get('origin');
  if (!safeOrigin(origin)) return null;
  if (trustForwarded && request.headers.get('x-native-relay-browser-origin') === origin) return origin;
  let endpointOrigin;
  try { endpointOrigin = new URL(request.url).origin; } catch { return null; }
  const configured = new Set((env.NATIVE_RELAY_BROWSER_ORIGINS || '')
    .split(',').map(value => value.trim()).filter(Boolean));
  return origin === endpointOrigin || configured.has(origin) ? origin : null;
}

export function browserTicketCorsHeaders(origin) {
  return {
    'access-control-allow-origin': origin,
    'access-control-allow-credentials': 'true',
    'cache-control': 'no-store',
    vary: 'Origin',
  };
}

export function browserTicketPreflight(request, env = {}) {
  const origin = authorizedBrowserOrigin(request, env);
  if (!origin || request.method !== 'OPTIONS' ||
      request.headers.get('access-control-request-method') !== 'POST') {
    return Response.json({ error: 'origin_forbidden' }, {
      status: 403, headers: { 'cache-control': 'no-store', vary: 'Origin' },
    });
  }
  const requested = new Set((request.headers.get('access-control-request-headers') || '')
    .toLowerCase().split(',').map(value => value.trim()).filter(Boolean));
  if ([...requested].some(value => !['authorization', 'content-type'].includes(value))) {
    return Response.json({ error: 'browser_ticket_headers_forbidden' }, {
      status: 403, headers: { 'cache-control': 'no-store', vary: 'Origin' },
    });
  }
  return new Response(null, { status: 204, headers: {
    ...browserTicketCorsHeaders(origin),
    allow: 'POST, OPTIONS',
    'access-control-allow-methods': 'POST, OPTIONS',
    'access-control-allow-headers': 'Authorization, Content-Type',
    'access-control-max-age': '300',
  } });
}

export async function issueBrowserTicket(storage, {connectorId, origin, scope = null, now = Math.floor(Date.now() / 1000)}) {
  if (!storage || typeof storage.transaction !== 'function') return null;
  const ticket = base64Url(crypto.getRandomValues(new Uint8Array(32)));
  const hash = await ticketHash(ticket);
  const expiresAtEpoch = now + BROWSER_RELAY_TICKET_TTL_SECONDS;
  const record = {version: 1, connectorId, origin, role: 'client', scope, expiresAtEpoch};
  const stored = await storage.transaction(async txn => {
    const minute = Math.floor(now / 60), rateKey = RATE_PREFIX + minute;
    const prior = await txn.get(rateKey);
    if ((prior?.count ?? 0) >= 120) return false;
    const key = STORAGE_PREFIX + hash;
    if (await txn.get(key)) return false;
    await txn.put(rateKey, {minute, count: (prior?.count ?? 0) + 1}, {expirationTtl: 120});
    await txn.put(key, record, {expirationTtl: BROWSER_RELAY_TICKET_TTL_SECONDS + 5});
    return true;
  });
  if (!stored) return null;
  return {
    ticket,
    expires_at_epoch: expiresAtEpoch,
    websocket_protocols: [BROWSER_RELAY_PROTOCOL, BROWSER_RELAY_TICKET_PREFIX + ticket],
  };
}

export async function consumeBrowserTicketRecord(storage, request, connectorId,
  now = Math.floor(Date.now() / 1000), {ignoreScope = false} = {}) {
  const offered = parseBrowserTicketProtocols(request.headers.get('sec-websocket-protocol'));
  if (!offered.present) return {present: false, valid: false};
  if (!offered.valid || typeof storage?.transaction !== 'function') return {present: true, valid: false};
  const origin = request.headers.get('origin');
  const scope = request.headers.get('x-native-relay-public-scope');
  const hash = await ticketHash(offered.ticket), key = STORAGE_PREFIX + hash;
  const record = await storage.transaction(async txn => {
    const saved = await txn.get(key);
    if (!saved || saved.version !== 1 || saved.connectorId !== connectorId ||
        saved.role !== 'client' || saved.origin !== origin ||
        (!ignoreScope && saved.scope !== (scope ?? null)) ||
        !Number.isSafeInteger(saved.expiresAtEpoch) || saved.expiresAtEpoch <= now) return null;
    await txn.delete(key);
    return saved;
  });
  const valid = !!record && record.version === 1 && record.connectorId === connectorId &&
    record.origin === origin && record.role === 'client' &&
    (ignoreScope || record.scope === (scope ?? null)) &&
    Number.isSafeInteger(record.expiresAtEpoch) && record.expiresAtEpoch > now;
  return {present: true, valid, record: valid ? record : null};
}

export async function consumeBrowserTicket(storage, request, connectorId, now = Math.floor(Date.now() / 1000)) {
  const result = await consumeBrowserTicketRecord(storage, request, connectorId, now);
  return {present: result.present, valid: result.valid};
}
