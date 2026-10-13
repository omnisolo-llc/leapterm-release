// Provider-neutral relay code may import this issuer; account policy stays with
// the caller. Never return, log, or persist the long-lived TURN key secret.
import { readBoundedJson, scopeId } from './security.js';

export const MAX_TURN_TTL = 300;
const API = 'https://rtc.live.cloudflare.com/v1/turn/keys/';
const URLS = new Set([
  'stun:stun.cloudflare.com:3478',
  'turn:turn.cloudflare.com:3478?transport=udp',
  'turn:turn.cloudflare.com:3478?transport=tcp',
  'turn:turn.cloudflare.com:80?transport=tcp',
  'turns:turn.cloudflare.com:5349?transport=tcp',
  'turns:turn.cloudflare.com:443?transport=tcp',
]);

export function turnConfigured(env) {
  return env.RELAY_TURN_ENABLED === 'true' &&
    typeof env.CLOUDFLARE_TURN_KEY_ID === 'string' &&
    /^[a-zA-Z0-9_-]{1,128}$/.test(env.CLOUDFLARE_TURN_KEY_ID) &&
    typeof env.CLOUDFLARE_TURN_KEY_API_TOKEN === 'string' &&
    env.CLOUDFLARE_TURN_KEY_API_TOKEN.length >= 16 &&
    !/[\s\x00-\x1f\x7f]/.test(env.CLOUDFLARE_TURN_KEY_API_TOKEN) &&
    !['RELAY_AUTH_TOKEN', 'WORKLOAD_SECRET', 'RELAY_METERING_SECRET'].some(
      name => env[name] && env[name] === env.CLOUDFLARE_TURN_KEY_API_TOKEN);
}

export function validateIceServers(value, issuerSecret) {
  // generate-ice-servers may return one RTCIceServer object or an array.
  // Normalize the documented object form; do not invent usernames/passwords.
  const raw = value?.iceServers;
  const servers = Array.isArray(raw) ? raw : raw && typeof raw === 'object' ? [raw] : [];
  if (!servers.length || servers.length > 8) throw Error('invalid_turn_response');
  let hasTurn = false;
  const iceServers = servers.map(server => {
    const supplied = typeof server?.urls === 'string' ? [server.urls] : server?.urls;
    if (!Array.isArray(supplied) || !supplied.length || supplied.length > 8 ||
        !supplied.every(url => URLS.has(url) || url === 'turn:turn.cloudflare.com:53?transport=udp')) throw Error('invalid_turn_response');
    // Browser ICE gathering can stall on port 53; use only returned supported URLs.
    const urls = supplied.filter(url => url !== 'turn:turn.cloudflare.com:53?transport=udp');
    if (!urls.length) return null;
    if (urls.some(url => url.startsWith('turn:') || url.startsWith('turns:'))) {
      hasTurn = true;
      for (const name of ['username', 'credential']) {
        if (typeof server[name] !== 'string' || !server[name].length || server[name].length > 1024 ||
            /[\s\x00-\x1f\x7f]/.test(server[name]) || server[name] === issuerSecret) {
          throw Error('invalid_turn_response');
        }
      }
      return { urls, username: server.username, credential: server.credential };
    }
    return { urls };
  }).filter(Boolean);
  if (!hasTurn) throw Error('invalid_turn_response');
  return iceServers;
}

export async function issueCloudflareTurn(env, scope, fetcher = fetch) {
  if (!turnConfigured(env)) throw Error('turn_unconfigured');
  if (!scopeId(scope.sessionId) || !scopeId(scope.connectorId) || !scopeId(scope.accountId) ||
      !['client', 'agent', 'gateway'].includes(scope.peer) ||
      !Number.isInteger(scope.ttl) || scope.ttl < 60 || scope.ttl > MAX_TURN_TTL) {
    throw Error('invalid_turn_scope');
  }
  // Opaque analytics identifier: no account names, hostnames or customer tokens.
  const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(
    JSON.stringify(['omni-turn-v1', scope.accountId, scope.connectorId, scope.sessionId, scope.peer])));
  const customIdentifier = Array.from(new Uint8Array(hash), b => b.toString(16).padStart(2, '0')).join('');
  const issuedAt = Math.floor(Date.now() / 1000);
  let response;
  try {
    response = await fetcher(API + env.CLOUDFLARE_TURN_KEY_ID + '/credentials/generate-ice-servers', {
      // Workerd supports manual/follow, not redirect:error. Manual keeps the
      // issuer secret at this exact origin; all 3xx responses fail below.
      method: 'POST', redirect: 'manual', signal: AbortSignal.timeout(10000),
      headers: { authorization: 'Bearer ' + env.CLOUDFLARE_TURN_KEY_API_TOKEN, 'content-type': 'application/json' },
      body: JSON.stringify({ ttl: scope.ttl, customIdentifier }),
    });
  } catch (error) {
    // Finite error categories only: never expose fetch exceptions or request data.
    throw Error(['TimeoutError', 'AbortError'].includes(error?.name)
      ? 'turn_provider_timeout' : 'turn_provider_transport_error');
  }
  if (response.status === 401 || response.status === 403) throw Error('turn_provider_permission_required');
  if (!response.ok) throw Error('turn_provider_unavailable');
  const parsed = await readBoundedJson(response, 16 * 1024, 5000);
  if (!parsed.ok) throw Error('invalid_turn_response');
  return {
    iceServers: validateIceServers(parsed.value, env.CLOUDFLARE_TURN_KEY_API_TOKEN),
    expires_at_epoch: issuedAt + scope.ttl,
    usage_id: customIdentifier,
  };
}
