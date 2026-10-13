import { isValidRelayToken, timingSafeEqual } from './security.js';
// Public self-hosted wire contract. No private managed-service implementation.
export const relayVersion = () => ({api_version: 1, supported_api_versions: [1], relay_revision: 2});
export const supportedTransports = Object.freeze(['websocket']);
export const nativeRtcRoute = path => /^\/internal\/v1\/connectors\/[A-Za-z0-9_-]{1,128}\/rtc-offer$/.test(path);
export const managementRoute = path => /^\/internal\/v1\/connectors\/([A-Za-z0-9_-]{1,128})\/(revoke|restore)$/.exec(path);
export const transportSupported = (scope, nativeRtcAvailable = false) =>
  scope.required_transport === undefined || supportedTransports.includes(scope.required_transport) ||
  (scope.required_transport === 'webrtc' && nativeRtcAvailable);

export function authorizeManagement(request, env) {
  const deny = (error, status) => Response.json({error}, {status, headers: {'cache-control': 'no-store'}});
  if (request.method !== 'POST') return deny('method_not_allowed', 405);
  if (new URL(request.url).search) return deny('invalid_management_request', 400);
  const expected = env.RELAY_MANAGEMENT_TOKEN;
  if (!isValidRelayToken(expected) || !isValidRelayToken(env.RELAY_AUTH_TOKEN) ||
      timingSafeEqual(expected, env.RELAY_AUTH_TOKEN)) return deny('relay_management_not_configured', 503);
  const supplied = request.headers.get('x-relay-management-token');
  return !isValidRelayToken(supplied) || !timingSafeEqual(supplied, expected)
    ? deny('unauthorized', 401) : null;
}

// HTTP runtimes may expose a readable stream even for a zero-byte POST.
// Reject actual bytes, not stream presence, with a bounded read deadline.
export async function emptyBody(request) {
  if (!request.body) return true;
  const reader = request.body.getReader();
  let timer;
  try {
    return await Promise.race([
      (async () => {
        for (;;) {
          const {done, value} = await reader.read();
          if (done) return true;
          if (value?.byteLength) return false;
        }
      })(),
      new Promise(resolve => { timer = setTimeout(() => resolve(false), 2000); }),
    ]);
  } catch { return false; }
  finally {
    clearTimeout(timer);
    void reader.cancel().catch(() => {});
    reader.releaseLock();
  }
}
