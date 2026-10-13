// Free Self-Hosted Cloudflare Worker Relay Entrypoint.
// Zero database dependencies, single pre-shared token authentication.

import {
  FreeNativeConnectorRelay,
  nativeConnectorRoute,
  nativeConnectorId,
} from './relay.js';
import { timingSafeEqual, validateRelayToken } from './security.js';
import { relayVersion, managementRoute, authorizeManagement } from './public-contract.js';
import { dispatchRtc, rtcConfiguration, rtcCorsPreflight, rtcRoute, withRtcCors } from './rtc.js';
import {
  authorizedBrowserOrigin,
  browserTicketCorsHeaders,
  browserTicketPreflight,
  parseBrowserTicketProtocols,
} from './browser-tickets.js';

const browserTicketRoute = /^\/internal\/v1\/connectors\/[A-Za-z0-9_-]{1,128}\/browser-ticket$/;
const browserDialRoute = /^\/internal\/v1\/connectors\/[A-Za-z0-9_-]{1,128}\/dial-stream$/;
const bearerToken = request => /^Bearer ([\x21-\x7e]{10,256})$/.exec(request.headers.get('authorization') || '')?.[1] ?? null;

export { FreeNativeConnectorRelay as NativeConnectorRelay };

export default {
  async fetch(request, env) {
    let url = new URL(request.url);
    const rtcMatch = rtcRoute(url.pathname);
    const rtcOrigin = rtcMatch && request.headers.has('origin')
      ? authorizedBrowserOrigin(request, env) : null;
    if (rtcMatch && request.headers.has('origin') && !rtcOrigin) {
      return Response.json({error: 'origin_forbidden'}, {status: 403, headers: {'cache-control': 'no-store'}});
    }
    const rtcReply = (body, status = 200) => withRtcCors(Response.json(body, {
      status, headers: {'cache-control': 'no-store'},
    }), rtcOrigin);
    if (url.pathname === '/relay/api/v1/init' || url.pathname === '/relay/api/v1/version') {
      if (request.method !== 'GET') return Response.json({error: 'method_not_allowed'}, {
        status: 405, headers: {allow: 'GET', 'cache-control': 'no-store'},
      });
      const metadata = relayVersion();
      const rtc = rtcConfiguration(env, url.origin);
      if (url.pathname.endsWith('/init')) Object.assign(metadata, {
        protocol_version: 1, transports: ['websocket', ...(rtc ? ['webrtc'] : [])],
        coordination: 'durable_object', native_rtc: !!rtc,
        connect_url: `${url.protocol === 'https:' ? 'wss:' : 'ws:'}//${url.host}/relay/api/v1/connect`,
      });
      return Response.json(metadata, {headers: {'cache-control': 'no-store', 'access-control-allow-origin': '*'}});
    }
    if (url.pathname === '/relay/api/v1/connect') {
      url = new URL(`/v1/connectors/stream${url.search}`, url);
      request = new Request(url, request);
    }
    const management = managementRoute(url.pathname);
    if (management) {
      // Reject unauthenticated connector IDs before allocating a Durable Object;
      // the object independently repeats the same operator check.
      const denied = authorizeManagement(request, env);
      if (denied) return denied;
      if (!env.NATIVE_CONNECTORS) return Response.json({error: 'native_relay_unavailable'}, {status: 503});
      const id = env.NATIVE_CONNECTORS.idFromName(JSON.stringify(['free-v1', management[1]]));
      return env.NATIVE_CONNECTORS.get(id).fetch(request);
    }

    // Health check endpoints
    if (url.pathname === '/healthz' || url.pathname === '/readyz') {
      return new Response('OK', {
        status: 200,
        headers: { 'cache-control': 'no-store' },
      });
    }

    if (browserTicketRoute.test(url.pathname) && request.method === 'OPTIONS') {
      if (url.search) {
        return Response.json({ error: 'relay_credentials_require_headers' }, {
          status: 400, headers: { 'cache-control': 'no-store' },
        });
      }
      return browserTicketPreflight(request, env);
    }

    if (rtcRoute(url.pathname) && request.method === 'OPTIONS') {
      if (url.search) return Response.json({error: 'relay_credentials_require_headers'}, {
        status: 400, headers: {'cache-control': 'no-store'},
      });
      return rtcCorsPreflight(request, env);
    }

    if (nativeConnectorRoute(url.pathname) || rtcRoute(url.pathname)) {
      const expected = env.RELAY_AUTH_TOKEN;
      const configError = validateRelayToken(expected);
      if (configError) {
        return Response.json(
          {
            error: 'server_misconfiguration',
            message: `Server RELAY_AUTH_TOKEN is invalid: ${configError}`,
          },
          { status: 500, headers: { 'cache-control': 'no-store' } }
        );
      }

      const ticketRoute = browserTicketRoute.test(url.pathname);
      const offeredTicket = parseBrowserTicketProtocols(request.headers.get('sec-websocket-protocol'));
      const browserOrigin = ticketRoute || offeredTicket.present
        ? authorizedBrowserOrigin(request, env)
        : null;
      const token = ticketRoute ? bearerToken(request) : request.headers.get('x-workload-token');

      if (url.searchParams.has('token')) {
        return rtcMatch ? rtcReply({error: 'header_authentication_required'}, 401) :
          Response.json({ error: 'header_authentication_required' }, {
            status: 401, headers: { 'cache-control': 'no-store' },
          });
      }
      if (ticketRoute && (request.method !== 'POST' || !browserOrigin || !token)) {
        return Response.json({ error: 'browser_ticket_unauthorized' }, {
          status: 401, headers: browserOrigin ? browserTicketCorsHeaders(browserOrigin) : { 'cache-control': 'no-store' },
        });
      }
      if (offeredTicket.present && (!offeredTicket.valid || !browserDialRoute.test(url.pathname) ||
          request.method !== 'GET' || request.headers.get('upgrade')?.toLowerCase() !== 'websocket' ||
          !browserOrigin)) {
        return Response.json({ error: 'invalid_browser_ticket' }, {
          status: 401, headers: { 'cache-control': 'no-store' },
        });
      }
      if (!token && !offeredTicket.present) {
        const denied = Response.json(
          {
            error: 'unauthorized',
            message: 'Relay token must be provided via the x-workload-token header.',
          },
          { status: 401, headers: { 'cache-control': 'no-store' } }
        );
        return rtcMatch ? withRtcCors(denied, rtcOrigin) : denied;
      }

      const clientTokenError = token ? validateRelayToken(token) : null;
      if (clientTokenError) {
        const denied = Response.json(
          {
            error: 'unauthorized',
            message: `Invalid relay token format: ${clientTokenError}`,
          },
          { status: 401, headers: { 'cache-control': 'no-store' } }
        );
        return rtcMatch ? withRtcCors(denied, rtcOrigin) : denied;
      }

      if (token && !timingSafeEqual(token, expected)) {
        const denied = Response.json(
          {
            error: 'unauthorized',
            message: 'Invalid relay token.',
          },
          { status: 401, headers: { 'cache-control': 'no-store' } }
        );
        return rtcMatch ? withRtcCors(denied, rtcOrigin) : denied;
      }

      const rtc = rtcMatch ? rtcConfiguration(env, url.origin) : null;
      const connectorId = rtcMatch?.[1] ?? nativeConnectorId(request);
      if (!connectorId) {
        return rtcMatch ? rtcReply({error: 'invalid_connector_scope'}, 400) : Response.json(
          { error: 'invalid_connector_scope' }, { status: 400, headers: { 'cache-control': 'no-store' } });
      }

      let relayRequest = request;
      if ((ticketRoute || offeredTicket.present) && browserOrigin) {
        const headers = new Headers(request.headers);
        if (ticketRoute) {
          headers.delete('authorization');
          headers.set('x-workload-token', token);
        }
        headers.set('x-native-relay-browser-origin', browserOrigin);
        relayRequest = new Request(request, { headers });
      }

      if (rtcMatch && !rtc) return dispatchRtc(relayRequest, null, null, connectorId, {env});
      if (!env.NATIVE_CONNECTORS) {
        const unavailable = Response.json(
          { error: 'native_relay_unavailable' },
          { status: 503, headers: { 'cache-control': 'no-store' } }
        );
        return rtcMatch ? withRtcCors(unavailable, rtcOrigin) : unavailable;
      }

      // Durable Object routing by connectorId
      const doId = env.NATIVE_CONNECTORS.idFromName(
        JSON.stringify(['free-v1', connectorId])
      );
      const stub = env.NATIVE_CONNECTORS.get(doId);
      if (rtcMatch) {
        return dispatchRtc(relayRequest, rtc, {fetch: preflight => stub.fetch(preflight)}, connectorId,
          {env, fetcher: fetch});
      }
      return stub.fetch(relayRequest);
    }

    return Response.json(
      { error: 'not_found' },
      { status: 404, headers: { 'cache-control': 'no-store' } }
    );
  },
};
