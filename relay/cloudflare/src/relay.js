// Free Self-Hosted Native Connector Relay.
// Uses the local standalone relay-core.js module.
// Socket streams stay in memory; the existing Durable Object stores revocation
// and one-use tickets. No D1, central account database, or billing dependency.

import { RelayCore, nativeConnectorRoute, nativeConnectorId, json, scopeId, OPEN } from './relay-core.js';
import { timingSafeEqual, isValidRelayToken } from './security.js';
import { managementRoute, transportSupported, authorizeManagement, emptyBody } from './public-contract.js';
import { rtcConfiguration } from './rtc.js';
import {
  authorizedBrowserOrigin,
  consumeBrowserTicket,
  parseBrowserTicketProtocols,
} from './browser-tickets.js';

export { nativeConnectorRoute, nativeConnectorId };

export class FreeNativeConnectorRelay extends RelayCore {
  constructor(state, env) {
    super(state, env);
    this.isFreeRelay = true;
    this.rtcBridgeSockets = new WeakSet();
    this.operatorRevoked = false;
    this.revocationUnavailable = false;
    this.revocationReady = Promise.resolve().then(async () => {
      const value = await state.storage.get('operator-revoked-v1');
      if (value !== undefined && typeof value !== 'boolean') throw new Error('invalid_revocation_state');
      this.operatorRevoked = value === true;
    }).catch(() => { this.revocationUnavailable = true; });
  }

  closeAllStreams() {
    for (const pending of [...this.pendingClients]) pending.close?.('operator_revoked');
    for (const agent of [...this.pending, ...this.agents.values()]) this.closeAgent(agent, 'operator_revoked');
  }

  async fetch(request) {
    await this.revocationReady;
    if (this.revocationUnavailable) return json({error: 'revocation_authority_unavailable'}, 503);
    const url = new URL(request.url);
    const management = managementRoute(url.pathname);
    if (management) {
      const denied = authorizeManagement(request, this.env);
      if (denied) return denied;
      if (!await emptyBody(request)) return json({error: 'invalid_management_request'}, 400);
      if (this.connectorId && this.connectorId !== management[1]) return json({error: 'invalid_connector_scope'}, 400);
      this.connectorId = management[1];
      const revoked = management[2] === 'revoke';
      if (revoked) {
        // Fence callbacks and stop existing sockets before any awaited storage IO.
        this.operatorRevoked = true;
        this.closeAllStreams();
      }
      try {
        await this.state.storage.transaction(async transaction => {
          await transaction.put('operator-revoked-v1', revoked);
          if (revoked) {
            const tickets = await transaction.list({prefix: 'native-relay-browser-ticket-v1:'});
            if (tickets.size) await transaction.delete([...tickets.keys()]);
          }
        });
      } catch {
        this.operatorRevoked = true;
        this.revocationUnavailable = true;
        this.closeAllStreams();
        return json({error: 'revocation_authority_unavailable'}, 503);
      }
      this.operatorRevoked = revoked;
      return new Response(null, {status: 204, headers: {'cache-control': 'no-store'}});
    }
    if (this.operatorRevoked) return json({error: 'connector_revoked'}, 403);
    // Registration requires the same header authority even via a direct binding.
    if (url.pathname === '/v1/connectors/stream' && !await this.authorizeWorkload(request)) {
      return json({error: 'unauthorized'}, 401);
    }
    if (this.operatorRevoked) return json({error: 'connector_revoked'}, 403);
    return super.fetch(request);
  }

  async authorizeWorkload(request) {
    const expected = this.env.RELAY_AUTH_TOKEN || '';
    if (!expected || !isValidRelayToken(expected)) return false;
    const url = new URL(request.url);
    if (url.searchParams.has('token')) return false;
    const match = url.pathname.match(/^\/internal\/v1\/connectors\/([A-Za-z0-9_-]{1,128})\/dial-stream$/);
    const offered = parseBrowserTicketProtocols(request.headers.get('sec-websocket-protocol'));
    if (offered.present) {
      if (!offered.valid || !match || request.method !== 'GET' ||
          request.headers.get('upgrade')?.toLowerCase() !== 'websocket' ||
          authorizedBrowserOrigin(request, this.env) !== request.headers.get('origin')) return false;
      return (await consumeBrowserTicket(this.state?.storage, request, match[1])).valid;
    }
    const supplied = request.headers.get('x-workload-token');
    if (!supplied || !isValidRelayToken(supplied)) return false;
    return timingSafeEqual(supplied, expected);
  }

  async createBrowserTicket(request, connectorId) {
    if (!authorizedBrowserOrigin(request, this.env)) return json({ error: 'origin_forbidden' }, 403);
    return super.createBrowserTicket(request, connectorId);
  }

  websocket(request) {
    const pair = super.websocket(request);
    const rtc = rtcConfiguration(this.env);
    if (pair && rtc && isValidRelayToken(request.headers.get('x-native-rtc-service-token')) &&
        timingSafeEqual(request.headers.get('x-native-rtc-service-token'), rtc.token)) {
      this.rtcBridgeSockets.add(pair.socket);
    }
    return pair;
  }

  async beginDial(connectorId, text, socket, pending, close) {
    let scope;
    try { scope = JSON.parse(text); }
    catch { close('invalid_connector_request'); return; }
    if (scope?.required_transport === 'webrtc' && !this.rtcBridgeSockets.has(socket)) {
      close('native_rtc_bridge_required');
      return;
    }
    return super.beginDial(connectorId, text, socket, pending, close);
  }

  async authorizeRegistration(connectorId, hello, agent) {
    if (this.operatorRevoked || this.revocationUnavailable) throw new Error('connector_revoked');
    // Free relay does not query a central database.
    // Authentication is verified at connection time via RELAY_AUTH_TOKEN.
    // The agent lease is dynamically created in-memory.
    const record = {
      connector_id: hello.connector_id,
      tenant_id: hello.tenant_id,
      target_id: 'default',
      hostname: '127.0.0.1',
      port: 22,
      public_key: '',
      status: 'enrolled',
      subject_id: 'free-self-host',
    };
    return record;
  }

  supportsTransport(scope) { return transportSupported(scope, !!rtcConfiguration(this.env)); }

  async authorizeDial(connectorId, request) {
    if (this.operatorRevoked || this.revocationUnavailable) return json({error: 'connector_revoked'}, 403);
    if (request && !this.supportsTransport(request)) return json({error: 'transport_unavailable'}, 409);
    const now = Math.floor(Date.now() / 1000);
    if (
      !request ||
      !scopeId(connectorId) ||
      request.connector_id !== connectorId ||
      !scopeId(request.tenant_id) ||
      !scopeId(request.subject_id) ||
      !scopeId(request.target_id) ||
      typeof request.hostname !== 'string' ||
      !request.hostname ||
      request.hostname.length > 253 ||
      !Number.isInteger(request.port) ||
      request.port < 1 ||
      request.port > 65535 ||
      !Number.isSafeInteger(request.expires_at_epoch) ||
      request.expires_at_epoch <= now
    ) {
      return json({ error: 'invalid_connector_scope' }, 400);
    }

    const agent = this.agents.get(connectorId);
    if (
      !agent ||
      agent.closed ||
      agent.socket.readyState !== OPEN ||
      agent.lastSeen + 90_000 <= Date.now()
    ) {
      return json({ error: 'connector_unavailable' }, 503);
    }

    if (request.expires_at_epoch <= Math.floor(Date.now() / 1000)) {
      return json({ error: 'connector_request_expired' }, 403);
    }

    // Return immutable snapshot of authorized dial parameters without mutating agent.record
    const destination = Object.freeze({
      target_id: request.target_id,
      hostname: request.hostname,
      port: request.port,
    });

    return {
      agent,
      destination,
      accountId: agent.record?.subject_id || 'free-self-host',
      policyEpoch: agent.record?.policy_epoch || 1,
    };
  }

  authorizeTurnCredentials(_authorized, request) {
    // Shared-token holders form one trusted owner group in free deployments.
    // Individual peer identity and target authorization are still verified by
    // the native peer transport before opening the destination TCP stream.
    return this.isFreeRelay && ['client', 'agent'].includes(request.peer);
  }

  async onStreamBytes(accountId, stream, byteLength) {
    // No OmniTerm billing; the owner's Cloudflare account limits still apply.
  }
}
