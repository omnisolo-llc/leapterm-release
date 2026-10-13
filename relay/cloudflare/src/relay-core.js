// Core modular relay engine for OmniTerminal.
// Provides base WebSocket lifecycle, postcard framing, duplex stream bridging, and backpressure.
// Shared byte-routing engine; subclasses supply admission and accounting policy.

import { FrameDecoder, encodeFrame } from './connector-wire.js';
import { emptyBody } from './public-contract.js';
import { scopeId, equalBytes, readBoundedJson } from './security.js';
import { issueCloudflareTurn, turnConfigured, MAX_TURN_TTL } from './cloudflare-turn.js';
import {
  authorizedBrowserOrigin, browserTicketCorsHeaders, BROWSER_RELAY_PROTOCOL,
  issueBrowserTicket as mintBrowserTicket,
} from './browser-tickets.js';

export { scopeId, equalBytes, readBoundedJson };

export const json = (value, status = 200) =>
  Response.json(value, { status, headers: { 'cache-control': 'no-store' } });

export const MAX_STREAMS = 16;
export const MAX_PENDING = 128;
export const MAX_DATA = 256 * 1024;
export const MAX_QUEUED = 16 * 1024 * 1024;
export const OPEN = 1;

export function nativeConnectorRoute(path) {
  return (
    path === '/v1/connectors/stream' ||
    /^\/internal\/v1\/connectors\/[A-Za-z0-9_-]{1,128}\/(route|dial-stream|dial-datagram|turn-credentials|browser-ticket)$/.test(path)
  );
}

export function nativeConnectorId(request) {
  const url = new URL(request.url);
  if (url.pathname === '/v1/connectors/stream') {
    const values = url.searchParams.getAll('connector_id');
    return values.length === 1 && scopeId(values[0]) ? values[0] : null;
  }
  return (
    url.pathname.match(
      /^\/internal\/v1\/connectors\/([A-Za-z0-9_-]{1,128})\/(route|dial-stream|dial-datagram|turn-credentials|browser-ticket)$/
    )?.[1] ?? null
  );
}

export class RelayCore {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this.agents = new Map();
    this.pending = new Set();
    this.pendingClients = new Set();
    this.nextStream = 1;
    this.queuedBytes = 0;
    this.connectorId = null;
  }

  // Hook: authorize workload token for internal management/dial routes.
  // Overridden by each deployment's authentication policy.
  authorizeWorkload(request) {
    return true;
  }

  upgradeResponse(pair, request) {
    const protocols = request?.headers.get('sec-websocket-protocol')?.split(',').map(value => value.trim()) ?? [];
    const headers = protocols.includes(BROWSER_RELAY_PROTOCOL)
      ? { 'sec-websocket-protocol': BROWSER_RELAY_PROTOCOL }
      : undefined;
    return new Response(null, { status: 101, webSocket: pair.client, headers });
  }

  async createBrowserTicket(request, connectorId) {
    if (request.method !== 'POST') return json({ error: 'method_not_allowed' }, 405);
    if (new URL(request.url).search) return json({ error: 'relay_credentials_require_headers' }, 400);
    if (!await emptyBody(request)) return json({ error: 'invalid_browser_ticket_request' }, 400);
    const origin = authorizedBrowserOrigin(request, this.env, true);
    if (!origin) return json({ error: 'origin_forbidden' }, 403);
    const scope = request.headers.get('x-native-relay-public-scope');
    let issued;
    try { issued = await mintBrowserTicket(this.state?.storage, { connectorId, origin, scope }); }
    catch { return json({ error: 'browser_ticket_unavailable' }, 503); }
    if (!issued) return json({ error: 'browser_ticket_unavailable' }, 503);
    return Response.json(issued, { headers: { ...browserTicketCorsHeaders(origin), pragma: 'no-cache' } });
  }

  // Hook: verify Hello frame and return registration record { connector_id, tenant_id, ... }
  // Overridden by the enrollment policy for this deployment.
  async authorizeRegistration(connectorId, hello, agent) {
    throw new Error('authorizeRegistration must be implemented by subclass');
  }

  // Hook: verify dial request and return live agent object or error Response
  // Overridden by the target authorization policy for this deployment.
  async authorizeDial(connectorId, dialRequest) {
    throw new Error('authorizeDial must be implemented by subclass');
  }

  // Hook: accounting callback on forwarded stream bytes
  async onStreamBytes(accountId, stream, byteLength) {
    // Default no-op in base/free relay
  }

  websocket(request) {
    if (request.headers.get('Upgrade')?.toLowerCase() !== 'websocket') return null;
    const pair = new WebSocketPair();
    const [client, socket] = Object.values(pair);
    socket.binaryType = 'arraybuffer';
    socket.accept();
    return { client, socket };
  }

  send(agent, frame) {
    if (agent.closed || agent.socket.readyState !== OPEN) throw Error('connector_closed');
    agent.socket.send(encodeFrame(frame));
  }

  meteredQueue(accountId, stream, active, write, close) {
    let tail = Promise.resolve(), queued = 0, frames = 0, stopped = false;
    return input => {
      if (stopped || !active()) return;
      const bytes = input instanceof ArrayBuffer ? new Uint8Array(input) : input;
      if (
        !(bytes instanceof Uint8Array) ||
        !bytes.length ||
        bytes.length > MAX_DATA ||
        frames >= 64 ||
        queued + bytes.length > 1024 * 1024 ||
        this.queuedBytes + bytes.length > MAX_QUEUED
      ) {
        stopped = true;
        close('relay_backpressure_limit');
        return;
      }
      const billable = this.isStreamBillable(stream);
      // Gateway-authorized traffic is admitted even when this Worker is not
      // the billing boundary. An agent marker alone never authorizes managed use.
      const admitted = this.isFreeRelay ? stream.authenticated : stream.meteringAuthorized;
      if (!billable && !admitted) {
        if (stream.handshakeBytes + bytes.length > 64 * 1024) {
          stopped = true;
          close('relay_authentication_budget_exceeded');
          return;
        }
        stream.handshakeBytes += bytes.length;
        this.consumeAdmissionResource(accountId, stream, bytes.length);
      }
      queued += bytes.length;
      frames++;
      this.queuedBytes += bytes.length;
      tail = tail
        .then(async () => {
          if (stopped || !active()) return;
          if (billable) await this.onStreamBytes(accountId, stream, bytes.length);
          if (!stopped && active()) write(bytes);
        })
        .catch(() => {
          stopped = true;
          close('relay_forwarding_denied');
        })
        .finally(() => {
          queued -= bytes.length;
          frames--;
          this.queuedBytes -= bytes.length;
        });
    };
  }

  isStreamBillable(stream) {
    if (this.isFreeRelay) return false;
    return !!stream.meteringAuthorized;
  }

  consumeAdmissionResource(accountId, stream, byteLength) {
    this.admissionResourceBudget = Math.max(0, (this.admissionResourceBudget ?? 64 * 1024) - byteLength);
  }

  closeStream(agent, stream, reason = 'stream_closed', notify = true) {
    if (stream.closed) return;
    stream.closed = true;
    clearTimeout(stream.timer);
    agent.streams.delete(stream.id);
    try {
      stream.socket.close(1008, reason);
    } catch {}
    if (notify && !agent.closed && this.agents.get(agent.record.connector_id) === agent) {
      try {
        this.send(agent, { type: 'Close', stream_id: stream.id, reason });
      } catch {}
    }
  }

  closeAgent(agent, reason = 'connector_closed') {
    if (agent.closed) return;
    agent.closed = true;
    clearTimeout(agent.timer);
    this.pending.delete(agent);
    if (agent.record && this.agents.get(agent.record.connector_id) === agent) {
      this.agents.delete(agent.record.connector_id);
    }
    for (const stream of [...agent.streams.values()]) {
      this.closeStream(agent, stream, reason, false);
    }
    try {
      agent.socket.close(1008, reason);
    } catch {}
  }

  touch(agent) {
    agent.lastSeen = Date.now();
    clearTimeout(agent.timer);
    agent.timer = setTimeout(() => this.closeAgent(agent, 'connector_heartbeat_expired'), 90_000);
  }

  acceptAgent(request, requestedId) {
    if (this.pending.size >= MAX_PENDING) return json({ error: 'connector_handshake_capacity' }, 429);
    const pair = this.websocket(request);
    if (!pair) return json({ error: 'websocket_required' }, 426);
    const agent = {
      socket: pair.socket,
      closed: false,
      record: null,
      requestedId,
      streams: new Map(),
      nonce: crypto.getRandomValues(new Uint8Array(32)),
      decoder: new FrameDecoder(),
      lastSeen: Date.now(),
    };
    this.pending.add(agent);
    agent.timer = setTimeout(() => this.closeAgent(agent, 'connector_handshake_expired'), 10_000);

    let tail = Promise.resolve(), queued = 0, messages = 0;
    pair.socket.addEventListener('message', event => {
      if (agent.closed) return;
      if (
        !(event.data instanceof ArrayBuffer) ||
        event.data.byteLength > 1024 * 1024 + 4 ||
        queued + event.data.byteLength > 1024 * 1024 ||
        messages >= 64 ||
        this.queuedBytes + event.data.byteLength > MAX_QUEUED
      ) {
        this.closeAgent(agent, 'invalid_connector_frame');
        return;
      }
      const bytes = new Uint8Array(event.data);
      if (!agent.record) {
        if (
          bytes.length < 1 ||
          bytes.length > 1024 ||
          messages >= 4 ||
          queued + bytes.length > 4096 ||
          (!agent.helloQueued &&
            (bytes.length < 5 ||
              new DataView(bytes.buffer, bytes.byteOffset).getUint32(0) !== bytes.length - 4))
        ) {
          this.closeAgent(agent, 'invalid_connector_hello');
          return;
        }
        agent.helloQueued = true;
      }
      queued += bytes.length;
      messages++;
      this.queuedBytes += bytes.length;
      tail = tail
        .then(() => this.agentMessage(agent, bytes))
        .catch(() => this.closeAgent(agent, 'invalid_connector_frame'))
        .finally(() => {
          queued -= bytes.length;
          messages--;
          this.queuedBytes -= bytes.length;
        });
    });
    pair.socket.addEventListener('close', () => this.closeAgent(agent));
    pair.socket.addEventListener('error', () => this.closeAgent(agent));
    this.send(agent, { type: 'HelloChallenge', nonce: agent.nonce });
    return this.upgradeResponse(pair, request);
  }

  async agentMessage(agent, bytes) {
    if (agent.closed) return;
    const frames = agent.decoder.push(bytes);
    if (!agent.record) {
      if (
        frames.length !== 1 ||
        frames[0].type !== 'Hello' ||
        !equalBytes(encodeFrame(frames[0]), bytes)
      ) {
        throw Error('canonical_hello_required');
      }
      const hello = frames[0];
      if (
        hello.connector_id !== agent.requestedId ||
        !scopeId(hello.tenant_id) ||
        ![1, 2].includes(hello.version)
      ) {
        throw Error('invalid_hello');
      }
      const record = await this.authorizeRegistration(hello.connector_id, hello, agent);
      if (agent.closed || this.agents.has(record.connector_id)) {
        throw Error('connector_already_connected');
      }
      agent.record = record;
      agent.version = hello.version;
      this.pending.delete(agent);
      this.agents.set(record.connector_id, agent);
      this.touch(agent);
      this.send(agent, {
        type: 'HelloAccepted',
        version: hello.version,
        lease_id: crypto.randomUUID(),
      });
      if (hello.version === 2) this.send(agent, { type: 'Capabilities', capabilities: 0 });
      return;
    }
    if (this.agents.get(agent.record.connector_id) !== agent) return;
    for (const frame of frames) {
      this.touch(agent);
      if (frame.type === 'Ping') {
        this.send(agent, { type: 'Pong', value: frame.value });
        continue;
      }
      if (frame.type === 'Pong') continue;
      if (frame.type === 'Capabilities' && agent.version === 2 && !agent.capabilitiesReceived) {
        agent.capabilitiesReceived = true;
        continue;
      }
      if (frame.type === 'Telemetry' && frame.target_id === agent.record.target_id) continue;
      if (
        !['DialAccepted', 'ClientAuthenticated', 'Data', 'WindowUpdate', 'Close'].includes(
          frame.type
        ) ||
        frame.stream_id === 0
      ) {
        throw Error('unexpected_agent_frame');
      }
      const stream = agent.streams.get(frame.stream_id);
      if (!stream || stream.closed) continue;
      if (frame.type === 'Close') {
        this.closeStream(agent, stream, frame.reason, false);
        continue;
      }
      if (frame.type === 'ClientAuthenticated') {
        if (!stream.ready || stream.agentMarker || (this.isFreeRelay && stream.authenticated)) {
          this.closeStream(agent, stream, 'invalid_client_authentication');
          continue;
        }
        stream.agentMarker = true;
        if (this.isFreeRelay) {
          stream.authenticated = true;
          stream.meteringAuthorized = true;
          clearTimeout(stream.timer);
        }
        continue;
      }
      if (frame.type === 'DialAccepted') {
        if (stream.ready) {
          this.closeStream(agent, stream, 'duplicate_dial_accept');
          continue;
        }
        stream.ready = true;
        try {
          if (stream.socket.readyState !== OPEN) throw Error('client_closed');
          stream.socket.send(JSON.stringify({ status: 'ready', stream_id: stream.id, admission_id: stream.admissionId }));
        } catch {
          this.closeStream(agent, stream, 'client_closed');
        }
      } else if (frame.type === 'Data') {
        if (!stream.ready) {
          this.closeStream(agent, stream, 'dial_not_ready');
          continue;
        }
        stream.fromAgent(frame.bytes);
      }
    }
  }

  handleClientControl(agent, stream, text, close) {
    try {
      const msg = JSON.parse(text);
      if (msg && (msg.type === 'metering_receipt' || msg.type === 'metering_start')) {
        const receipt = msg.receipt || msg;
        const authorized = this.authorizeMeteringReceipt(agent, stream, receipt);
        if (!authorized) {
          close('invalid_metering_receipt');
          return;
        }
        stream.meteringAuthorized = true;
        stream.authenticated = true;
        clearTimeout(stream.timer);
        return;
      }
    } catch {}
    close('invalid_connector_control');
  }

  authorizeMeteringReceipt(agent, stream, receipt) {
    return false;
  }

  acceptClient(request, connectorId) {
    if (this.pendingClients.size >= MAX_PENDING) return json({ error: 'connector_dial_capacity' }, 429);
    const pair = this.websocket(request);
    if (!pair) return json({ error: 'websocket_required' }, 426);
    const pending = { closed: false, started: false, stream: null, agent: null };
    this.pendingClients.add(pending);
    const close = reason => {
      if (pending.closed) return;
      pending.closed = true;
      this.pendingClients.delete(pending);
      clearTimeout(pending.timer);
      if (pending.stream) this.closeStream(pending.agent, pending.stream, reason);
      else {
        try {
          pair.socket.close(1008, reason);
        } catch {}
      }
    };
    pending.close = close;
    pending.timer = setTimeout(() => close('connector_dial_expired'), 10_000);
    pair.socket.addEventListener('close', () => close('client_closed'));
    pair.socket.addEventListener('error', () => close('client_error'));
    pair.socket.addEventListener('message', event => {
      if (pending.closed) return;
      if (!pending.started) {
        pending.started = true;
        if (typeof event.data !== 'string' || event.data.length > 16 * 1024) {
          close('invalid_connector_request');
          return;
        }
        this.beginDial(connectorId, event.data, pair.socket, pending, close).catch(() =>
          close('connector_dial_denied')
        );
      } else if (
        pending.stream?.ready &&
        event.data instanceof ArrayBuffer &&
        event.data.byteLength <= MAX_DATA
      ) {
        pending.stream.fromClient(event.data);
      } else if (
        pending.stream?.ready &&
        typeof event.data === 'string' &&
        event.data.length <= 16 * 1024
      ) {
        this.handleClientControl(pending.agent, pending.stream, event.data, close);
      } else close('connector_dial_not_ready');
    });
    return this.upgradeResponse(pair, request);
  }

  async beginDial(connectorId, text, socket, pending, close) {
    let parsed;
    try {
      parsed = JSON.parse(text);
    } catch {
      close('invalid_connector_request');
      return;
    }
    const authorized = await this.authorizeDial(connectorId, parsed);
    if (authorized instanceof Response || (authorized && typeof authorized.status === 'number') || pending.closed) {
      close('connector_dial_denied');
      return;
    }
    const agent = authorized.agent || authorized;
    const destination = authorized.destination || Object.freeze({
      target_id: agent.record?.target_id,
      hostname: agent.record?.hostname,
      port: agent.record?.port,
    });
    const accountId = authorized.accountId || agent.record?.subject_id || 'free-self-host';
    const policyEpoch = authorized.policyEpoch || agent.record?.policy_epoch || 1;

    if (
      agent.closed ||
      this.agents.get(connectorId) !== agent ||
      agent.streams.size >= MAX_STREAMS ||
      this.nextStream > 0xffffffff
    ) {
      close('connector_stream_limit');
      return;
    }
    const stream = {
      id: this.nextStream++,
      admissionId: crypto.randomUUID(),
      socket,
      ready: false,
      closed: false,
      authenticated: false,
      agentMarker: false,
      meteringAuthorized: false,
      handshakeBytes: 0,
      chargeSequence: 0,
      destination,
      accountId,
      policyEpoch,
    };
    pending.agent = agent;
    pending.stream = stream;
    this.pendingClients.delete(pending);
    clearTimeout(pending.timer);
    // Bounded setup must accommodate ICE and interactive SSH proof. The byte
    // budget and pending/stream limits continue to apply until verified admission.
    stream.timer = setTimeout(() => close('connector_dial_expired'), 120_000);
    const active = () =>
      !stream.closed &&
      !agent.closed &&
      this.agents.get(connectorId) === agent &&
      agent.streams.get(stream.id) === stream;
    stream.fromClient = this.meteredQueue(
      accountId,
      stream,
      active,
      bytes => this.send(agent, { type: 'Data', stream_id: stream.id, bytes }),
      close
    );
    stream.fromAgent = this.meteredQueue(
      accountId,
      stream,
      active,
      bytes => {
        if (socket.readyState === OPEN) socket.send(bytes);
        else close('client_closed');
      },
      close
    );
    agent.streams.set(stream.id, stream);
    this.send(agent, {
      type: 'Dial',
      stream_id: stream.id,
      target_id: destination.target_id,
      hostname: destination.hostname,
      port: destination.port,
    });
  }

  // Both relay variants share issuance, size/rate limits and provider validation.
  // A subclass must separately grant permission: the base class is fail-closed.
  authorizeTurnCredentials(_authorized, _request) { return false; }

  async reserveTurnIssuance(now) {
    const storage = this.state?.storage;
    if (!storage || typeof storage.transaction !== 'function') return false;
    return storage.transaction(async tx => {
      const prior = await tx.get('turn-issuance-v1');
      const minute = Math.floor(now / 60), hour = Math.floor(now / 3600);
      const value = {
        minute, hour,
        minuteCount: prior?.minute === minute ? prior.minuteCount : 0,
        hourCount: prior?.hour === hour ? prior.hourCount : 0,
      };
      if (value.minuteCount >= 12 || value.hourCount >= 120) return false;
      value.minuteCount++; value.hourCount++;
      await tx.put('turn-issuance-v1', value);
      return true;
    });
  }

  async turnCredentials(request, connectorId) {
    if (request.method !== 'POST') return json({ error: 'method_not_allowed' }, 405);
    // Never accept a browser query token for a credential-minting operation.
    if (new URL(request.url).search || !request.headers.get('x-workload-token')) {
      return json({ error: 'header_authentication_required' }, 401);
    }
    const origin = request.headers.get('origin');
    if (origin && origin !== new URL(request.url).origin) return json({ error: 'origin_forbidden' }, 403);
    if (!turnConfigured(this.env)) return json({ error: 'turn_unconfigured' }, 503);
    const parsed = await readBoundedJson(request, 16 * 1024, 5000);
    if (!parsed.ok) return json({ error: 'invalid_turn_request' }, parsed.status || 400);
    const input = parsed.value;
    const now = Math.floor(Date.now() / 1000);
    if (!input || !scopeId(input.session_id) || !['client', 'agent', 'gateway'].includes(input.peer) ||
        !Number.isInteger(input.ttl) || input.ttl < 60 || input.ttl > MAX_TURN_TTL ||
        !Number.isSafeInteger(input.expires_at_epoch) || input.expires_at_epoch <= now ||
        input.expires_at_epoch > now + 300) return json({ error: 'invalid_turn_request' }, 400);
    // This is the same enrollment, identity, target, entitlement and budget gate
    // as the existing WebSocket dial path. No client-supplied account is trusted.
    const authorized = await this.authorizeDial(connectorId, input);
    if (authorized instanceof Response || typeof authorized?.status === 'number') return authorized;
    if (!await this.authorizeTurnCredentials(authorized, input)) return json({ error: 'turn_authority_required' }, 403);
    const ttl = Math.min(input.ttl, input.expires_at_epoch - now);
    if (ttl < 60) return json({ error: 'session_expiring' }, 403);
    if (!await this.reserveTurnIssuance(now)) return json({ error: 'turn_issuance_limited' }, 429);
    try {
      const credentials = await issueCloudflareTurn(this.env, {
        sessionId: input.session_id, connectorId, accountId: authorized.accountId,
        peer: input.peer, ttl,
      });
      return json({ ...credentials, session_id: input.session_id, peer: input.peer });
    } catch (error) {
      // Keep local 401/403 admission denials distinct from provider-key failure.
      // Never include upstream response bodies, URLs or credential material.
      const allowed = new Set(['turn_provider_permission_required', 'turn_provider_timeout',
        'turn_provider_transport_error', 'invalid_turn_response']);
      const code = allowed.has(error?.message) ? error.message : 'turn_provider_unavailable';
      return json({ error: code }, 502);
    }
  }

  async fetch(request) {
    const path = new URL(request.url).pathname;
    const requestedId = nativeConnectorId(request);
    if (!requestedId || (this.connectorId && this.connectorId !== requestedId)) {
      return json({ error: 'invalid_connector_scope' }, 400);
    }
    this.connectorId = requestedId;
    if (path === '/v1/connectors/stream') {
      if (request.method !== 'GET') return json({ error: 'method_not_allowed' }, 405);
      return this.acceptAgent(request, requestedId);
    }
    const match = path.match(
      /^\/internal\/v1\/connectors\/([A-Za-z0-9_-]{1,128})\/(route|dial-stream|dial-datagram|turn-credentials|browser-ticket)$/
    );
    if (!match) return json({ error: 'not_found' }, 404);
    if (!await this.authorizeWorkload(request)) return json({ error: 'unauthorized' }, 401);
    const [, connectorId, operation] = match;
    if (operation === 'browser-ticket') return this.createBrowserTicket(request, connectorId);
    if (operation === 'turn-credentials') return this.turnCredentials(request, connectorId);
    if (operation === 'dial-datagram') return json({ error: 'authenticated_relay_required' }, 403);
    if (operation === 'route') {
      if (request.method !== 'POST') return json({ error: 'method_not_allowed' }, 405);
      const parsed = await readBoundedJson(request, 16 * 1024, 5000);
      if (!parsed.ok) return json({ error: 'invalid_connector_request' }, parsed.status || 400);
      try {
        const authorized = await this.authorizeDial(connectorId, parsed.value);
        if (authorized instanceof Response || (authorized && typeof authorized.status === 'number')) return authorized;
        const agent = authorized.agent || authorized;
        return json({
          owner_url: null,
          lease_expires_at_epoch: Math.floor((agent.lastSeen + 90_000) / 1000),
        });
      } catch {
        return json({ error: 'connector_unavailable' }, 503);
      }
    }
    if (request.method !== 'GET') return json({ error: 'method_not_allowed' }, 405);
    return this.acceptClient(request, connectorId);
  }
}
