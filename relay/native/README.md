# Self-hosted ordinary-process relay

This package runs the public connector protocol in a Node.js process. It does
not use Durable Objects, D1, an OmniTerm account database, or OmniTerm billing.
The existing Cloudflare Worker relay remains a separate deployment option.

## Runtime and storage

Use Node.js 24.21.0 or newer, install this package with `npm ci --ignore-scripts`,
and run `npm start`. The public kit must include the sibling `cloudflare/src`
directory: the native owner uses that same public protocol engine.

The listener is deliberately restricted to loopback. Publish it through your
own HTTPS reverse proxy with WebSocket upgrade support. Do not expose a plain
HTTP listener to the Internet. Configure:

- `RELAY_PUBLIC_ORIGIN`: the exact public HTTPS origin, without a trailing slash.
- `RELAY_AUTH_TOKEN`: the independent workload credential used by your peers.
- `RELAY_MANAGEMENT_TOKEN`: a different operator-only credential.
- `RELAY_STATE_PATH`: a persistent local SQLite file in an owner-only directory.
- `RELAY_PORT`: the loopback HTTP port; the default is 7777.

The state directory must be owned by the process user with mode 0700; existing
state files must be regular owner-only files. A separate SQLite exclusive
transaction prevents two owners from opening the same state. Process exit
releases that lock; a stale PID file is not used. Keep the database and its WAL
on persistent local storage. Do not run independent owners behind round-robin
routing: an active connector has one socket owner.

The database stores connector denial state, hashed short-lived browser tickets,
and bounded issuance windows. It does not store relay credentials or stream
contents. Missing storage, corruption, conflicting ownership, and invalid
permissions fail closed.

## Browser WebSocket access

Set `NATIVE_RELAY_BROWSER_ORIGINS` to an explicit comma-separated list of allowed
HTTPS app origins. The browser exchanges its bearer credential at the public
browser-ticket endpoint for an origin-bound one-use ticket. It then offers the
ticket in the WebSocket subprotocol list. Credentials are not accepted in URL
query parameters. Do not record authorization or WebSocket subprotocol headers
in reverse-proxy logs.

Browser RTC offers use the same exact-origin allowlist. Their CORS preflight is
limited to `POST` with `Content-Type` and `X-Workload-Token`; cookies and
wildcard origins are not used. Native and browser offers share the same
admission, ingress-service signature check, and fail-closed transport rules.

## Operator revocation

POST `/internal/v1/connectors/{id}/revoke` with the operator credential in
`x-relay-management-token`. A workload credential cannot revoke or restore a
connector. Revocation closes existing streams and persists across restart.
POST the corresponding `/restore` endpoint with the operator credential to
explicitly allow the connector again. Keep operator and workload credentials
separate; the server rejects configurations that reuse them.

## Native RTC ingress

The WebRTC signaling path requires a separately installed matching
`omniterm-rtc-ingress` binary. It is not implemented by TURN credential issuance
and is not a fallback to a WebSocket-only connection. Set
`NATIVE_PUBLIC_RTC_ENABLED=true`, `NATIVE_RTC_INGRESS`, and a distinct
`NATIVE_RTC_SERVICE_TOKEN`. A loopback HTTP ingress also requires
`NATIVE_RTC_ALLOW_LOOPBACK_INGRESS=true`. Other ingress URLs must use HTTPS.

The native ingress owns DTLS/data-channel negotiation while this process owns
connector authorization, actual target streams, and revocation. Signaling
responses are bound to a fresh request, exact scope, offer, answer, stream, and
admission identifier using the independently configured ingress credential.
The ingress must also authenticate its internal backend WebSocket; an ordinary
workload connection cannot claim to be a WebRTC bridge.

`/relay/api/v1/init` reports the configured transport list. A disabled or invalid
RTC configuration is not advertised as supported. This is configuration
metadata, not a health or end-to-end acceptance certificate.

## Verification status

The release tests extract this package from the public ZIP and exercise actual
sockets, TCP bytes, ticket consumption, revocation, and restart persistence.
Full native RTC and browser-origin acceptance must also pass before publication.
No all-platform or all-transport release approval is implied by this package.
