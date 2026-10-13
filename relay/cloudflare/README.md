# Deploy your own Cloudflare relay

This standalone Worker forwards OmniTerm connector WebSocket streams. It uses a
single shared relay token and a SQLite-backed Durable Object namespace for
routing. No D1 database, external database, billing service, private source
checkout, or OmniTerm build credentials are needed.

This is **not a general-purpose HTTP/SOCKS proxy or a STUN/TURN server**.
It connects compatible OmniTerm clients and agents over WebSockets.

An optional [Cloudflare TURN credential issuer](TURN.md) is also included and is
**disabled by default**. Cloudflare operates the TURN server; this Worker only
issues short-lived credentials to authenticated sessions. Turning it on does not
add WebRTC support to an old client or agent. Test compatible peers before enabling
it. The linked guide explains free-tier limits, direct-first routing and why
customer-owned traffic is not an OmniTerm relay charge.

This public kit does not expose native RTC offer signaling or advertise a
WebRTC relay transport. TURN credential issuance remains separate from the
WebSocket relay path.

## Requirements and free-tier limits

Use your own Cloudflare account, Git, and Node.js 22 or newer (Node.js 24 LTS is a
suitable choice). The package locks its Wrangler version; use `npm ci` rather
than a globally installed Wrangler.

Cloudflare supports SQLite-backed Durable Objects on the Workers Free plan.
Free does not mean unlimited: Worker requests and Durable Object requests,
duration and storage have limits. This implementation keeps live connections
in memory and uses regular WebSockets and heartbeat timers, not the WebSocket
hibernation API. Long-lived connections can consume the duration allowance.
On the Free plan, operations exceeding applicable free limits fail; a Paid
plan can incur usage charges. Check your account's plan and usage before relying
on this for continuous service.

Official references: [Wrangler installation](https://developers.cloudflare.com/workers/wrangler/install-and-update/),
[Durable Objects plans and limits](https://developers.cloudflare.com/durable-objects/platform/pricing/),
and [Workers pricing](https://developers.cloudflare.com/workers/platform/pricing/).

## 1. Get only the public relay kit

```bash
git clone https://github.com/omnisolo-llc/omniterm-release.git
cd omniterm-release/relay/cloudflare
npm ci
npm test
npm run check
```

Alternatively, extract the self-host relay ZIP from the repository's Releases
page and enter its `relay/cloudflare` directory. `npm run check` bundles locally;
it does not deploy anything.

## 2. Log in to your Cloudflare account

```bash
npx wrangler login
npx wrangler whoami
```

Approve the browser login and confirm the intended account. When you have more
than one account, select the correct one when prompted. This does not require
access to the application's release workflow or any maintainer GitHub secret.

You may change `name` in `wrangler.toml` to a unique Worker name before your first
deploy. Keep `NATIVE_CONNECTORS`, `NativeConnectorRelay`, and the `v1` SQLite
migration as shipped. Do not reset migration tags on an existing deployment.

## 3. Deploy, then configure a fresh token

```bash
npm run deploy
node -e "console.log(require('node:crypto').randomUUID())"
npx wrangler secret put RELAY_AUTH_TOKEN
```

Copy the newly generated UUID into the secret prompt and save it in your password
manager. **Do not use a UUID or password copied from documentation.** The Worker
rejects connector traffic while the secret is absent or invalid, so the initial
secretless deployment is not an open relay. Wrangler stores the secret on your
own Worker and deploys the updated version.

The token validator accepts a UUID, or 10–256 characters containing uppercase,
lowercase, a number and a symbol with no whitespace. A randomly generated UUID
is the simplest supported option. Do not place the token in `wrangler.toml`,
commit it to Git, pass it as a literal shell argument, or paste it in an issue.

Record the HTTPS URL printed by Wrangler, for example
`https://omniterm-free-relay.YOUR-SUBDOMAIN.workers.dev`.
The same hostname uses `wss://` for WebSocket connections. No custom domain is
required. If Workers asks for a `workers.dev` subdomain, complete that setup in
your Cloudflare account.

Cloudflare's [secret configuration guide](https://developers.cloudflare.com/workers/configuration/secrets/)
explains secret updates and local development. Local `.dev.vars` files are ignored
by Git; never publish one.

## 4. Check reachability and authentication

Replace `YOUR-RELAY` below with your deployed hostname; neither test needs a token.

```bash
curl -i https://YOUR-RELAY/healthz
curl -i 'https://YOUR-RELAY/v1/connectors/stream?connector_id=probe'
```

The health endpoint should return `200 OK`. After configuring a valid server
token, the second request should return `401 Unauthorized`, because it supplies
no client token. A `500 server_misconfiguration` indicates the server token is
missing or invalid. `/healthz` and `/readyz` are reachability checks, **not proof
of a working authenticated relay session**.

## 5. Connect your application and agent

Configure a custom relay in your OmniTerm client using the Worker URL and your
fresh relay token. The connector/agent must use the same relay and token. Every
participant holding this shared token belongs to the same trust group; deploy
separate Workers with separate tokens for users who must not trust each other.

The registration WebSocket route is `/v1/connectors/stream` and requires one
`connector_id` query parameter. Client routes are beneath
`/internal/v1/connectors/CONNECTOR_ID/`. The compatible application/agent constructs
the protocol requests; the Worker alone is not an SSH server. Use the installed
agent's configuration help for its endpoint and credential settings.

Native clients send the shared workload secret in the `x-workload-token` header.
Browser clients first POST to
`/internal/v1/connectors/CONNECTOR_ID/browser-ticket` with
`Authorization: Bearer <workload-token>` and an allowed `Origin`. Configure
`NATIVE_RELAY_BROWSER_ORIGINS` as a comma-separated list of exact HTTPS origins
in Wrangler variables. The response contains a 30-second, one-use ticket; pass
it only in the WebSocket subprotocol list together with `omni-relay.v1`. The
server returns only `omni-relay.v1` as the negotiated protocol. Workload secrets
and tickets are not accepted in URL query strings. Relay authentication does
not replace SSH host-key verification or target-host authentication. Destination
hostnames and routing metadata are visible to the relay; do not describe the
relay as hiding all metadata. Treat each ticket as a bearer credential: do not
persist it or include it in application, proxy, tracing, or error logs. Redact
`Sec-WebSocket-Protocol`, `Authorization`, and `x-workload-token` from request
logging.

Browser native-RTC signaling also requires an exact allowed `Origin`. Its CORS
preflight permits only `POST` with `Content-Type` and `X-Workload-Token`; cookies
and wildcard origins are not used.

Datagram relay is not supported by this free kit. Agent IDs must be unique within
your deployment. A Worker restart or deployment can interrupt in-memory sessions;
clients/agents need to reconnect.

## Updating, token rotation and removal

Review changes, update the public checkout, then run `npm ci`, `npm test`, and
`npm run deploy`. Back up any local configuration outside Git first. Do not copy
another account's bindings or credentials.

Rotate with `npx wrangler secret put RELAY_AUTH_TOKEN`, update your clients and
agents, then reconnect. Existing authenticated WebSockets may remain active until
they disconnect; explicitly terminate sessions when revoking access urgently.

To remove your deployment, run `npx wrangler delete` from this directory and
confirm the exact Worker/account shown by Wrangler. Review remaining Durable
Object namespaces in your dashboard before deleting any stored state.

## Troubleshooting

`401` means missing/wrong client credentials. `500 server_misconfiguration` means
invalid server configuration. `426` on a registration request with valid credentials
means an actual WebSocket upgrade is required. `503 connector_unavailable` means
there is no live agent for that connector ID. Check the ID, agent heartbeat,
network reachability and Cloudflare usage limits.

Use the Cloudflare dashboard's deployment and usage views. Do not post raw logs
or WebSocket URLs containing tokens. If Wrangler complains about Node.js, upgrade
to a supported version and rerun `npm ci`.


## Capability discovery and compatibility

`GET /relay/api/v1/init` returns this kit's actual API version, supported API
versions, the configured transport list, and its canonical WebSocket connection
URL. It includes `webrtc` only when `NATIVE_PUBLIC_RTC_ENABLED`, the independent
`NATIVE_RTC_SERVICE_TOKEN`, and an HTTPS `NATIVE_RTC_INGRESS` are valid. The
`GET /relay/api/v1/version` response returns wire/revision metadata. Both are
public, contain no credentials, and are marked `Cache-Control: no-store`.
The canonical registration endpoint `/relay/api/v1/connect?connector_id=ID`
and the original `/v1/connectors/stream?connector_id=ID` have the same token
and connector-scope checks.

A request that explicitly requires an unavailable transport is rejected rather
than silently accepted on WebSocket. To enable the native RTC path, deploy the
matching `omniterm-rtc-ingress` service separately, set
`NATIVE_PUBLIC_RTC_ENABLED` to `"true"`, set `NATIVE_RTC_INGRESS` to its HTTPS
origin, and store a distinct `NATIVE_RTC_SERVICE_TOKEN` with Wrangler. The
ingress must connect back to this Worker's authenticated `/dial-stream` route
using the configured workload secret and the same RTC service token. The Worker
admits the target before forwarding an offer and verifies the ingress response
signature. Missing or invalid configuration returns `503 native_rtc_unavailable`
and omits `webrtc`; TURN credential issuance alone does not enable WebRTC. SFU
and MoQ remain separate capabilities. Configuration is not proof of nominated
TURN candidates, DTLS/data-channel traffic, owner cutoff, or provider cost
acceptance; those still require the real end-to-end relay acceptance suite.

## Operator revocation and recovery

The shared relay token grants the configured relay trust domain access. It is
not a per-user account or tenant-isolation mechanism. Keep operator control
separate from client/agent connection authority:

```sh
npx wrangler secret put RELAY_MANAGEMENT_TOKEN
```

Choose a separately generated strong token; it must not equal `RELAY_AUTH_TOKEN`.
Do not embed either token in a URL, commit, browser storage without vault
protection, diagnostic log, or public issue. Never give the management token to
ordinary clients or agents. Missing, malformed, or reused operator credentials
make management unavailable; they never enable unauthenticated management.

The operator can send an empty `POST` to either endpoint with the
`x-relay-management-token` header:

```text
/internal/v1/connectors/CONNECTOR_ID/revoke
/internal/v1/connectors/CONNECTOR_ID/restore
```

Successful requests return `204`. Query strings, request bodies, incorrect
methods and unrelated credentials are rejected. Revocation closes established
agent/client streams and pending streams, invalidates unused browser tickets,
and persists a revocation marker in that connector's existing Durable Object.
Subsequent traffic is denied with `403 connector_revoked`, including after the
object or local service restarts. A storage failure leaves the connector closed
and returns an unavailable error instead of claiming durable success.

Restoration is an explicit operator action. It permits a fresh authenticated
connection; it does not resurrect old streams or tickets. Keep an operator-owned
connector inventory and revoke affected connectors before rotating credentials.
Changing a token alone must not be assumed to terminate every already-open
connection. If the operator key is unavailable during an incident, stop the
relay until trusted control is restored instead of weakening authentication.

## What the tests establish

`npm ci && npm test` includes real local Workerd/SQLite-backed Durable Object
checks for registration routing, token denial, browser-ticket origin and
connector binding, real elapsed expiry, and simultaneous replay. Pure wire and
policy tests remain component checks, not provider acceptance.

The private source release suite additionally builds and extracts the public ZIP
and runs Rust assertions against that extracted Worker, actual WebSockets and
a disposable TCP endpoint. These tests check byte transfer, operator authority,
active/pending cutoff, restart persistence and ticket invalidation. A deployment
from the released ZIP in an isolated customer Cloudflare account, final signed
clients, protocol/transport coverage, load/cost limits and platform acceptance
are still required before release certification.
