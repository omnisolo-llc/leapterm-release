# Optional Cloudflare TURN credential issuer

This Worker can issue short-lived Cloudflare TURN credentials to authenticated,
live connector sessions. Cloudflare operates the TURN service; this repository
does not run coturn. The existing WebSocket relay remains available.

**This endpoint is not, by itself, a complete application transport upgrade.**
Both peers need a compatible WebRTC implementation, authenticated signaling,
and target authorization. Native `/rtc-offer` signaling is a separate opt-in
that requires the matching `omniterm-rtc-ingress` service, configured
`NATIVE_RTC_INGRESS`, and independent `NATIVE_RTC_SERVICE_TOKEN`. TURN
credential issuance alone does not add a WebRTC relay route. Existing app
releases do not automatically gain TURN, audio, or video by enabling this
setting. Leave native RTC and TURN disabled until the peer integration has
passed a forced-relay test on your supported clients.

## Configure your own account

Create a TURN key in Cloudflare Realtime, then use the secret prompts:

```bash
npx wrangler secret put CLOUDFLARE_TURN_KEY_ID
npx wrangler secret put CLOUDFLARE_TURN_KEY_API_TOKEN
```

The second value is the TURN key's credential-issuance secret, not a generated
short-lived TURN password and not your account-wide Cloudflare API credential.
Keep it distinct from `RELAY_AUTH_TOKEN`. Never paste credentials into a source
file, command argument, issue, or client application.

After setting both secrets, change `RELAY_TURN_ENABLED` to `"true"` in the
Worker's `[vars]` configuration and deploy. No extra Durable Object namespace
or migration is required. Set it back to `"false"` to stop new issuance.
Already issued credentials/allocations may remain usable until expiry; this
switch is not instantaneous revocation of every existing connection.

## Fixing HTTP 403

There are two separate authorization steps. An account API token needs **Calls
Write**, scoped to this account, to create a TURN key. In the current custom-token
form this is Account / Cloudflare Realtime / Edit (older labels used Calls).
Check token expiry and source-IP restrictions.
Successful account lookup or Workers/R2 access does not prove Calls permission.
The simpler route is to create the TURN key directly in the account's Realtime
TURN dashboard.

For credential generation, use that key's ID and matching issuer API token in the
two Worker secrets above. Do not use the account token or a temporary TURN client
password. A mismatched, revoked, or unauthorized issuer must fail; changing relay
authentication or disabling TLS verification will not repair it.

A 401/403 returned by this Worker's own authentication is different: check
`RELAY_AUTH_TOKEN` and connector scope. A provider authorization failure is reported
as `turn_provider_permission_required`; compatible clients may use authenticated
WebSocket in Automatic mode, but must not label that fallback as successful TURN.

## Runtime compatibility and diagnostics

Generated 64-character hexadecimal tokens from `openssl rand -hex 32` are accepted
alongside supported UUID/password formats. Token format validation does not make
predictable strings secure: always generate a fresh random value.

Issuer requests use Workerd-compatible `redirect: "manual"`. Redirect responses
are rejected rather than forwarding a credential-bearing request to another
origin. Do not replace this with `follow`; Workerd also does not support the
browser/Node `redirect: "error"` request setting.

Authenticated issuance failures return bounded categories: provider permission,
provider timeout, provider transport failure, malformed provider response, or
unavailability. None contains upstream response bodies, credentials or SDP.

## Endpoint contract

`POST /internal/v1/connectors/CONNECTOR_ID/turn-credentials` requires the existing
`x-workload-token` header. Query tokens are rejected for this operation. The
request repeats the normal connector dial scope and adds `session_id`, `peer`
(`client` or `agent`), and `ttl` (60–300 seconds). Admission must expire no more
than 300 seconds ahead. A live connector must exist. Responses use `no-store`.

The Worker calls Cloudflare's credential-generation API, returns only the
allowlisted ICE URLs and generated peer credentials, and rejects malformed
responses or an issuer secret accidentally returned as a peer password. The
account/session analytics identifier is an opaque hash. Issuance is limited
transactionally per connector to 12 requests/minute and 120/hour, including
provider failures. These are abuse limits, not a hard provider bandwidth cap.

Free relay token holders form one trusted owner group. Use separate deployments
and tokens for unrelated users. Possession of a TURN credential does not establish
SSH host identity, authorize arbitrary targets, or authenticate a WebRTC peer.
A compatible client must preserve peer identity checks and SSH host-key/auth checks.

## Compatible native agent authentication

A compatible enrolled native agent enables `CONNECTOR_WEBRTC_ENABLED=true` and
uses `CONNECTOR_ENDPOINT=wss://YOUR-RELAY/v1/connectors/stream` without a token in
the URL. Supply `CONNECTOR_RELAY_AUTH_TOKEN` through protected service/process
configuration; it is sent in `x-workload-token` and bound to that WSS origin.
Changing origins requires explicit token reconfiguration. Certificate bypass is
not permitted with this credential. Existing agent and target key enrollment is
still required; the token is not SSH authorization.

The v2 native byte transport supports direct WebRTC, Cloudflare TURN/UDP and WSS
fallback. Its current native driver does not support TURN/TCP or TURN/TLS. Modes
are `auto`, `websocket_only`, `webrtc_only` and `turn_only`. Direct success does not
request TURN credentials. A provider configuration denial can fall back to WSS
in `auto`, but wrong keys/targets never trigger an authentication downgrade.

## Choosing WebSocket or TURN

Cloudflare documentation checked September 19, 2026 lists 1,000 GB of monthly
free egress shared by Realtime TURN and SFU, then $0.05/GB. TURN is attractive for
multiple simultaneous sessions and real-time media. Do not treat that allowance
as a provider-enforced no-charge ceiling.

Durable Objects Free provides 100,000 compute requests and 13,000 GB-seconds of
active duration per day. At Cloudflare's billed 0.128 GB per object, that is about
28.2 aggregate active object-hours/day. Incoming WebSocket messages count at 20:1
for compute-request billing. There is no directly comparable WebSocket GB pool;
large batched transfers through a few objects can have generous free throughput.

Prefer an available authenticated direct peer, then an eligible TURN path, with
WebSocket as fallback. An operator can prefer WebSocket or disable TURN when its
budget is exhausted. Do not fail over after identity or authorization denial.

**Important:** this version's legacy connector WebSocket uses non-hibernating
state. Keeping it open for signaling still consumes object duration even when
payload travels over TURN. Short-lived or hibernating signaling is needed for
the full duration saving; credential issuance alone does not provide that saving.

## Usage reporting and charges

Direct customer-to-agent connections and traffic on the customer's own Cloudflare
account do not incur OmniTerm relay-byte charges. Advisory endpoint sent/received
counters can be recorded without moving payload through an OmniTerm server. They
are never trusted as billing receipts, including for video and audio traffic.

Managed TURN requires a separate existing authorization and cost-accounting path.
Provider egress attributable to that customer must be reconciled with the managed
account's included allowance and credits before charging. A positive client byte
counter alone is not a charge, and sampled provider analytics are not automatically
an exact invoice. The shared policy helper does not replace receipt verification
or the durable idempotent billing ledger. Gate managed TURN until that complete
path is available. Successful direct connectivity never needs that meter.

TURN over UDP is the first relay candidate. TURN/TLS is eligible only after the
selected native/browser runtime passes its own TLS/443 connectivity check; an
endpoint URL in the provider response alone is not a capability test.

## Screen and audio traffic

Raw VNC/RFB and X11 protocol bytes belong on a reliable ordered DataChannel, just
like SSH and SFTP. Screen video and system audio require capture/decoding plus
encoding into separate media tracks. Keys, buttons and clipboard remain reliable;
pointer motion can use a separate latest-state channel. A video track is not an
encoding of arbitrary VNC/X11 bytes. No screen, microphone or system-audio capture
is enabled by this Worker. There is no media transcoder in this kit.

## Verification

```bash
npm test
npm run check
```

Unit tests mock the provider response and exercise endpoint validation, safe
credential handling and rate limits. They do not prove live Cloudflare TURN
connectivity. That requires a peer-to-peer relay-only test using your own
short-lived credentials, with direct routes blocked or absent.

References: [credential generation](https://developers.cloudflare.com/realtime/turn/generate-credentials/),
[Realtime pricing](https://developers.cloudflare.com/realtime/sfu/pricing/),
[TURN FAQ](https://developers.cloudflare.com/realtime/turn/faq/),
[Durable Objects pricing](https://developers.cloudflare.com/durable-objects/platform/pricing/).
