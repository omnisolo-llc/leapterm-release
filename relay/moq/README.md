# OmniTerm first-party MoQT relay

This package owns the WebTransport/HTTP/3 sessions used by OmniTerm's browser
MoQ transport. The authenticated HTTPS control API and QUIC data plane run in
one Node process so token revocation can close each admitted connection and
wait for the transport's closed event before acknowledging cutoff.

## Run

Use Node 24 and a direct public HTTPS origin with a TLS certificate whose
subject covers `MOQ_PUBLIC_ORIGIN`. TCP and UDP may use the same port: TCP
serves the authenticated control API while UDP serves HTTP/3. The provider
origin must be DNS-only unless the selected network proxy has been accepted for
WebTransport end to end. Configure UDP ingress and do not place a round-robin
load balancer in front of this single-process owner.

Set these values through the host's secret/configuration manager:

```text
MOQ_PUBLIC_ORIGIN=https://moq.example.com
MOQ_CONTROL_TOKEN=<32..512-character independent secret>
MOQ_TLS_CERT_FILE=/run/secrets/moq-cert.pem
MOQ_TLS_KEY_FILE=/run/secrets/moq-key.pem
MOQ_CONTROL_HOST=0.0.0.0
MOQ_CONTROL_PORT=443
MOQ_DATA_HOST=0.0.0.0
MOQ_DATA_PORT=443
MOQ_MAX_RELAYS=512
MOQ_MAX_SESSIONS=1024
MOQ_USAGE_URL=https://api.example.com/internal/v1/live-share/moq/usage
MOQ_USAGE_TOKEN=<independent Worker-to-relay usage secret>
MOQ_MANAGED_USAGE_REQUIRED=true
```

Install the locked package and start it. Installation requires Git, tar, CMake,
a C++20 compiler, and the ICU development libraries. Optional upstream tests
and interpreter discovery are disabled for this native build. The explicit
`npm run native-build` command verifies and rebuilds the adapter source closure
from the SHA-512-pinned npm tarball in `package-lock.json`
(`sha512-UOcDhjzQEll2sYC2nGBtklTkKCdx442LVPP9jxp09ZU12qYTG65pjPBC38PbZAJEoIwkBP85h7o2fuIcN2W73Q==`).
It uses adapter commit `212ef743f0cf52adb234d60d5b41c48257e967b4` only to verify
the pinned Quiche gitlink `80bf9559d3a4c08dde4b85abc46d190a88ffef64`. Tracked
patches cover the Quiche peer CLOSE/FIN acknowledgement, adapter-side reporting
of observed QUIC connection shutdown, and deferred client teardown after the
native receive callback unwinds. The rebuilt binary is installed at the exact
platform-specific Release path selected by the adapter loader; the stock
generic prebuild fallback and Debug addon are removed. Owner cutoff is
acknowledged only after the patched adapter reports the HTTP/3 session closed.

```sh
npm ci --omit=dev --ignore-scripts
npm run native-build
npm start
```

Configure the OmniTerm live-share origin/Worker with the matching public
configuration:

```text
LIVE_SHARE_MOQ_ENABLED=true
LIVE_SHARE_MOQ_PROVIDER=first_party
LIVE_SHARE_MOQ_CONTROL_ORIGIN=https://moq.example.com
LIVE_SHARE_MOQ_PUBLIC_ORIGIN=https://moq.example.com
LIVE_SHARE_MOQ_CONTROL_TOKEN=<same secret as MOQ_CONTROL_TOKEN>
LIVE_SHARE_MOQ_USAGE_ORIGIN=https://api.example.com
LIVE_SHARE_MOQ_USAGE_TOKEN=<same secret as MOQ_USAGE_TOKEN>
LIVE_SHARE_MOQ_MANAGED=true
```

The public Flutter web `config.json` must set `moq_origin` to that exact HTTPS
origin. The browser verifies the control service's provider URL against this
deployment-owned value before opening WebTransport. Keep the management secret
on the Worker/origin only. Keep the usage secret separate from the control
secret and provision it only to the Worker and relay service. The relay accepts
only the exact HTTPS usage endpoint path shown above, with no query or fragment.
Its authenticated readiness probe fails unless the Worker confirms usage
authority. `MOQ_MANAGED_USAGE_REQUIRED=true` additionally requires every room
creation to carry the Worker origin and a finite byte ceiling, checks active
owner/quota authority periodically, and closes the room on revocation, expiry,
quota exhaustion, or an unavailable authority.

## Authorization and limits

Control requests require the independent bearer secret, same-origin URL and a
bounded JSON body. Relay creation binds an 8-character share ID, epoch and
expiry. Each participant receives a separate random token scoped to that share,
epoch, participant ID and one role (`publish` or `subscribe`). One publisher
and at most nine viewers are allowed per room. Tokens expire no later than the
room or five minutes; concurrent sessions are bounded by `MOQ_MAX_SESSIONS`.

The close endpoint marks admission closed before terminating existing sessions.
It acknowledges only the exact token IDs after every session's transport has
closed; a timeout returns `503` and cannot be treated as proof. Owner termination
closes every token in the room. A short-lived tombstone makes successful room
closure idempotent if the response is lost. Process shutdown also closes every
session and exits unsuccessfully if the transport owner cannot confirm cutoff.

State is intentionally process-local because the process owns the QUIC sockets.
Run one active replica until a separately reviewed relay-ID sharding and
failover protocol exists. A restart drops all connections; source-room owners
must reauthorize before reconnect. Provider availability, CPU, bandwidth,
connection cost and sustained-load budgets require deployment-specific
measurement. Token URL paths, `Authorization`, and control request bodies must
be redacted from proxy/access logs.

### Native build identity and confirmed shutdown

The `native-build` command verifies the package-lock tarball integrity, adapter
package version, pinned Quiche source identity, all three patch digests, the patched
source trees, and the platform/CPU-specific Release binary. Its receipt is
accepted only when Node loads that exact addon; a stale CMake path is rebuilt
locally. `node scripts/build-patched-webtransport.mjs --verify-only` checks the
receipt without downloads or compilation and fails on an absent or different
addon.

Client teardown waits until the native receive callback has unwound before
releasing the socket. This preserves the peer FIN/close acknowledgement; it
neither invents server closure nor lengthens the five-second cutoff deadline.
Self-hosted readiness reports `worker_usage_metering: false` when no account
meter is configured. Configured or required managed metering still fails closed
when its authenticated Worker readiness call fails.
