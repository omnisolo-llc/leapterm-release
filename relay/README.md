# Self-hosted Cloudflare relay

The first-party browser live-share MoQT provider is a separate service in
[moq](moq/README.md). It owns real HTTP/3 sessions and provides the protected
token-control endpoint required for authoritative participant cutoff.

The [Cloudflare relay](cloudflare/README.md) connects compatible LeapTerm clients
and agents over WebSockets, with optional native WebRTC signaling through a
separately deployed RTC ingress. Deploy it to your own Cloudflare account and
create your own access token; no private source or maintainer credentials are
needed.

The kit contains a Worker, its routing code, a deployment configuration, and tests.
It does not include the desktop/mobile apps, an SSH server, or a STUN/TURN server.

**[Deploy the relay →](cloudflare/README.md)**

For browser live-share over MoQ, deploy the first-party HTTP/3 provider from
[moq](moq/README.md). It owns active WebTransport sessions and confirms cutoff
before acknowledging viewer removal. The live-share origin needs the provider's
HTTPS control origin and independent control token, and the web deployment must
set `moq_origin` to the same HTTPS origin.

Use Node.js 24.21.0 or newer. The MoQ endpoint also needs direct UDP/443 access;
do not assume an HTTP-only reverse proxy supports WebTransport.

## Coordinated relay connection updates

A relay connection identifies an enrolled host or agent route. Configuration
fields named `connector_id` contain that route's enrolled relay connection ID.

Update the relay kit and its agents together. Both the direct Worker and the
ordinary-process relay require relay connection protocol `Hello` version 2 and scoped-destination
capability `8192`. Network dials use `DialScoped` (wire tag 47) with scope version
1; the relay refuses older or incapable agents and never falls back to an
unscoped `Dial`. The HTTP discovery API remains version 1, which is separate
from the relay connection wire version and does not prove compatible negotiation.

Deploy the matching relay before upgrading its agents, and plan for existing
connections to reconnect. For the ordinary-process option, update the sibling
`cloudflare/src` directory along with `native`; it supplies their shared wire
engine. Keep the existing Durable Object namespace/migration and native state
database when updating.

The default destination policy permits public addresses only. An operator may
set the trusted relay environment value `LEAPTERM_ALLOW_LOCAL_NETWORK` to the
string `true` or `1` to permit private networks. Client request fields, purpose
labels and headers cannot enable that setting. The Agent still enforces its
target authorization and hard denials, including loopback destinations, when
the operator enables private networks. The relay introduces no caller-supplied
CIDR grants.

The source is licensed under [GPL-3.0](../LICENSE). Cloudflare's service limits
and charges are separate from the software license.
