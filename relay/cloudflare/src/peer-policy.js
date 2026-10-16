// Shared transport policy. Available means the complete authenticated path is
// usable, not merely that a TURN hostname or a saved profile exists.
export function peerTransportOrder({ direct = false, turn = false, turnTls = false, websocket = true,
  managed = false, authoritativeMeter = false, turnBudgetAvailable = true,
  preferWebsocket = false } = {}) {
  // `direct` means authenticated customer-device <-> customer-agent connectivity,
  // NOT a direct gateway-to-agent hop. Account subscription is not a byte cost.
  // Only the selected managed relay resource requires authoritative metering.
  const peerAllowed = !managed || authoritativeMeter;
  const relay = [];
  if (turn && turnBudgetAvailable && peerAllowed) relay.push('turn-udp');
  // A TLS URL in configuration is not evidence that the native stack supports it.
  if (turnTls && turnBudgetAvailable && peerAllowed) relay.push('turn-tls');
  if (websocket) preferWebsocket ? relay.unshift('websocket') : relay.push('websocket');
  return [...(direct ? ['direct-peer'] : []), ...relay];
}

export function channelPolicy(kind) {
  if (['ssh', 'sftp', 'vnc-wire', 'x11-wire', 'keyboard', 'clipboard'].includes(kind)) {
    return { transport: 'datachannel', ordered: true, reliable: true, maxMessageBytes: 16384 };
  }
  if (kind === 'pointer-motion') return { transport: 'datachannel', ordered: false, reliable: false, maxRetransmits: 0 };
  if (kind === 'screen-video') return { transport: 'srtp-video', requires: 'capture-and-encoder' };
  if (kind === 'system-audio') return { transport: 'srtp-audio', requires: 'capture-and-encoder' };
  throw Error('unsupported_channel_kind');
}
