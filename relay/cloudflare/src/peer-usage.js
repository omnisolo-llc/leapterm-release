// Endpoint usage is advisory and never a billing input. A direct customer peer
// path must not be routed through a managed gateway merely to count its bytes.
const kinds=new Set(['direct-peer','turn-udp','turn-tls','websocket','srtp-video','srtp-audio']);
export function validateUsageByteCount(value){if(!Number.isSafeInteger(value)||value<0)throw Error('invalid_usage_bytes');return value;}
export function peerUsageTelemetry({path,resourceOwner,sentBytes,receivedBytes}){
  if(!kinds.has(path)||!['none','customer','managed'].includes(resourceOwner))throw Error('invalid_usage_path');
  return {path,resourceOwner,sentBytes:validateUsageByteCount(sentBytes),receivedBytes:validateUsageByteCount(receivedBytes),
    authority:'endpoint-estimate',billingEligible:false};
}
