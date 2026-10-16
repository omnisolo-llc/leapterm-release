import test from 'node:test';
import assert from 'node:assert/strict';
import {peerUsageTelemetry} from '../src/peer-usage.js';
test('free relay endpoint statistics are advisory, not charges',()=>{
 for(const path of ['direct-peer','turn-udp','turn-tls','websocket','srtp-video','srtp-audio']){
  const usage=peerUsageTelemetry({path,resourceOwner:'customer',sentBytes:123,receivedBytes:456});
  assert.equal(usage.billingEligible,false);assert.equal(usage.authority,'endpoint-estimate');
 }
});
test('invalid endpoint counters are rejected without network calls',()=>{
 for(const sentBytes of [-1,NaN,Infinity,Number.MAX_SAFE_INTEGER+1,'10']){
  assert.throws(()=>peerUsageTelemetry({path:'direct-peer',resourceOwner:'none',sentBytes,receivedBytes:0}));
 }
});
