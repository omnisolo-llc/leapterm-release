// Offline tests only. No external provider requests or real credentials.
import test from 'node:test';
import assert from 'node:assert/strict';
import { issueCloudflareTurn, turnConfigured, validateIceServers } from '../src/cloudflare-turn.js';
import { peerTransportOrder, channelPolicy } from '../src/peer-policy.js';
import { FreeNativeConnectorRelay } from '../src/relay.js';
const providerReply = () => ({ iceServers: [
  { urls: ['stun:stun.cloudflare.com:3478'] },
  { urls: ['turn:turn.cloudflare.com:3478?transport=udp'], username: 'issued-user', credential: 'issued-password' },
] });
function storage() {
  const values = new Map(); let tail = Promise.resolve();
  const api = { get: async key => structuredClone(values.get(key)),
    put: async (key,value) => values.set(key, structuredClone(value)),
    transaction: fn => {const next=tail.then(()=>fn(api));tail=next.catch(()=>{});return next;} };
  return api;
}
test('TURN remains disabled unless explicitly and separately configured',()=>{
  assert.equal(turnConfigured({}),false);
  assert.equal(turnConfigured({RELAY_TURN_ENABLED:'false'}),false);
});
test('only official supported ICE endpoints are accepted',()=>{
  assert.equal(validateIceServers(providerReply(),'fixture').length,2);
  for(const url of ['turns:turn.cloudflare.com:5349?transport=udp','http://example.test']) {
    const reply=providerReply();reply.iceServers[1].urls=[url];
    assert.throws(()=>validateIceServers(reply,'fixture'));
  }
});
test('provider object response is normalized without losing peer credentials',()=>{
  const server=providerReply().iceServers[1];
  assert.deepEqual(validateIceServers({iceServers:server},'fixture'),[server]);
  assert.deepEqual(validateIceServers({iceServers:{...server,urls:server.urls[0]}},'fixture'),[server]);
});
test('port 53 is removed but unsupported hosts remain rejected',()=>{
  const server=providerReply().iceServers[1];
  assert.deepEqual(validateIceServers({iceServers:{...server,urls:[...server.urls,'turn:turn.cloudflare.com:53?transport=udp']}},'fixture'),[server]);
  assert.throws(()=>validateIceServers({iceServers:{...server,urls:['turn:evil.example:3478?transport=udp']}},'fixture'));
});
test('issuer credentials cannot be returned as peer credentials',()=>{
  const reply=providerReply();
  assert.throws(()=>validateIceServers(reply,reply.iceServers[1].credential));
});
test('credential issuance uses the provider response rather than invented usernames',async()=>{
  const env={RELAY_TURN_ENABLED:'true',CLOUDFLARE_TURN_KEY_ID:'fixture',CLOUDFLARE_TURN_KEY_API_TOKEN:'fixture'.repeat(8)};
  const scope={sessionId:'session',connectorId:'connector',accountId:'owner',peer:'client',ttl:120};
  let sent;
  const result=await issueCloudflareTurn(env,scope,async (url,init)=>{
    sent={url,init};return Response.json(providerReply());
  });
  assert(sent.url.endsWith('/credentials/generate-ice-servers'));
  assert.equal(JSON.parse(sent.init.body).ttl,120);
  assert.match(JSON.parse(sent.init.body).customIdentifier,/^[a-f0-9]{64}$/);
  assert.equal(sent.init.redirect,'manual');
  assert.equal(result.iceServers[1].username,'issued-user');
  assert(!JSON.stringify(result).includes(env.CLOUDFLARE_TURN_KEY_API_TOKEN));
});
test('issuer never follows redirects with credential-bearing headers',async()=>{
  const env={RELAY_TURN_ENABLED:'true',CLOUDFLARE_TURN_KEY_ID:'fixture',CLOUDFLARE_TURN_KEY_API_TOKEN:'fixture'.repeat(8)};
  let calls=0;
  await assert.rejects(issueCloudflareTurn(env,{sessionId:'s',connectorId:'c',accountId:'a',peer:'client',ttl:120},
    async(_url,init)=>{calls++;assert.equal(init.redirect,'manual');return new Response(null,{status:302,headers:{location:'https://untrusted.example'}});}),/^Error: turn_provider_unavailable$/);
  assert.equal(calls,1);
});
test('network failure returns a finite code rather than fetch diagnostics',async()=>{
  const env={RELAY_TURN_ENABLED:'true',CLOUDFLARE_TURN_KEY_ID:'fixture',CLOUDFLARE_TURN_KEY_API_TOKEN:'fixture'.repeat(8)};
  await assert.rejects(issueCloudflareTurn(env,{sessionId:'s',connectorId:'c',accountId:'a',peer:'client',ttl:120},
    async()=>{throw new TypeError('private upstream diagnostics');}),/^Error: turn_provider_transport_error$/);
});
test('provider response bodies are not echoed in failures',async()=>{
  const env={RELAY_TURN_ENABLED:'true',CLOUDFLARE_TURN_KEY_ID:'fixture',CLOUDFLARE_TURN_KEY_API_TOKEN:'fixture'.repeat(8)};
  await assert.rejects(issueCloudflareTurn(env,{sessionId:'s',connectorId:'c',accountId:'a',peer:'client',ttl:120},
    async()=>new Response('provider-specific private detail',{status:403})),/^Error: turn_provider_permission_required$/);
});
test('parallel credential reservations are serialized and bounded',async()=>{
  const relay=new FreeNativeConnectorRelay({storage:storage()},{});
  const results=await Promise.all(Array.from({length:25},()=>relay.reserveTurnIssuance(10000)));
  assert.equal(results.filter(Boolean).length,12);
  assert.equal(await new FreeNativeConnectorRelay({},{}).reserveTurnIssuance(10000),false);
});
test('transport priority depends on availability, budget and trusted metering',()=>{
  assert.deepEqual(peerTransportOrder({direct:true,turn:true,turnTls:true}),['direct-peer','turn-udp','turn-tls','websocket']);
  assert.deepEqual(peerTransportOrder({direct:true,turn:true,managed:true}),['direct-peer','websocket']);
  assert.deepEqual(peerTransportOrder({turn:true,turnBudgetAvailable:false}),['websocket']);
  assert.deepEqual(peerTransportOrder({direct:true,turn:true}),['direct-peer','turn-udp','websocket']);
  assert.deepEqual(peerTransportOrder({turn:true,turnTls:true,preferWebsocket:true}),['websocket','turn-udp','turn-tls']);
});
test('lossless protocols and media tracks have distinct policies',()=>{
  for(const kind of ['ssh','sftp','vnc-wire','x11-wire','keyboard','clipboard']) {
    assert.equal(channelPolicy(kind).transport,'datachannel');assert.equal(channelPolicy(kind).reliable,true);
  }
  assert.equal(channelPolicy('screen-video').transport,'srtp-video');
  assert.equal(channelPolicy('system-audio').requires,'capture-and-encoder');
  assert.equal(channelPolicy('pointer-motion').maxRetransmits,0);
});
