import test from 'node:test';
import assert from 'node:assert/strict';
import {isValidRelayToken, validateRelayToken} from '../src/security.js';
import worker from '../src/index.js';

const token='3f72a8c01d46e59bf82ac4d7319fe605c49172e8bd634a0f952dc8b36a14ef07';
test('generated 256-bit hex relay tokens are accepted consistently',async()=>{
  assert.equal(validateRelayToken(token),null);
  assert.equal(isValidRelayToken(token),true);
  let routed=false;
  const response=await worker.fetch(new Request('https://relay.test/internal/v1/connectors/agent/route',{
    method:'POST',headers:{'x-workload-token':token},body:'{}'
  }),{RELAY_AUTH_TOKEN:token,NATIVE_CONNECTORS:{idFromName:()=> 'fixture',get:()=>({fetch:async()=>{routed=true;return new Response('authorized');}})}});
  assert.equal(response.status,200);assert(routed);
});
test('hex tokens still reject whitespace and malformed lengths',()=>{
  for(const invalid of [' '+token,token+'\n',token.slice(0,63),token+'a','weak-password',token.slice(0,60)+'zzzz']){
    assert.notEqual(validateRelayToken(invalid),null);
  }
});
