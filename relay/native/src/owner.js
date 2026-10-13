// SPDX-License-Identifier: GPL-3.0-only
import {createServer} from 'node:http';
import {isIP} from 'node:net';
import {WebSocketServer} from 'ws';
import {FreeNativeConnectorRelay} from '../../cloudflare/src/relay.js';
import {nativeConnectorId,nativeConnectorRoute} from '../../cloudflare/src/relay-core.js';
import {isValidRelayToken,timingSafeEqual} from '../../cloudflare/src/security.js';
import {authorizeManagement,managementRoute,relayVersion} from '../../cloudflare/src/public-contract.js';
import {authorizedBrowserOrigin,browserTicketPreflight,parseBrowserTicketProtocols,BROWSER_RELAY_PROTOCOL} from '../../cloudflare/src/browser-tickets.js';
import {LocalRelayState} from './storage.js';
import {RelaySocket,AcceptedSocket} from './socket.js';
import {normalizedRequest,sendResponse,rejectUpgrade} from './http.js';
import {rtcRoute,rtcConfiguration,dispatchRtc,rtcCorsPreflight,withRtcCors} from './rtc.js';
const ticket=/^\/internal\/v1\/connectors\/([A-Za-z0-9_-]{1,128})\/browser-ticket$/;
const describe=/^\/internal\/v1\/connectors\/([A-Za-z0-9_-]{1,128})\/describe$/;
const json=(error,status)=>Response.json({error},{status,headers:{'cache-control':'no-store'}});
const equal=(first,second)=>isValidRelayToken(first)&&isValidRelayToken(second)&&timingSafeEqual(first,second);
function publicOrigin(value){
  try{const url=new URL(value);if(url.protocol!=='https:'||url.origin!==value||url.username||url.password)throw Error();return url.origin;}
  catch{throw Error('canonical_https_public_origin_required');}
}
class OriginRelay extends FreeNativeConnectorRelay {
  constructor(state,env,upgrades,rtc){super(state,env);this.upgrades=upgrades;this.rtc=rtc;}
  supportsTransport(scope){return scope.required_transport===undefined||scope.required_transport==='websocket'||(scope.required_transport==='webrtc'&&this.rtc!==null);}
  async beginDial(id,text,socket,pending,close){
    let scope;try{scope=JSON.parse(text);}catch{close('invalid_connector_request');return;}
    if(scope?.required_transport==='webrtc'&&!socket.rtcAuthorized){close('native_rtc_bridge_required');return;}
    return super.beginDial(id,text,socket,pending,close);
  }
  websocket(request){const socket=this.upgrades.get(request);return socket?{socket}:null;}
  upgradeResponse(pair){return new AcceptedSocket(pair.socket);}
  async authorizeDial(id,value){
    if(!Number.isSafeInteger(value?.expires_at_epoch)||value.expires_at_epoch>Math.floor(Date.now()/1000)+300)return json('invalid_connector_scope',400);
    const result=await super.authorizeDial(id,value);if(result instanceof Response)return result;
    if(result.agent.record.tenant_id!==value.tenant_id||value.subject_id!=='free-self-host')return json('connector_scope_forbidden',403);
    return result;
  }
}
export async function createRelayOwner({env={},statePath,host='127.0.0.1',port=0,maxConnectors=1024,maxConnections=4096,maxInFlight=128}={}){
  if(!['127.0.0.1','::1'].includes(host)||!isIP(host)||!Number.isInteger(port)||port<0||port>65535)throw Error('loopback_relay_listener_required');
  for(const count of [maxConnectors,maxConnections,maxInFlight])if(!Number.isSafeInteger(count)||count<1||count>65536)throw Error('invalid_relay_capacity');
  if(!isValidRelayToken(env.RELAY_AUTH_TOKEN)||!isValidRelayToken(env.RELAY_MANAGEMENT_TOKEN)||equal(env.RELAY_AUTH_TOKEN,env.RELAY_MANAGEMENT_TOKEN))throw Error('independent_relay_credentials_required');
  if(env.NATIVE_RELAY_ORIGIN_TOKEN&&(!isValidRelayToken(env.NATIVE_RELAY_ORIGIN_TOKEN)||
      [env.RELAY_AUTH_TOKEN,env.RELAY_MANAGEMENT_TOKEN].some(token=>equal(token,env.NATIVE_RELAY_ORIGIN_TOKEN))))throw Error('independent_gateway_credential_required');
  const publicBase=publicOrigin(env.RELAY_PUBLIC_ORIGIN);env={...env};
  const rtc=rtcConfiguration(env,publicBase,env.NATIVE_RTC_ALLOW_LOOPBACK_INGRESS==='true');
  if(env.NATIVE_PUBLIC_RTC_ENABLED==='true'&&!rtc)throw Error('independent_valid_rtc_ingress_required');
  const transports=Object.freeze(rtc?['websocket','webrtc']:['websocket']);
  const state=new LocalRelayState(statePath),cores=new Map(),upgrades=new WeakMap(),connections=new Set();
  let closed=false,inFlight=0,queuedBytes=0,closePromise;
  const wss=new WebSocketServer({noServer:true,perMessageDeflate:false,maxPayload:1024*1024+4,maxFragments:128,maxBufferedChunks:256,
    handleProtocols:protocols=>protocols.has(BROWSER_RELAY_PROTOCOL)?BROWSER_RELAY_PROTOCOL:false});
  function getCore(id){
    let core=cores.get(id);if(core)return core;
    if(cores.size>=maxConnectors)return null;
    core=new OriginRelay(state.scope(id),env,upgrades,rtc);
    // The wire engine's queued-byte limit is shared across all connector cores.
    Object.defineProperty(core,'queuedBytes',{get:()=>queuedBytes,set:value=>{queuedBytes=value;}});
    cores.set(id,core);return core;
  }
  async function route(request,bridge){
    if(closed)return json('relay_stopping',503);
    const url=new URL(request.url);
    if(url.searchParams.has('token'))return json('header_authentication_required',401);
    if(env.NATIVE_RELAY_ORIGIN_TOKEN&&!equal(env.NATIVE_RELAY_ORIGIN_TOKEN,request.headers.get('x-native-relay-origin-token')))return json('gateway_authentication_required',401);
    if(['/healthz','/readyz'].includes(url.pathname))return new Response('OK',{headers:{'cache-control':'no-store'}});
    if(['/relay/api/v1/init','/relay/api/v1/version'].includes(url.pathname)){
      if(request.method!=='GET')return json('method_not_allowed',405);
      return Response.json({...relayVersion(),protocol_version:1,coordination:'origin',transports,native_rtc:rtc!==null,
        connect_url:publicBase.replace('https:','wss:')+'/relay/api/v1/connect'},
        {headers:{'cache-control':'no-store','access-control-allow-origin':'*'}});
    }
    if(url.pathname==='/relay/api/v1/connect'){
      url.pathname='/v1/connectors/stream';request=new Request(url,request);
    }
    if(url.pathname!=='/v1/connectors/stream'&&url.search)return json('invalid_relay_query',400);
    const management=managementRoute(url.pathname),metadata=describe.exec(url.pathname),offer=rtcRoute(url.pathname);
    const browser=ticket.exec(url.pathname),offered=parseBrowserTicketProtocols(request.headers.get('sec-websocket-protocol'));
    if(offer&&request.method==='OPTIONS'){
      if(url.search)return json('relay_credentials_require_headers',400);
      return rtcCorsPreflight(request,env);
    }
    const rtcOrigin=offer&&request.headers.has('origin')?authorizedBrowserOrigin(request,env):null;
    if(offer&&request.headers.has('origin')&&!rtcOrigin)return json('origin_forbidden',403);
    const rtcFailure=(code,status)=>withRtcCors(json(code,status),rtcOrigin);
    if(browser&&request.method==='OPTIONS'){
      if(url.search)return json('invalid_browser_ticket_request',400);
      return browserTicketPreflight(request,env);
    }
    if(management){const denied=authorizeManagement(request,env);if(denied)return denied;}
    else{
      if(!nativeConnectorRoute(url.pathname)&&!metadata&&!offer)return json('not_found',404);
      const token=browser?/^Bearer ([\x21-\x7e]{10,256})$/.exec(request.headers.get('authorization')||'')?.[1]:request.headers.get('x-workload-token');
      if(offered.present){
        if(!offered.valid||!/^\/internal\/v1\/connectors\/[A-Za-z0-9_-]{1,128}\/dial-stream$/.test(url.pathname)||!bridge||!authorizedBrowserOrigin(request,env))return json('invalid_browser_ticket',401);
      }else if(!equal(token,env.RELAY_AUTH_TOKEN))return offer?rtcFailure('unauthorized',401):json('unauthorized',401);
      if(browser){
        if(request.method!=='POST'||!authorizedBrowserOrigin(request,env))return json('browser_ticket_unauthorized',401);
        const headers=new Headers(request.headers);headers.delete('authorization');headers.set('x-workload-token',token);
        request=new Request(request,{headers});
      }
    }
    const id=management?.[1]??metadata?.[1]??offer?.[1]??nativeConnectorId(request);
    if(!id)return json('invalid_connector_scope',400);
    const core=getCore(id);if(!core)return offer?rtcFailure('connector_capacity',429):json('connector_capacity',429);
    if(offer){await core.revocationReady;return dispatchRtc(request,rtc,core,id,{env});}
    if(metadata){
      await core.revocationReady;
      if(request.method!=='GET')return json('method_not_allowed',405);
      const agent=core.agents.get(id);
      if(core.operatorRevoked||core.revocationUnavailable||!agent||agent.closed)return json('connector_unavailable',403);
      return Response.json({mode:'self_hosted',connector_id:id,tenant_id:agent.record.tenant_id,subject_id:'free-self-host',transports},{headers:{'cache-control':'no-store'}});
    }
    if(bridge){
      bridge.rtcAuthorized=rtc!==null&&equal(rtc.token,request.headers.get('x-native-rtc-service-token'));
      upgrades.set(request,bridge);
    }
    return core.fetch(request);
  }
  const server=createServer({requestTimeout:10000,headersTimeout:10000,maxHeaderSize:16384},async(incoming,response)=>{
    if(inFlight>=maxInFlight){response.writeHead(429).end();return;}inFlight++;
    try{await sendResponse(response,await route(await normalizedRequest(incoming,publicBase)));}
    catch{if(!response.destroyed)response.writeHead(400,{'content-type':'application/json','cache-control':'no-store'}).end('{"error":"invalid_relay_request"}');}
    finally{inFlight--;}
  });
  server.on('connection',socket=>{
    if(closed||connections.size>=maxConnections){socket.destroy();return;}
    connections.add(socket);socket.once('close',()=>connections.delete(socket));socket.setTimeout(30000,()=>socket.destroy());
  });
  server.on('upgrade',async(incoming,socket,head)=>{
    if(closed||inFlight>=maxInFlight){socket.end('HTTP/1.1 503 Unavailable\r\nConnection: close\r\n\r\n');return;}inFlight++;
    const bridge=new RelaySocket();let accepted=false;
    socket.once('close',()=>bridge.close());
    try{
      const result=await route(await normalizedRequest(incoming,publicBase),bridge);
      if(result instanceof AcceptedSocket&&result.socket===bridge&&bridge.readyState===1&&!socket.destroyed&&!closed){
        wss.handleUpgrade(incoming,socket,head,raw=>{accepted=true;socket.setTimeout(0);bridge.attach(raw);});
      }else{
        bridge.close();await rejectUpgrade(socket,result instanceof Response?result:json('relay_unavailable',503));
      }
    }catch{bridge.close();socket.end('HTTP/1.1 400 Rejected\r\nConnection: close\r\n\r\n');}
    finally{inFlight--;if(!accepted)bridge.close();}
  });
  try{await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(port,host,resolve);});}
  catch(error){await state.close();throw error;}
  const address=server.address();
  return{origin:`http://${host.includes(':')?'['+host+']':host}:${address.port}`,
    close(){return closePromise??=(async()=>{
      closed=true;for(const core of cores.values())core.closeAllStreams();
      const done=new Promise(resolve=>server.close(resolve));
      for(const socket of connections)socket.destroy();wss.close();
      await done;await state.close();
    })();}};
}
