// SPDX-License-Identifier: GPL-3.0-only
// Normalize against the configured public origin, never the caller's Host header.
export async function normalizedRequest(incoming,publicBase){
  const headers=new Headers();
  for(let index=0;index<incoming.rawHeaders.length;index+=2){
    const name=incoming.rawHeaders[index].toLowerCase();
    if(['authorization','x-workload-token','x-relay-management-token','x-native-relay-origin-token',
      'x-native-rtc-service-token'].includes(name)&&headers.has(name))throw Error('ambiguous_headers');
    if(['x-native-relay-public-scope','x-native-relay-browser-origin','cookie','forwarded'].includes(name))continue;
    headers.append(name,incoming.rawHeaders[index+1]);
  }
  if(!incoming.url?.startsWith('/')||incoming.url.startsWith('//')||incoming.url.includes('\\'))throw Error('invalid_path');
  const parts=[];let bytes=0;
  if(incoming.method!=='GET'&&incoming.method!=='HEAD'){
    for await(const part of incoming){bytes+=part.length;if(bytes>32768)throw Error('request_too_large');parts.push(part);}
  }
  return new Request(new URL(incoming.url,publicBase),{method:incoming.method,headers,
    body:parts.length?Buffer.concat(parts):undefined});
}
export async function sendResponse(response,result){
  const bytes=Buffer.from(await result.arrayBuffer());
  if(!response.destroyed)response.writeHead(result.status,{...Object.fromEntries(result.headers),'content-length':bytes.length}).end(bytes);
}
export async function rejectUpgrade(socket,result){
  if(socket.destroyed)return;
  const body=Buffer.from(await result.arrayBuffer());
  socket.end(`HTTP/1.1 ${result.status} Rejected\r\nConnection: close\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nContent-Length: ${body.length}\r\n\r\n${body}`);
}
