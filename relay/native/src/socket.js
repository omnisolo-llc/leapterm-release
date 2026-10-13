// SPDX-License-Identifier: GPL-3.0-only
// EventTarget boundary for actual ws sockets; no Cloudflare emulation.
const LIMIT=1024*1024+4096;
export class AcceptedSocket {constructor(socket){this.socket=socket;}}
export class RelaySocket extends EventTarget {
  constructor(){super();this.readyState=1;this.pending=[];this.pendingBytes=0;this.raw=null;}
  attach(raw){
    if(this.raw)throw Error('relay_socket_already_attached');
    this.raw=raw;if(this.readyState!==1){raw.terminate();return;}
    raw.on('message',(value,binary)=>{
      if(this.readyState!==1)return;
      this.dispatchEvent(new MessageEvent('message',{data:binary?
        value.buffer.slice(value.byteOffset,value.byteOffset+value.byteLength):value.toString('utf8')}));
    });
    raw.once('close',()=>this.retire());raw.once('error',()=>this.close(1011,'relay_socket_failed'));
    const waiting=this.pending;this.pending=[];this.pendingBytes=0;
    for(const value of waiting)this.send(value);
  }
  send(value){
    if(this.readyState!==1)throw Error('relay_socket_closed');
    const data=typeof value==='string'?value:Buffer.from(value instanceof ArrayBuffer?new Uint8Array(value):value);
    const size=Buffer.byteLength(data);
    if(size>LIMIT||(!this.raw&&(this.pendingBytes+size>LIMIT||this.pending.length>=64))||
        (this.raw&&(this.raw.readyState!==1||this.raw.bufferedAmount+size>LIMIT))){
      this.close(1008,'relay_backpressure_limit');throw Error('relay_backpressure_limit');
    }
    if(!this.raw){this.pending.push(data);this.pendingBytes+=size;return;}
    this.raw.send(data,error=>{if(error)this.close(1011,'relay_write_failed');});
  }
  retire(){
    if(this.readyState===3)return;
    this.readyState=3;this.pending=[];this.pendingBytes=0;
    this.dispatchEvent(new Event('close'));
  }
  close(code=1000,reason='relay_closed'){
    if(this.readyState===3)return;this.retire();if(!this.raw)return;
    try{this.raw.close(code,reason);}catch{this.raw.terminate();}
    const timer=setTimeout(()=>this.raw.terminate(),1000);
    timer.unref();this.raw.once('close',()=>clearTimeout(timer));
  }
}
