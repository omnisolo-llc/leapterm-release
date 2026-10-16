// SPDX-License-Identifier: GPL-3.0-only
// Denial state and hashed, expiring tickets only. No credentials or stream data.
import {DatabaseSync} from 'node:sqlite';
import {constants,closeSync,openSync,lstatSync,realpathSync,mkdirSync} from 'node:fs';
import {dirname,resolve} from 'node:path';
const identifier=value=>typeof value==='string'&&/^[A-Za-z0-9_-]{1,128}$/.test(value);
const validKey=value=>typeof value==='string'&&(value==='operator-revoked-v1'||value==='turn-issuance-v1'||
  /^native-relay-browser-ticket-v1:[a-f0-9]{64}$/.test(value)||/^native-relay-browser-ticket-window-v1:[0-9]{1,16}$/.test(value));
function privateFile(path){
  try{closeSync(openSync(path,constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW,0o600));}
  catch(error){if(error.code!=='EEXIST')throw error;}
  const stat=lstatSync(path);
  if(!stat.isFile()||stat.isSymbolicLink()||(stat.mode&0o077)||(process.getuid&&stat.uid!==process.getuid()))throw Error('relay_state_permissions');
}
export class LocalRelayState {
  constructor(path,maximum=100000){
    if(typeof path!=='string'||!path||path===':memory:'||!Number.isSafeInteger(maximum)||maximum<1||maximum>1000000)throw Error('relay_state_required');
    path=resolve(path);const parent=dirname(path);
    mkdirSync(parent,{recursive:true,mode:0o700});const stat=lstatSync(parent);
    if(realpathSync(parent)!==parent||!stat.isDirectory()||(stat.mode&0o077)||(process.getuid&&stat.uid!==process.getuid()))throw Error('relay_state_directory_must_be_private');
    this.maximum=maximum;this.tail=Promise.resolve();this.closed=false;
    try{
      privateFile(path+'.owner');privateFile(path);
      this.owner=new DatabaseSync(path+'.owner',{timeout:0});
      this.owner.exec('PRAGMA journal_mode=DELETE; BEGIN EXCLUSIVE');
      this.db=new DatabaseSync(path,{timeout:2000,enableDoubleQuotedStringLiterals:false});
      const version=this.db.prepare('PRAGMA user_version').get().user_version;
      if(version!==0&&version!==1)throw Error('unsupported_relay_state');
      if(version===0&&this.db.prepare("SELECT COUNT(*) AS n FROM sqlite_master WHERE type='table'").get().n!==0)throw Error('unrecognized_relay_state');
      this.db.exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
        CREATE TABLE IF NOT EXISTS relay_state(scope TEXT NOT NULL,key TEXT NOT NULL,value TEXT NOT NULL,expires INTEGER,
        PRIMARY KEY(scope,key)) STRICT;
        CREATE INDEX IF NOT EXISTS relay_expiry ON relay_state(expires); PRAGMA user_version=1;`);
      if(this.db.prepare('SELECT COUNT(*) AS n FROM relay_state').get().n>maximum)throw Error('relay_state_capacity');
      for(const row of this.db.prepare('SELECT scope,key,value FROM relay_state').iterate()){
        if(!identifier(row.scope)||!validKey(row.key)||Buffer.byteLength(row.value)>4096)throw Error('relay_state_corrupt');
        const value=JSON.parse(row.value);
        if(row.key==='operator-revoked-v1'&&typeof value!=='boolean')throw Error('relay_state_corrupt');
      }
    }catch{
      try{this.db?.close();}finally{try{this.owner?.exec('ROLLBACK');}catch{}this.owner?.close();}
      throw Error('relay_state_unavailable_or_already_owned');
    }
  }
  enqueue(action){
    if(this.closed)return Promise.reject(Error('relay_state_closed'));
    const result=this.tail.then(action);this.tail=result.catch(()=>{});return result;
  }
  scope(scope){
    if(!identifier(scope))throw Error('invalid_connector_scope');
    const transaction=action=>this.enqueue(async()=>{
      this.db.exec('BEGIN IMMEDIATE');let committed=false;
      try{
        const now=Math.floor(Date.now()/1000);
        this.db.prepare('DELETE FROM relay_state WHERE expires IS NOT NULL AND expires<=?').run(now);
        const api={
          get:async key=>{
            if(!validKey(key))throw Error('invalid_relay_state_key');
            const row=this.db.prepare('SELECT value FROM relay_state WHERE scope=? AND key=?').get(scope,key);
            return row?JSON.parse(row.value):undefined;
          },
          put:async(key,value,options={})=>{
            if(!validKey(key))throw Error('invalid_relay_state_key');
            const encoded=JSON.stringify(value);
            if(typeof encoded!=='string'||Buffer.byteLength(encoded)>4096)throw Error('relay_state_value_too_large');
            const ttl=options.expirationTtl;
            if(ttl!==undefined&&(!Number.isInteger(ttl)||ttl<1||ttl>3600))throw Error('relay_state_expiry');
            const exists=this.db.prepare('SELECT 1 FROM relay_state WHERE scope=? AND key=?').get(scope,key);
            if(!exists&&this.db.prepare('SELECT COUNT(*) AS n FROM relay_state').get().n>=this.maximum)throw Error('relay_state_capacity');
            this.db.prepare('INSERT INTO relay_state(scope,key,value,expires) VALUES(?,?,?,?) ON CONFLICT(scope,key) DO UPDATE SET value=excluded.value,expires=excluded.expires')
              .run(scope,key,encoded,ttl===undefined?null:now+ttl);
          },
          delete:async keys=>{
            const list=Array.isArray(keys)?keys:[keys];
            if(list.length>4096||list.some(key=>!validKey(key)))throw Error('invalid_relay_state_key');
            for(const key of list)this.db.prepare('DELETE FROM relay_state WHERE scope=? AND key=?').run(scope,key);
          },
          list:async({prefix=''})=>{
            if(typeof prefix!=='string'||prefix.length>128)throw Error('invalid_relay_state_key');
            const rows=this.db.prepare('SELECT key,value FROM relay_state WHERE scope=? AND substr(key,1,?)=? ORDER BY key LIMIT 4097').all(scope,prefix.length,prefix);
            if(rows.length>4096)throw Error('relay_state_capacity');
            return new Map(rows.map(row=>[row.key,JSON.parse(row.value)]));
          },
        };
        const result=await action(api);this.db.exec('COMMIT');committed=true;return result;
      }finally{if(!committed)this.db.exec('ROLLBACK');}
    });
    return{storage:{transaction,get:key=>transaction(tx=>tx.get(key))}};
  }
  async close(){
    if(this.closed)return;this.closed=true;await this.tail;
    try{this.db.close();}finally{try{this.owner.exec('ROLLBACK');}finally{this.owner.close();}}
  }
}
