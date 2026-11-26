(()=>{
// 隔离上下文内的 API；没有 require、文件系统或系统环境变量。
// 宿主函数先收进闭包再从全局删除，脚本无法直接调用或替换它们。
const __host_call = __host, __finish_call = __finish, __store_r = __store_read, __store_w = __store_write, __enc = __utf8encode, __dec = __utf8decode, __ungz = __ungzip, __gz = __gzip, __b64 = __base64, __b64b = __b64_bytes;
const input = JSON.parse(__input);
const __rb = typeof __req_body === 'undefined' ? undefined : __req_body;
const __sb = typeof __res_body === 'undefined' ? undefined : __res_body;
for (const k of ['__host','__finish','__store_read','__store_write','__utf8encode','__utf8decode','__ungzip','__gzip','__base64','__b64_bytes','__input','__req_body','__res_body']) delete globalThis[k];
let finished = false, nextID = 1;
let requests = [], callbacks = new Map(), timers = new Map(), logs = [], notifications = [];
const $request = ['http-request','http-response','rule'].includes(input.kind) && input.request && typeof input.request === 'object' ? input.request : undefined;
const $response = input.response && typeof input.response === 'object' ? input.response : undefined;
if ($request && __rb !== undefined) {
 $request.body = __rb;
 if (__rb instanceof Uint8Array) $request.bodyBytes = __rb;
}
if ($response) {
 if ($response.status !== undefined && $response.statusCode === undefined) $response.statusCode = $response.status;
 if (__sb !== undefined) {
  $response.body = __sb;
  if (__sb instanceof Uint8Array) $response.bodyBytes = __sb;
 }
}
const $argument = (input.argument === null || input.argument === undefined) ? undefined : input.argument;
const ctx = {env: Object.assign({}, input.env || {})};
const $script = {name: input.name, type: input.kind, binaryBodyMode: input.binary, startTime: Date.now() / 1000};
const $environment = {
 "surge-version": "5.11.0",
 "surge-build": "3000",
 "system": "iOS",
 "system-version": "18.0",
 "device-model": "iPhone",
 "language": "zh-Hans",
 "oryn-version": "0.0.1"
};
const $loon = input.loon ? "Oryn compatibility" : undefined;
const control = (name,extra={}) => {const r=JSON.parse(__host_call(JSON.stringify(Object.assign({control:name},extra))));if(r.error)throw Error(r.error);return r;};
const $surge = {
 selectGroupDetails:()=>control('groups'),
 setSelectGroupPolicy:(group,name)=>!!control('select',{group,name}).ok,
 setOutboundMode:mode=>!!control('mode',{mode}).ok,
 logbook:(...v)=>console.log(...v)
};
const $config = {
 getConfig:()=>JSON.stringify(control('groups')),
 setSelectPolicy:(group,name)=>!!control('select',{group,name}).ok,
 getSelectedPolicy:group=>control('groups').decisions[group]||null,
 getSubPolicies:(group,cb)=>cb(JSON.stringify(control('groups').groups[group]||[])),
 setRunningModel:mode=>!!control('mode',{mode:['direct','rule','global-proxy'][mode]}).ok
};
// 不伪造 Surge HTTP API 的响应结构；未实现的接口明确返回错误。
const $httpAPI=(method,path,body,cb)=>cb({error:'Unsupported HTTP API endpoint: '+method+' '+path});
class TextEncoder {get encoding(){return 'utf-8'} encode(text=''){return __enc(String(text));}}
class TextDecoder {constructor(label='utf-8',options={}){if(!['utf-8','utf8'].includes(label.toLowerCase()))throw Error('Unsupported text encoding');this.fatal=!!options.fatal;this.encoding='utf-8';}decode(bytes){return __dec(new Uint8Array(bytes||[]),this.fatal);}}
const atob=text=>__b64(String(text),false), btoa=text=>__b64(String(text),true);
const $utils = {
 ungzip:bytes=>__ungz(bytes instanceof Uint8Array?bytes:new Uint8Array(bytes||[])),
 gzip:bytes=>__gz(bytes instanceof Uint8Array?bytes:(typeof bytes==='string'?__enc(bytes):new Uint8Array(bytes||[])))
};
const $network = {};
const $event = (input.event === null || input.event === undefined) ? undefined : input.event;
const $cronexp = (input.cron === null || input.cron === undefined) ? undefined : input.cron;

// 轻量标准 URL / URLSearchParams，覆盖 iRingo / BiliUniverse / DualSubs / Script-Hub 等脚本依赖。
function __safeDecode(s){try{return decodeURIComponent(s.replace(/\+/g,' '));}catch(_){return s;}}
function __encodeParam(s){return encodeURIComponent(String(s)).replace(/%20/g,'+');}
class URLSearchParams {
 constructor(init='',onChange){
  this._list=[];
  this._onChange=onChange||null;
  if(init instanceof URLSearchParams){for(const [k,v] of init._list)this._list.push([k,v]);}
  else if(Array.isArray(init)){for(const p of init)if(Array.isArray(p)&&p.length>=2)this._list.push([String(p[0]),String(p[1])]);}
  else if(init&&typeof init==='object'){for(const k of Object.keys(init))this._list.push([String(k),String(init[k])]);}
  else if(typeof init==='string'&&init.length>0){
   const s=init.charAt(0)==='?'?init.slice(1):init;
   if(s.length>0){for(const part of s.split('&')){if(!part)continue;const eq=part.indexOf('=');const k=eq<0?part:part.slice(0,eq);const v=eq<0?'':part.slice(eq+1);this._list.push([__safeDecode(k),__safeDecode(v)]);}}
  }
 }
 _notify(){if(this._onChange)this._onChange();}
 get size(){return this._list.length;}
 append(k,v){this._list.push([String(k),String(v)]);this._notify();}
 delete(k){k=String(k);this._list=this._list.filter(p=>p[0]!==k);this._notify();}
 get(k){k=String(k);const p=this._list.find(x=>x[0]===k);return p?p[1]:null;}
 getAll(k){k=String(k);return this._list.filter(x=>x[0]===k).map(x=>x[1]);}
 has(k){k=String(k);return this._list.some(x=>x[0]===k);}
 set(k,v){k=String(k);v=String(v);let found=false;const next=[];for(const p of this._list){if(p[0]===k){if(!found){next.push([k,v]);found=true;}}else next.push(p);}if(!found)next.push([k,v]);this._list=next;this._notify();}
 sort(){this._list.sort((a,b)=>a[0]<b[0]?-1:(a[0]>b[0]?1:0));this._notify();}
 forEach(cb,thisArg){for(const [k,v] of this._list)cb.call(thisArg,v,k,this);}
 keys(){return this._list.map(p=>p[0])[Symbol.iterator]();}
 values(){return this._list.map(p=>p[1])[Symbol.iterator]();}
 entries(){return this._list.map(p=>[p[0],p[1]])[Symbol.iterator]();}
 [Symbol.iterator](){return this.entries();}
 toString(){return this._list.map(([k,v])=>__encodeParam(k)+'='+__encodeParam(v)).join('&');}
}
const __defaultPorts={'http:':'80','https:':'443','ws:':'80','wss:':'443'};
class URL {
 constructor(url,base){
  let raw=String(url);
  const schemeRe=/^([a-zA-Z][a-zA-Z0-9+.-]*):/;
  if(!schemeRe.test(raw)&&base!==undefined){
   const b=base instanceof URL?base:new URL(base);
   if(raw.startsWith('//'))raw=b.protocol+raw;
   else if(raw.startsWith('/'))raw=b.origin+raw;
   else if(raw.startsWith('?'))raw=b.origin+b.pathname+raw;
   else if(raw.startsWith('#'))raw=b.origin+b.pathname+b.search+raw;
   else{const dir=b.pathname.replace(/[^/]*$/,'');raw=b.origin+dir+raw;}
  }
  const m=raw.match(/^([a-zA-Z][a-zA-Z0-9+.-]*):\/\/([^/?#]*)([^?#]*)(\?[^#]*)?(#.*)?$/);
  if(!m)throw new TypeError('Invalid URL: '+raw);
  this._protocol=m[1].toLowerCase()+':';
  let auth=m[2];
  this._username='';this._password='';
  const at=auth.lastIndexOf('@');
  if(at>=0){const cred=auth.slice(0,at);auth=auth.slice(at+1);const ci=cred.indexOf(':');if(ci>=0){this._username=cred.slice(0,ci);this._password=cred.slice(ci+1);}else{this._username=cred;}}
  if(auth.startsWith('[')){
   const rb=auth.indexOf(']');
   this._hostname=rb>=0?auth.slice(0,rb+1).toLowerCase():auth.toLowerCase();
   const rest=rb>=0?auth.slice(rb+1):'';
   this._port=rest.startsWith(':')?rest.slice(1):'';
  }else{
   const ci=auth.lastIndexOf(':');
   if(ci>=0){this._hostname=auth.slice(0,ci).toLowerCase();this._port=auth.slice(ci+1);}
   else{this._hostname=auth.toLowerCase();this._port='';}
  }
  if(__defaultPorts[this._protocol]===this._port)this._port='';
  this._pathname=m[3]||'/';
  this._search=m[4]||'';
  this._hash=m[5]||'';
  this._params=new URLSearchParams(this._search,()=>{const s=this._params.toString();this._search=s?'?'+s:'';});
 }
 get protocol(){return this._protocol;}
 set protocol(v){v=String(v).toLowerCase();this._protocol=v.endsWith(':')?v:v+':';if(__defaultPorts[this._protocol]===this._port)this._port='';}
 get username(){return this._username;}
 set username(v){this._username=String(v);}
 get password(){return this._password;}
 set password(v){this._password=String(v);}
 get hostname(){return this._hostname;}
 set hostname(v){this._hostname=String(v).toLowerCase();}
 get port(){return this._port;}
 set port(v){v=String(v);this._port=(__defaultPorts[this._protocol]===v)?'':v;}
 get host(){return this._port?this._hostname+':'+this._port:this._hostname;}
 set host(v){v=String(v);const ci=v.lastIndexOf(':');if(ci>=0&&!v.endsWith(']')){this.hostname=v.slice(0,ci);this.port=v.slice(ci+1);}else{this.hostname=v;this._port='';}}
 get origin(){return this._protocol+'//'+this.host;}
 get pathname(){return this._pathname;}
 set pathname(v){v=String(v);this._pathname=v.startsWith('/')?v:'/'+v;}
 get search(){return this._search;}
 set search(v){v=String(v);this._search=v?(v.startsWith('?')?v:'?'+v):'';this._params._list=new URLSearchParams(this._search)._list;}
 get searchParams(){return this._params;}
 get hash(){return this._hash;}
 set hash(v){v=String(v);this._hash=v?(v.startsWith('#')?v:'#'+v):'';}
 get href(){const cred=this._username?(this._username+(this._password?':'+this._password:'')+'@'):'';return this._protocol+'//'+cred+this.host+this._pathname+this._search+this._hash;}
 set href(v){const u=new URL(v);this._protocol=u._protocol;this._username=u._username;this._password=u._password;this._hostname=u._hostname;this._port=u._port;this._pathname=u._pathname;this._search=u._search;this._hash=u._hash;this._params._list=u._params._list;}
 toString(){return this.href;}
 toJSON(){return this.href;}
}

function headerObject(obj){if(Array.isArray(obj)||!obj)return obj;return new Proxy(obj,{get:(o,k)=>typeof k==='string'?o[Object.keys(o).find(x=>x.toLowerCase()===k.toLowerCase())||k]:o[k],set:(o,k,v)=>{const old=Object.keys(o).find(x=>x.toLowerCase()===String(k).toLowerCase());o[old||k]=v;return true;},deleteProperty:(o,k)=>{const old=Object.keys(o).find(x=>x.toLowerCase()===String(k).toLowerCase());delete o[old||k];return true;}});}
for(const m of [$request,$response])if(m)m.headers=headerObject(m.headers);
function normalizeBody(b){
 if(b===undefined||b===null)return undefined;
 if(typeof b==='string'||b instanceof Uint8Array)return b;
 if(b instanceof ArrayBuffer)return new Uint8Array(b);
 if(ArrayBuffer.isView(b))return new Uint8Array(b.buffer,b.byteOffset,b.byteLength);
 return b;
}
function pickBody(obj){
 if(!obj||typeof obj!=='object')return undefined;
 if(Object.prototype.hasOwnProperty.call(obj,'body')){
  const b=normalizeBody(obj.body);
  if(b!==undefined)return b;
 }
 if(Object.prototype.hasOwnProperty.call(obj,'bodyBytes')){
  return normalizeBody(obj.bodyBytes);
 }
 return undefined;
}
function stripBody(obj){
 const out={};
 for(const k of Object.keys(obj)){
  if(k==='body'||k==='bodyBytes')continue;
  if(k==='response'&&obj.response&&typeof obj.response==='object'){
   const r={};
   for(const rk of Object.keys(obj.response))if(rk!=='body'&&rk!=='bodyBytes')r[rk]=obj.response[rk];
   out.response=r;
  }else{
   out[k]=obj[k];
  }
 }
 return out;
}
function $done(v = {}) {
    if(finished) return;
    if(input.loon && input.kind==='http-request' && arguments.length===0) v={abort:true};
    if(!v || typeof v !== 'object') v={};
    const bodyVal = pickBody(v);
    const respBodyVal = pickBody(v.response);
    __finish_call(JSON.stringify(stripBody(v)), bodyVal, respBodyVal);
    finished = true; callbacks.clear(); timers.clear(); requests=[];
}
const console = {log: (...v) => { if(logs.length < 64) logs.push(v.map(x=>typeof x==='string'?x:JSON.stringify(x)).join(' ').slice(0,4096)); }};
console.info=console.debug=console.warn=console.error=console.log;
const $persistentStore = {
    read: (k=input.name)=>{if(typeof k!=='string')return null;const v=__store_r(k);return v===undefined?null:v;},
    write: (v,k=input.name)=>{
        if(typeof k!=='string') return false;
        if(v===null||v===undefined) return __store_w(k, null);
        if(typeof v!=='string') return false;
        return __store_w(k, v);
    }
};
const $notification = {post:(title,subtitle,body,options)=>{if(notifications.length<4)notifications.push({title:String(title).slice(0,256),subtitle:String(subtitle||'').slice(0,256),body:String(body||'').slice(0,4096),options});}};
const $httpClient = {};
for(const method of ['get','post','put','delete','head','options','patch']) $httpClient[method]=(options,cb)=>{
    if(requests.length>=8)throw Error('script HTTP request limit');
    const id=nextID++;callbacks.set(id,cb);
    const opts=Object.assign({},typeof options==='string'?{url:options}:options,{method:method.toUpperCase()});
    const rawBody=opts.body!==undefined&&opts.body!==null?opts.body:opts.bodyBytes;
    const norm=normalizeBody(rawBody);
    delete opts.bodyBytes;
    if(norm instanceof Uint8Array){
        delete opts.body;
        opts.body_base64=__b64b(norm);
    }else if(norm!==undefined){
        opts.body=norm;
    }else{
        delete opts.body;
    }
    requests.push({id,options:opts});
};
function __deliver(id,metaJson,bodyVal){
    const r=JSON.parse(metaJson);
    const cb=callbacks.get(id);callbacks.delete(id);
    if(!finished&&cb){
        const response=r.response||{};
        if(response.status!==undefined&&response.statusCode===undefined)response.statusCode=response.status;
        response.headers=headerObject(response.headers);
        const data=bodyVal!==undefined?bodyVal:(r.binary?new Uint8Array(0):'');
        if(r.binary&&data instanceof Uint8Array)response.bodyBytes=data;
        cb(r.error||null,response,data);
    }
}
function setTimeout(fn,delay=0){if(timers.size>=64)throw Error('timer limit');const id=nextID++;timers.set(id,{fn,due:Date.now()+Math.max(0,Number(delay)||0),repeat:0});return id;}
function clearTimeout(id){timers.delete(id);}
function setInterval(fn,delay=0){if(timers.size>=64)throw Error('timer limit');const ms=Math.max(10,Number(delay)||10);const id=nextID++;timers.set(id,{fn,due:Date.now()+ms,repeat:ms});return id;}
function clearInterval(id){timers.delete(id);}
function __timers(){for(const [id,t] of Array.from(timers)){if(t.due<=Date.now()){if(t.repeat>0){t.due=Date.now()+t.repeat;}else{timers.delete(id);}t.fn();if(finished)break;}}}
// next：距最近一个定时器到期的毫秒数，没有定时器时为 null；pending：仍有等待回复的 HTTP 请求。
function __poll(){let next=null;for(const t of timers.values()){const d=Math.max(0,t.due-Date.now());if(next===null||d<next)next=d;}return JSON.stringify({done:finished,request:requests.shift()||null,next,pending:callbacks.size>0});}
function __take_logs(){const out={logs,notifications};logs=[];notifications=[];return JSON.stringify(out);}

Object.assign(globalThis, {$utils,TextEncoder,TextDecoder,URL,URLSearchParams,atob,btoa,$surge,$config,$httpAPI,ctx,$script,$environment,$network,$done,console,$persistentStore,$notification,$httpClient,setTimeout,clearTimeout,setInterval,clearInterval});
// 只在确实存在时挂载上下文变量，避免 `"$loon" in globalThis` / `"$response" in globalThis` 误判。
if($loon!==undefined)globalThis.$loon=$loon;
if($request!==undefined)globalThis.$request=$request;
if($response!==undefined)globalThis.$response=$response;
if($argument!==undefined)globalThis.$argument=$argument;
if($event!==undefined)globalThis.$event=$event;
if($cronexp!==undefined)globalThis.$cronexp=$cronexp;
// 宿主协议函数不可写、不可删除、不可枚举，脚本无法伪造状态或改写定时器调度。
for (const [k,v] of Object.entries({__poll,__take_logs,__deliver,__timers})) Object.defineProperty(globalThis,k,{value:v,writable:false,configurable:false,enumerable:false});
})();
