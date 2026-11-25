(()=>{
// 隔离上下文内的 API；没有 require、文件系统或系统环境变量。
// 宿主函数先收进闭包再从全局删除，脚本无法直接调用或替换它们。
const __host_call = __host, __finish_call = __finish, __store_r = __store_read, __store_w = __store_write, __enc = __utf8encode, __dec = __utf8decode, __gz = __ungzip, __b64 = __base64;
const input = JSON.parse(__input);
const __rb = typeof __req_body === 'undefined' ? undefined : __req_body;
const __sb = typeof __res_body === 'undefined' ? undefined : __res_body;
for (const k of ['__host','__finish','__store_read','__store_write','__utf8encode','__utf8decode','__ungzip','__base64','__input','__req_body','__res_body']) delete globalThis[k];
let finished = false, nextID = 1;
let requests = [], callbacks = new Map(), timers = new Map(), logs = [], notifications = [];
const $request = ['http-request','http-response','rule'].includes(input.kind) ? input.request || undefined : undefined;
const $response = input.response || undefined;
if ($request && __rb !== undefined) $request.body = __rb;
if ($response && __sb !== undefined) $response.body = __sb;
const $argument = input.argument;
const ctx = {env: Object.assign({}, input.env || {})};
const $script = {name: input.name, type: input.kind, binaryBodyMode: input.binary};
const $environment = {"surge-version": "5", "oryn-version": "0.0.1"};
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
const $utils = {ungzip:bytes=>__gz(new Uint8Array(bytes))};
const $network = {};
const $event = input.event;
const $cronexp = input.cron;
function headerObject(obj){if(Array.isArray(obj)||!obj)return obj;return new Proxy(obj,{get:(o,k)=>typeof k==='string'?o[Object.keys(o).find(x=>x.toLowerCase()===k.toLowerCase())||k]:o[k],set:(o,k,v)=>{const old=Object.keys(o).find(x=>x.toLowerCase()===String(k).toLowerCase());o[old||k]=v;return true;},deleteProperty:(o,k)=>{const old=Object.keys(o).find(x=>x.toLowerCase()===String(k).toLowerCase());delete o[old||k];return true;}});}
for(const m of [$request,$response])if(m)m.headers=headerObject(m.headers);
function normalizeBody(b){
 if(b===undefined||typeof b==='string'||b instanceof Uint8Array)return b;
 if(b instanceof ArrayBuffer)return new Uint8Array(b);
 if(ArrayBuffer.isView(b))return new Uint8Array(b.buffer,b.byteOffset,b.byteLength);
 return b;
}
function stripBody(obj){
 const out={};
 for(const k of Object.keys(obj)){
  if(k==='body')continue;
  if(k==='response'&&obj.response&&typeof obj.response==='object'){
   const r={};
   for(const rk of Object.keys(obj.response))if(rk!=='body')r[rk]=obj.response[rk];
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
    const bodyVal = Object.prototype.hasOwnProperty.call(v, 'body') ? normalizeBody(v.body) : undefined;
    const respBodyVal = v.response && typeof v.response === 'object' && Object.prototype.hasOwnProperty.call(v.response, 'body')
        ? normalizeBody(v.response.body) : undefined;
    __finish_call(JSON.stringify(stripBody(v)), bodyVal, respBodyVal);
    finished = true; callbacks.clear(); timers.clear(); requests=[];
}
const console = {log: (...v) => { if(logs.length < 64) logs.push(v.map(x=>typeof x==='string'?x:JSON.stringify(x)).join(' ').slice(0,4096)); }};
console.warn=console.error=console.log;
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
    requests.push({id,options:Object.assign({},typeof options==='string'?{url:options}:options,{method:method.toUpperCase()})});
};
function __deliver(id,metaJson,bodyVal){const r=JSON.parse(metaJson);const cb=callbacks.get(id);callbacks.delete(id);if(!finished&&cb){const response=r.response||{};response.headers=headerObject(response.headers);const data=bodyVal!==undefined?bodyVal:(r.binary?new Uint8Array(0):'');cb(r.error||null,response,data);}}
function setTimeout(fn,delay=0){if(timers.size>=64)throw Error('timer limit');const id=nextID++;timers.set(id,{fn,due:Date.now()+Math.max(0,Number(delay))});return id;}
function clearTimeout(id){timers.delete(id);}
function __timers(){for(const [id,t] of timers){if(t.due<=Date.now()){timers.delete(id);t.fn();if(finished)break;}}}
// next：距最近一个定时器到期的毫秒数，没有定时器时为 null；pending：仍有等待回复的 HTTP 请求。
function __poll(){let next=null;for(const t of timers.values()){const d=Math.max(0,t.due-Date.now());if(next===null||d<next)next=d;}return JSON.stringify({done:finished,request:requests.shift()||null,next,pending:callbacks.size>0});}
function __take_logs(){const out={logs,notifications};logs=[];notifications=[];return JSON.stringify(out);}

Object.assign(globalThis, {$utils,TextEncoder,TextDecoder,atob,btoa,$surge,$config,$httpAPI,$event,$cronexp,$request,$response,$argument,ctx,$script,$environment,$loon,$network,$done,console,$persistentStore,$notification,$httpClient,setTimeout,clearTimeout});
// 宿主协议函数不可写、不可删除、不可枚举，脚本无法伪造状态或改写定时器调度。
for (const [k,v] of Object.entries({__poll,__take_logs,__deliver,__timers})) Object.defineProperty(globalThis,k,{value:v,writable:false,configurable:false,enumerable:false});
})();
