export type TargetPreset = {
  id: string; name: string; profile_revision: string; policy_ref: string;
  platform_id?: string|null; platform_name?: string|null;
  authorization_status: 'review_required'|'reviewed_for_offline_configuration';
  endpoint: string; protocol: 'openai-chat'; method: 'POST'; models: string[]; default_model: string;
  timeout_min: number; timeout_max: number; timeout_default: number;
  credential_alias: string|null; credential_availability: string;
  request_mapping: 'openai-chat-user-message-v1'; response_parser: 'choices.0.message.content';
  connection_probe: {status:'unsupported';reason:'safe_probe_not_verified';active_probe_authorized:false;security_execution_authorized:false};
  capabilities: string[]; capability_basis: string; limitations: string[];
};
export type Draft = Pick<TargetPreset,'profile_revision'|'policy_ref'|'endpoint'|'protocol'|'method'|'request_mapping'|'response_parser'|'credential_alias'> & {target_id:string;model:string;timeout_seconds:number};
export type ValidationResult = {configuration_status:'valid'|'invalid';errors:string[];target_id:string;profile_revision:string;connection_reachable:null;runtime_protocol_compatible:null;target_execution_performed:false;security_verdict:null};
export type EvaluationMode = 'rule_only'|'hybrid';
type Obj=Record<string,unknown>;
function obj(v:unknown):Obj{if(!v||typeof v!=='object'||Array.isArray(v))throw Error('contract');return v as Obj;}
function strings(v:unknown){if(!Array.isArray(v)||v.some(s=>typeof s!=='string'))throw Error('contract');}
function envelope(v:unknown){const o=obj(v);if(o.workflow_schema_version!=='1.0.0')throw Error('contract');return o;}
export function parseTargets(v:unknown):{targets:TargetPreset[];protocols:{id:string;state:string}[]}{
 const o=envelope(v);if(!Array.isArray(o.targets)||!Array.isArray(o.protocols))throw Error('contract');
 const identities=new Set<string>(),platforms=new Map<string,string>();
 for(const t of o.targets){
  const p=obj(t),probe=obj(p.connection_probe);
  if(probe.status!=='unsupported'||probe.reason!=='safe_probe_not_verified'||probe.active_probe_authorized!==false||probe.security_execution_authorized!==false)throw Error('contract');
  const url=new URL(String(p.endpoint));if(!["http:","https:"].includes(url.protocol)||url.username||url.password||url.search||url.hash)throw Error('contract');
  for(const k of ['id','name','profile_revision','policy_ref','endpoint','default_model','credential_availability','capability_basis'])if(typeof p[k]!=='string')throw Error('contract');
  const id=String(p.id);if(identities.has(id))throw Error('contract');identities.add(id);
  const platformId=p.platform_id??null,platformName=p.platform_name??null;
  if((platformId===null)!==(platformName===null))throw Error('contract');
  if(platformId!==null){
   if(typeof platformId!=='string'||!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(platformId)||typeof platformName!=='string'||!(/^[A-Za-z0-9 ._-]{1,80}$/.test(platformName)))throw Error('contract');
   if(platforms.has(platformId)&&platforms.get(platformId)!==platformName)throw Error('contract');platforms.set(platformId,platformName);
  }
  if(!/^[a-f0-9]{64}$/.test(String(p.profile_revision))||p.protocol!=='openai-chat'||p.method!=='POST'||p.request_mapping!=='openai-chat-user-message-v1'||p.response_parser!=='choices.0.message.content')throw Error('contract');
  if(!['review_required','reviewed_for_offline_configuration'].includes(String(p.authorization_status)))throw Error('contract');
  if(p.credential_alias!==null&&typeof p.credential_alias!=='string')throw Error('contract');
  for(const k of ['models','capabilities','limitations'])strings(p[k]);
  for(const k of ['timeout_min','timeout_max','timeout_default'])if(!Number.isSafeInteger(p[k])||Number(p[k])<1||Number(p[k])>120)throw Error('contract');
 }
 for(const p of o.protocols){if(typeof obj(p).id!=='string'||typeof obj(p).state!=='string')throw Error('contract');}return o as unknown as {targets:TargetPreset[];protocols:{id:string;state:string}[]};
}
export function parseValidation(v:unknown):ValidationResult{const r=envelope(v);if(!['valid','invalid'].includes(String(r.configuration_status))||r.connection_reachable!==null||r.runtime_protocol_compatible!==null||r.target_execution_performed!==false||r.security_verdict!==null)throw Error('contract');strings(r.errors);if(typeof r.target_id!=='string'||typeof r.profile_revision!=='string'||(r.configuration_status==='valid'&&(r.errors as string[]).length))throw Error('contract');return r as unknown as ValidationResult;}
async function request<T>(route:string,parse:(v:unknown)=>T,signal:AbortSignal,body?:Draft,nonce?:string):Promise<T>{
 try{const r=await fetch(`/api/testing/${route}`,{method:body?'POST':'GET',credentials:'omit',cache:'no-store',signal:AbortSignal.any([signal,AbortSignal.timeout(10000)]),headers:body?{'Content-Type':'application/json','X-SecAgent-Validation':nonce!}:undefined,body:body?JSON.stringify(body):undefined});if(!r.ok)throw Error(`Workflow API rejected the request (HTTP ${r.status}). Reload the catalog and check the operator configuration. No target request was made.`);try{return parse(await r.json());}catch{throw Error('Workflow API returned an unsupported response. Configuration has not been validated.');}}
 catch(e){if(signal.aborted)throw e;if(e instanceof Error&&e.message.startsWith('Workflow API'))throw e;throw Error('Workflow API unavailable or timed out. Start the offline service on port 8092.');}
}
export const testingApi={
 health:(signal:AbortSignal)=>request('health',v=>{const h=envelope(v);if(h.status!=='ok'||!['offline_configuration_only','controlled_execution_enabled'].includes(String(h.mode))||h.target_network_access!==(h.mode==='controlled_execution_enabled')||typeof h.validation_nonce!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(h.validation_nonce))throw Error('contract');const modes=h.evaluation_modes??['rule_only'];if(!Array.isArray(modes)||modes.length<1||modes.length>2||modes[0]!=='rule_only'||(modes.length===2&&modes[1]!=='hybrid')||(modes.length===2&&h.judge_configuration!=='configured_unverified'))throw Error('contract');return {nonce:h.validation_nonce as string,evaluationModes:modes as EvaluationMode[]};},signal),
 targets:(signal:AbortSignal)=>request('targets',parseTargets,signal),
 validate:(draft:Draft,nonce:string,signal:AbortSignal)=>request('target-drafts/validate',parseValidation,signal,draft,nonce),
};
export function draftFor(t:TargetPreset,model:string,timeout:number):Draft{return {target_id:t.id,profile_revision:t.profile_revision,policy_ref:t.policy_ref,endpoint:t.endpoint,protocol:t.protocol,method:t.method,model,request_mapping:t.request_mapping,response_parser:t.response_parser,timeout_seconds:timeout,credential_alias:t.credential_alias};}
