import { useEffect, useRef, useState, type FormEvent, type ReactNode } from 'react';
import { testingApi, type CapabilityState, type DiscoveryResult, type HttpContractConfig, type ManagedProfile, type OpenApiCandidate, type ProbeResult, type TargetPreset } from './testingApi';
import DiscoveryPanel from './DiscoveryPanel';
import EvidenceSources from './EvidenceSources';
import ApplicationContext from './ApplicationContext';

const defaultHttpConfig: HttpContractConfig = {
  method: 'POST',
  body_template: { input: '{{input}}' },
  headers: {},
  response: { text_path: 'answer' },
};
const UNRESOLVED_PLACEHOLDER_RE = /<REQUIRED:[A-Za-z0-9_.-]+>/;
function hasUnresolvedPlaceholder(value: unknown): boolean {
  if (typeof value === 'string') return UNRESOLVED_PLACEHOLDER_RE.test(value);
  if (Array.isArray(value)) return value.some(hasUnresolvedPlaceholder);
  if (value && typeof value === 'object') {
    return Object.entries(value as Record<string, unknown>).some(
      ([k, v]) => UNRESOLVED_PLACEHOLDER_RE.test(k) || hasUnresolvedPlaceholder(v),
    );
  }
  return false;
}
function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, v]) => v !== undefined)
      .sort(([a], [b]) => a.localeCompare(b));
    return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`).join(',')}}`;
  }
  return JSON.stringify(value);
}
function httpContractSignature(endpoint: string, protocol: string, credAlias?: string | null, httpCfg?: HttpContractConfig | null): string {
  if (protocol !== 'http-json') return JSON.stringify([endpoint, protocol]);
  return JSON.stringify([endpoint, protocol, credAlias ?? '', canonicalJson(httpCfg ?? null)]);
}
function parseCsvValues(raw: string): string[] {
  return raw.split(',').map(s => s.trim()).filter(Boolean);
}
function coerceTypedValue(raw: string, fieldType: string): unknown {
  if (fieldType === 'boolean') return raw === 'true';
  if (fieldType === 'integer') {
    const n = Number.parseInt(raw, 10);
    return Number.isNaN(n) ? raw : n;
  }
  if (fieldType === 'number') {
    const n = Number(raw);
    return Number.isNaN(n) ? raw : n;
  }
  return raw;
}
const CAPABILITY_KEYS: [string, string][] = [
  ['response_behavior', 'Response behavior'],
  ['tool_intent', 'Model-reported tool intent'],
  ['agent_run', 'Agent-mediated run / actions'],
  ['runtime_execution', 'Actual runtime / code execution'],
  ['direct_tool_access', 'Direct tool / MCP access'],
];

const researchBot: ManagedProfile = {
  id:'dvaa-researchbot',name:'DVAA ResearchBot',platform_id:'dvaa',platform_name:'DVAA',
  protocol:'openai-chat',endpoint:'http://127.0.0.1:7015/v1/chat/completions',
  model:'researchbot',timeout_seconds:30,
};
const toolBotLab: ManagedProfile = {id:'dvaa-toolbot-lab',name:'DVAA ToolBot Lab',
 platform_id:'dvaa',platform_name:'DVAA',protocol:'mcp-jsonrpc',
 endpoint:'http://127.0.0.1:17022/mcp',model:'toolbot-lab',timeout_seconds:30};
const empty: ManagedProfile = {...researchBot,id:'',name:'',platform_id:'unknown',platform_name:'Unknown',endpoint:'',model:''};

export type ConnectionState = 'Not checked'|'Checking'|'Connected'|'Connection failed';
export function targetKey(target?:TargetPreset){return target?JSON.stringify([target.id,target.profile_revision,target.policy_ref,target.endpoint,target.default_model]):'';}
export default function TargetManager({enabled,nonce,target,onChanged,onDiscoveryFlowChange,localSingleUser=false,toolbotLabEnabled=false,onConnectionChange,settingsMatch=true,configurationInvalid=false,evidenceEnabled=false,initialConnect=false,existingSelector,existingTargetIds=[],existingProfiles=[]}:{existingTargetIds?:string[];existingProfiles?:TargetPreset[];existingSelector?:ReactNode;initialConnect?:boolean;evidenceEnabled?:boolean;enabled:boolean;nonce:string;target?:TargetPreset;onChanged:(id:string)=>void;onDiscoveryFlowChange?:(active:boolean)=>void;localSingleUser?:boolean;toolbotLabEnabled?:boolean;onConnectionChange?:(key:string,state:ConnectionState)=>void;settingsMatch?:boolean;configurationInvalid?:boolean}){
 const [secret,setSecret]=useState(''),[unlocked,setUnlocked]=useState(false),[busy,setBusy]=useState(false);
 const [mode,setMode]=useState<'create'|'edit'|null>(null),[form,setForm]=useState<ManagedProfile>(empty);
 const [bodyJson,setBodyJson]=useState<string>(JSON.stringify(defaultHttpConfig.body_template,null,2));
 const [bodyJsonError,setBodyJsonError]=useState<string>('');
 const [selectedCandidate,setSelectedCandidate]=useState<OpenApiCandidate|null>(null);
 const [guidedFieldValues,setGuidedFieldValues]=useState<Record<string,string>>({});
 const [expected,setExpected]=useState<string|null>(null),[checked,setChecked]=useState(false);
 const [confirmed,setConfirmed]=useState(false),[message,setMessage]=useState(''),[error,setError]=useState('');
 const [probe,setProbe]=useState<ProbeResult|null>(null);
 const [discovering,setDiscovering]=useState(initialConnect),[discoveryId,setDiscoveryId]=useState<string|null>(null);
 const [discoveryResult,setDiscoveryResult]=useState<DiscoveryResult|null>(null);
 const [discoveryEndpoint,setDiscoveryEndpoint]=useState<string|null>(null);
 const [discoveryProtocol,setDiscoveryProtocol]=useState<ManagedProfile['protocol']|null>(null);
 const [quickProbe,setQuickProbe]=useState<ProbeResult|null>(null),[quickConfirmed,setQuickConfirmed]=useState(false);
 const [quickError,setQuickError]=useState(''),[quickSavedProbe,setQuickSavedProbe]=useState(false);
 const [awaitingSelection,setAwaitingSelection]=useState(false);
 const [query,setQuery]=useState('');
 const [deleteCandidate,setDeleteCandidate]=useState<TargetPreset|null>(null);
 const [editingOriginal,setEditingOriginal]=useState<TargetPreset|null>(null),[platformConfirmed,setPlatformConfirmed]=useState(false);
 const carryProbe=useRef<{id:string;revision:string;result:ProbeResult|null}|null>(null);
 const carryMessage=useRef<string>('');
 const [checking,setChecking]=useState(false),[probeFailed,setProbeFailed]=useState(false);
 const [probeKey,setProbeKey]=useState('');
 const identity=targetKey(target),current=useRef(identity+nonce),generation=useRef(0);
 if(current.current!==identity+nonce){current.current=identity+nonce;generation.current++;}
 useEffect(()=>{const carry=carryProbe.current;
  if(carry&&target?.id===carry.id&&target.profile_revision===carry.revision){
   setProbe(carry.result);setProbeKey(identity+nonce);setQuickSavedProbe(true);carryProbe.current=null;
  }else{setProbe(null);setQuickSavedProbe(false);}
  const nextMsg=carryMessage.current;carryMessage.current='';
  setConfirmed(false);setProbeFailed(false);setChecking(false);setBusy(false);setQuickConfirmed(false);setAwaitingSelection(false);setMessage(nextMsg);setError('');
 },[identity,nonce]);
 useEffect(()=>()=>{generation.current++;},[]);
 useEffect(()=>{setConfirmed(false);},[settingsMatch]);
 useEffect(()=>{if(['stale','expired'].includes(target?.connection_verification?.status??''))setProbe(null);},[target?.connection_verification?.status]);
 const ownProbe=probeKey===identity+nonce?probe:null;
 const connection:ConnectionState=!settingsMatch?'Not checked':probeKey===identity+nonce&&checking?'Checking':probeKey===identity+nonce&&probeFailed?'Connection failed':ownProbe?
  ownProbe.connection_status==='succeeded'&&ownProbe.runtime_protocol_compatible===true?'Connected':'Connection failed':
  target?.connection_verification?.status==='compatible'&&target.connection_verification.profile_revision===target.profile_revision?'Connected':'Not checked';
 useEffect(()=>{onConnectionChange?.(identity,connection);},[identity,connection,onConnectionChange]);
 async function unlock(){if(!secret)return;setBusy(true);setError('');try{await testingApi.unlock(secret,nonce);setUnlocked(true);setMessage('Operator access verified for this browser session.');}catch{setError('Operator access was rejected. Check the local operator secret and service configuration.');}finally{setBusy(false);}}
 function resetDiscoveryPreview(){generation.current++;setMode(null);setDiscoveryId(null);setDiscoveryResult(null);setSelectedCandidate(null);setGuidedFieldValues({});setDiscoveryEndpoint(null);setDiscoveryProtocol(null);setChecked(false);setQuickProbe(null);setQuickConfirmed(false);setQuickError('');setMessage('');setError('');}
 function start(which:'create'|'edit',profile:TargetPreset|undefined=target,renameTo?:string){
  if(which==='edit'&&!profile)return;
  generation.current++;setDiscovering(false);onDiscoveryFlowChange?.(false);setMode(which);setDiscoveryId(null);setSelectedCandidate(null);setGuidedFieldValues({});setDiscoveryEndpoint(null);setDiscoveryProtocol(null);setChecked(false);setConfirmed(false);setMessage('');setError('');if(which==='create')setProbe(null);setQuickProbe(null);
  setEditingOriginal(which==='edit'?profile!:null);setPlatformConfirmed(false);
  setExpected(which==='edit'?profile!.profile_revision:null);
  // Preserve legacy server-side credential_alias by omitting it from legacy edit payloads;
  // only http-json managed profiles submit credential_alias explicitly.
  const nextForm:ManagedProfile=which==='edit'?{id:profile!.id,name:renameTo??profile!.name,platform_id:profile!.platform_id??'',
    platform_name:profile!.platform_name??'',endpoint:profile!.endpoint,protocol:profile!.protocol,
    model:profile!.protocol==='http-json'?(profile!.default_model||null):profile!.default_model,
    timeout_seconds:profile!.timeout_default,
    ...(profile!.protocol==='http-json'&&profile!.credential_alias?{credential_alias:profile!.credential_alias}:{}),
    ...(profile!.http_config?{http_config:profile!.http_config}:{}),
    ...(profile!.capability_states?{capability_states:profile!.capability_states}:{})}:empty;
  setForm(nextForm);
  setBodyJson(JSON.stringify((nextForm.http_config??defaultHttpConfig).body_template,null,2));
  setBodyJsonError('');
  if(which==='edit'&&profile!.id!==target?.id)onChanged(profile!.id);
 }
 function change<K extends keyof ManagedProfile>(key:K,v:ManagedProfile[K]){const token=++generation.current;setBusy(false);let updated={...form,[key]:v};
  if(key==='protocol'){
   if(v==='http-json'){
    const hc=form.http_config??defaultHttpConfig;
    updated={...updated,model:form.model||null,http_config:hc};
    setBodyJson(JSON.stringify(hc.body_template,null,2));setBodyJsonError('');
   }else{
    const {http_config:_drop,...rest}=updated;
    updated={...rest,model:form.model??''};
   }
  }
  setForm(updated);setChecked(false);setError('');
  if(key==='platform_id'||key==='platform_name')setPlatformConfirmed(false);
  if(['name','platform_id','platform_name'].includes(key)){if(discoveryId)void validateForSave(updated,token);return;}
  setQuickProbe(null);setQuickConfirmed(false);setQuickError('');}
 function updateHttpConfig(mutator:(prev:HttpContractConfig)=>HttpContractConfig){
  const prev=form.http_config??defaultHttpConfig;
  change('http_config',mutator(prev));
 }
 function updateCapability(capKey:string,state:CapabilityState|''){
  const prev={...(form.capability_states??{})};
  if(!state){delete prev[capKey];}else{prev[capKey]=state;}
  change('capability_states',Object.keys(prev).length?prev:null);
 }
 const discoveryBindingValid=!discoveryId||(form.endpoint===discoveryEndpoint&&form.protocol===discoveryProtocol);
 const formSig=httpContractSignature(form.endpoint,form.protocol,form.credential_alias,form.http_config);
 const existingEndpoint=mode==='create'?existingProfiles.find(item=>httpContractSignature(item.endpoint,item.protocol,item.credential_alias,item.http_config)===formSig):undefined;
 const hasUnresolvedFields=form.protocol==='http-json'&&hasUnresolvedPlaceholder(form.http_config?.body_template);
 const authSchemeUnsupported=form.protocol==='http-json'&&!!discoveryId&&selectedCandidate?.requires_auth===true&&selectedCandidate?.auth_scheme_supported===false;
 const missingDiscoveredAuth=form.protocol==='http-json'&&!!discoveryId&&selectedCandidate?.requires_auth===true&&!authSchemeUnsupported&&!form.credential_alias;
 const discoveryAuthBlocked=authSchemeUnsupported||missingDiscoveredAuth;
 const platformChanged=mode==='edit'&&!!editingOriginal&&(editingOriginal.platform_id!==form.platform_id||editingOriginal.platform_name!==form.platform_name);
 const discoveredPlatformChanged=mode==='create'&&!!discoveryId&&!!discoveryResult?.proposed_profile&&
  (discoveryResult.proposed_profile.platform_id!==form.platform_id||discoveryResult.proposed_profile.platform_name!==form.platform_name);
 const platformNeedsConfirmation=platformChanged||discoveredPlatformChanged;
 const knownPlatforms=Array.from(new Map(existingProfiles.filter(item=>item.platform_id&&item.platform_name)
  .map(item=>[item.platform_id!,item.platform_name!])).entries());
 function choosePlatform(id:string){const value=id==='unknown'?['unknown','Unknown']:
  knownPlatforms.find(([key])=>key===id)??[form.platform_id,form.platform_name];
  const updated={...form,platform_id:value[0],platform_name:value[1]};setForm(updated);setChecked(false);setPlatformConfirmed(false);
  if(discoveryId){const token=++generation.current;void validateForSave(updated,token);}
 }
 const matchingProfiles=existingProfiles.filter(item=>`${item.name} ${item.endpoint} ${item.platform_name??''}`.toLowerCase().includes(query.trim().toLowerCase()));
 const platformGroups=Array.from(new Map(matchingProfiles.map(item=>[item.platform_id??'unknown',item.platform_name??'Unknown platform'])).entries());
 async function deleteTargetPermanently(){if(!deleteCandidate||busy)return;
  const candidate=deleteCandidate;
  const token=++generation.current;setBusy(true);setError('');
  try{await testingApi.deleteTarget({target_id:candidate.id,profile_revision:candidate.profile_revision},secret,nonce);
   if(token!==generation.current)return;
   setDeleteCandidate(null);
   const msg=`Target "${candidate.name}" (${candidate.id}) and its associated target data were permanently deleted.`;
   carryMessage.current=msg;
   setMessage(msg);
   onChanged(candidate.id===target?.id?'':target?.id??'');
  }catch(e){if(token===generation.current)setError(e instanceof Error?e.message:'Delete rejected. Check if a scan is currently running and reload targets.');}
  finally{if(token===generation.current)setBusy(false);}
 }
 function probeError(e:unknown){return e instanceof Error&&e.message.startsWith('Workflow API')?e.message:
  'Connection could not be verified. Check the endpoint and retry the benign probe.';}
 async function validateForSave(profile:ManagedProfile,token:number){
  if(existingTargetIds.includes(profile.id)){
   setError('Target identifier already exists. Select the existing target, or change Target identifier under Advanced target fields before saving a new profile.');
   return;
  }
  const sig=httpContractSignature(profile.endpoint,profile.protocol,profile.credential_alias,profile.http_config);
  if(existingProfiles.some(item=>profile.protocol==='http-json'?httpContractSignature(item.endpoint,item.protocol,item.credential_alias,item.http_config)===sig:item.endpoint===profile.endpoint&&item.protocol===profile.protocol&&item.default_model===profile.model)){
   setError(profile.protocol==='http-json'?'This target invocation contract is already saved. Select the existing target or customize its request contract.':'This endpoint, protocol and model are already saved. Select the existing target instead of creating a duplicate.');return;
  }
  if(profile.protocol==='http-json'&&hasUnresolvedPlaceholder(profile.http_config?.body_template)){
   setChecked(false);
   setError('Resolve all required discovery parameters before validating or saving.');
   return;
  }
  if(profile.protocol==='http-json'&&discoveryId&&selectedCandidate?.requires_auth===true){
   if(selectedCandidate.auth_scheme_supported===false){
    setChecked(false);
    setError('Discovered operation requires an authentication scheme not supported by server-managed Bearer credential aliases.');
    return;
   }
   if(!profile.credential_alias){
    setChecked(false);
    setError('Discovered operation requires authentication. Select a registered server-managed credential alias before validating or saving.');
    return;
   }
  }
  try{await (discoveryId&&profile.protocol==='http-json'?testingApi.validateManaged(profile,null,secret,nonce,discoveryId):testingApi.validateManaged(profile,null,secret,nonce));
   if(token===generation.current)setChecked(true);
  }catch(e){if(token===generation.current)setError(probeError(e));}
 }
 async function acceptDiscovery(profile:ManagedProfile,id:string,result:DiscoveryResult,candidate?:OpenApiCandidate){
  const token=generation.current;
  setMode('create');setForm(profile);setExpected(null);setChecked(false);setDiscoveryId(id);setDiscoveryResult(result);
  setSelectedCandidate(candidate??null);
  setGuidedFieldValues({});
  setDiscoveryEndpoint(profile.endpoint);setDiscoveryProtocol(profile.protocol);
  setBodyJson(JSON.stringify((profile.http_config??defaultHttpConfig).body_template,null,2));
  setBodyJsonError('');
  setQuickProbe(null);setQuickConfirmed(false);setQuickError('');setError('');
  if(profile.protocol==='http-json'){
   const authPending=candidate?.requires_auth===true&&(candidate.auth_scheme_supported===false||!profile.credential_alias);
   if(!hasUnresolvedPlaceholder(profile.http_config?.body_template)&&!authPending){
    await validateForSave(profile,token);
   }
   return;
  }
  if(!profile.model)return;
  setBusy(true);
  try{
   const result=await testingApi.probeDiscovery(profile,id,secret,nonce);
   if(token===generation.current)setQuickProbe(result);
  }catch(e){if(token===generation.current)setQuickError(probeError(e));}
  if(token===generation.current)await validateForSave(profile,token);
  if(token===generation.current)setBusy(false);
 }
 async function validate(){const token=generation.current;setBusy(true);setError('');setMessage('');try{await (discoveryId&&form.protocol==='http-json'?testingApi.validateManaged(form,expected,secret,nonce,discoveryId):testingApi.validateManaged(form,expected,secret,nonce));if(token!==generation.current)return;setChecked(true);setMessage('Target details are valid. Save to create an unreviewed profile.');}catch(e){if(token!==generation.current)return;setChecked(false);setError(e instanceof Error&&e.message.startsWith('Workflow API')?e.message:'Target details are invalid or stale. Check the identifier, endpoint, model, timeout and current revision.');}finally{if(token===generation.current)setBusy(false);}}
 async function probeQuick(){if(!discoveryId||!discoveryBindingValid||!quickConfirmed||busy||!form.model||!enabled||!(localSingleUser||unlocked))return;
  const token=generation.current;setBusy(true);setQuickProbe(null);setQuickError('');setChecked(false);
  try{const result=await testingApi.probeDiscovery(form,discoveryId,secret,nonce);
   if(token!==generation.current)return;
   setQuickProbe(result);setQuickConfirmed(false);
  }catch(e){if(token===generation.current){setQuickError(probeError(e));setQuickConfirmed(false);}}
  if(token===generation.current)await validateForSave(form,token);
  if(token===generation.current)setBusy(false);
 }
 async function save(e:FormEvent){e.preventDefault();if(!checked||busy||!discoveryBindingValid)return;const token=generation.current;setBusy(true);setError('');try{const wasDiscovered=!!discoveryId;
  const row=await (discoveryId?testingApi.saveManaged(form,expected,secret,nonce,discoveryId,!!discoveredPlatformChanged&&platformConfirmed):
   platformChanged?testingApi.saveManaged(form,expected,secret,nonce,undefined,platformConfirmed):
   testingApi.saveManaged(form,expected,secret,nonce));
  if(token!==generation.current)return;
  if(wasDiscovered&&row.id===form.id&&row.endpoint===form.endpoint&&row.protocol===form.protocol&&
     row.default_model===form.model&&row.timeout_default===form.timeout_seconds)
   carryProbe.current={id:row.id,revision:row.profile_revision,result:quickProbe};
  setAwaitingSelection(!(mode==='edit'&&row.profile_revision===target?.profile_revision));setMode(null);setDiscovering(false);setDiscoveryId(null);setDiscoveryProtocol(null);setChecked(false);
  setMessage('Target saved without review or security execution permission. Review this exact profile before testcase selection.');onDiscoveryFlowChange?.(false);onChanged(row.id);
 }catch{if(token===generation.current)setError('Configuration could not be saved. Reload the catalog and check the profile.');}finally{if(token===generation.current)setBusy(false);}}
 async function review(){if(!target||!confirmed||busy)return;const token=generation.current;setBusy(true);setError('');try{const row=await testingApi.reviewManaged(target,secret,nonce);if(token!==generation.current)return;setConfirmed(false);setMessage('Review saved for this exact profile revision and policy. A separate execution grant is still required.');onChanged(row.id);}catch{if(token!==generation.current)return;setError('Review was rejected. Reload the target and confirm its current endpoint and policy.');}finally{if(token===generation.current)setBusy(false);}}
 const probeAvailable=!!target&&['supported','requires_confirmation'].includes(target.connection_probe.status);
 const probeConfirmationRequired=probeAvailable;
 async function testConnection(){if(!target||!probeAvailable||!enabled||!(localSingleUser||unlocked)||!settingsMatch||configurationInvalid||busy||!confirmed)return;
  const first=target.connection_probe.status==='requires_confirmation',token=generation.current;
  setProbeKey(identity+nonce);setBusy(true);setChecking(true);setError('');setProbe(null);setProbeFailed(false);
  try{const result=await testingApi.probe(target,secret,nonce,first);
   if(token!==generation.current)return;
   setProbe(result);setConfirmed(false);onChanged(target.id);
  }catch{if(token===generation.current){setProbeFailed(true);setConfirmed(false);setError('Connection check failed. Check the endpoint and try again.');}}
  finally{if(token===generation.current){setBusy(false);setChecking(false);}}
 }
  const webLabReview=localSingleUser&&(target?.id==='dvaa-researchbot-web-lab'||target?.id==='dvaa-toolbot-lab');
 return <div className="target-management" aria-label="Target management">
  {!enabled&&existingSelector}
  {enabled&&(!(localSingleUser||unlocked)?<div className="target-unlock"><label>Operator secret <input type="password" autoComplete="off" value={secret} onChange={e=>setSecret(e.target.value)}/></label> <button disabled={!secret||!nonce||busy} onClick={unlock}>Unlock target management</button><p className="caption">Local operator access. The secret is not saved.</p></div>:<>
   <div className="target-journeys" role="group" aria-label="Choose target setup"><button className={discovering?'is-active':''} aria-pressed={discovering} onClick={()=>{if(!discovering){resetDiscoveryPreview();setDiscovering(true);onDiscoveryFlowChange?.(true);}}} disabled={busy}>Connect new target</button><button className={!discovering?'is-active':''} aria-pressed={!discovering} onClick={()=>{if(discovering){setDiscovering(false);resetDiscoveryPreview();onDiscoveryFlowChange?.(false);}}} disabled={busy}>Select existing target</button></div>
   {discovering&&<DiscoveryPanel nonce={nonce} secret={secret} onReset={resetDiscoveryPreview} onUse={acceptDiscovery}/>}
   {!discovering&&<section className="target-list" aria-label="Existing targets"><div className="target-list-head"><div><h2>Existing targets</h2><p className="caption">Select a target directly. Platform is an association, separate from protocol and Target ID.</p></div><button type="button" onClick={()=>start('create')} disabled={busy}>Add Target</button></div>
    <label className="target-search">Search targets<input type="search" value={query} onChange={e=>setQuery(e.target.value)} placeholder="Name, platform or endpoint"/></label>
    {matchingProfiles.length===0?<p className="target-empty">{existingProfiles.length?'No targets match this search.':'No active targets. Connect a target.'}</p>:platformGroups.map(([id,name])=><div className="target-platform-group" key={id}><h3>{name}</h3><div className="target-list-rows">{matchingProfiles.filter(item=>(item.platform_id??'unknown')===id).map(item=>{const active=item.id===target?.id;const itemConnection=active?connection:item.connection_verification?.status==='compatible'?'Connected':'Not checked';return <div className={`target-list-row ${active?'is-selected':''}`} key={item.id}>
     <button type="button" className="target-list-select" aria-current={active?'true':undefined} onClick={()=>onChanged(item.id)}><strong>{item.name}</strong><span>{item.endpoint}</span><small>{item.protocol==='mcp-jsonrpc'?'MCP':item.protocol==='http-json'?'HTTP JSON':'HTTP chat'} · ID: <code>{item.id}</code> · {item.platform_provenance?.replaceAll('_',' ')??'platform source unknown'}</small></button>
     <div className="target-row-status"><span>{itemConnection}</span><span>{item.authorization_status==='reviewed_for_offline_configuration'?'Reviewed':'Review required'}</span></div>
     <div className="target-row-actions"><button type="button" onClick={()=>start('edit',item)} disabled={busy}>Edit</button><button type="button" className="danger-button" onClick={()=>{setError('');setDeleteCandidate(item);}} disabled={busy}>Delete</button></div>
    </div>;})}</div></div>)}
    {existingProfiles.length===0&&target&&<button type="button" onClick={()=>start('edit')} disabled={busy}>Edit Target</button>}
   </section>}
   {!discovering&&!localSingleUser&&<button type="button" onClick={()=>{generation.current++;setUnlocked(false);setSecret('');setMode(null);setProbe(null);setConfirmed(false);setDiscovering(false);onDiscoveryFlowChange?.(false);}}>Lock</button>}
   {deleteCandidate&&<div className="target-delete-overlay" role="dialog" aria-modal="true" aria-label="Confirm permanent target deletion"><div className="target-delete-dialog">
    <h2>Permanently delete target?</h2>
    <p className="notice error" role="alert"><strong>Warning: This action is permanent and cannot be undone.</strong></p>
    <ul>
     <li><strong>Target Name:</strong> {deleteCandidate.name}</li>
     <li><strong>Target ID:</strong> <code>{deleteCandidate.id}</code></li>
     <li><strong>Endpoint:</strong> <code>{deleteCandidate.endpoint}</code></li>
    </ul>
    <p><strong>The following target-specific records will be permanently purged:</strong></p>
    <ul>
     <li>Target Profile and endpoint/model/protocol configuration</li>
     <li>Application Context / Application Details and security boundaries</li>
     <li>Discovery and connection metadata associated with this Target</li>
     <li>Evidence Source configurations and captures for this Target</li>
     <li>Target-specific security policies, contracts, and MCP bindings</li>
     <li>Scan history, execution results, evidence, and reports bound to this Target</li>
    </ul>
    <p className="caption">Shared testcase datasets, canonical rubrics, and other Targets will not be affected.</p>
    <div className="target-form-actions">
     <button type="button" disabled={busy} onClick={()=>setDeleteCandidate(null)}>Cancel</button>
     <button type="button" className="danger-button" disabled={busy} onClick={()=>void deleteTargetPermanently()}>{busy?'Deleting...':'Delete Permanently'}</button>
    </div>
   </div></div>}
   {mode&&<form className="target-form" onSubmit={save} aria-label="Manage target details">
    <h3>{discoveryId?'Auto-detected Configuration':mode==='create'?'Add target':'Edit target'}</h3>
   {discoveryId&&discoveryResult&&<p className="target-detected-count">{discoveryResult.advertised_tools.length} advertised tools · {discoveryResult.possible_contracts.length} candidate API contracts. Metadata does not verify tool execution.</p>}
    {mode==='create'&&!discoveryId&&!discovering&&<button type="button" onClick={()=>{setForm(researchBot);setChecked(false);}}>Use DVAA ResearchBot example</button>}
    {mode==='create'&&!discoveryId&&!discovering&&toolbotLabEnabled&&<button type="button" onClick={()=>{setForm(toolBotLab);setChecked(false);}}>Use offline ToolBot Lab example</button>}
    <label>Platform association <span className="field-optional">Operator declared</span><select value={knownPlatforms.some(([id])=>id===form.platform_id)||form.platform_id==='unknown'?form.platform_id:'custom'} onChange={e=>choosePlatform(e.target.value)}><option value="unknown">Unknown / Local Agent</option>{knownPlatforms.filter(([id])=>id!=='unknown').map(([id,name])=><option key={id} value={id}>{name}</option>)}<option value="custom">Custom platform</option></select></label>
    {discoveryId?<details><summary>Advanced target fields</summary>
     <label>Platform identifier<input value={form.platform_id} required maxLength={128} onChange={e=>change('platform_id',e.target.value)}/></label>
     <label>Platform name<input value={form.platform_name} required maxLength={80} onChange={e=>change('platform_name',e.target.value)}/></label>
     <label>Target identifier<input value={form.id} required maxLength={128} onChange={e=>change('id',e.target.value)}/></label>
     <label>Timeout (seconds)<input type="number" min="1" max="60" step="1" required value={Number.isNaN(form.timeout_seconds)?'':form.timeout_seconds} onChange={e=>change('timeout_seconds',e.target.valueAsNumber)}/></label>
    </details>:<>
     <label>Platform identifier<input autoFocus value={form.platform_id} required maxLength={128} onChange={e=>change('platform_id',e.target.value)}/></label>
     <label>Platform name<input value={form.platform_name} required maxLength={80} onChange={e=>change('platform_name',e.target.value)}/></label>
     <label>Target identifier<input value={form.id} required maxLength={128} readOnly={mode==='edit'} onChange={e=>change('id',e.target.value)}/></label>
    </>}
    <label>{discoveryId?'Agent Name (from connection step)':'Target display name'}<input value={form.name} required maxLength={100} pattern="[A-Za-z0-9 ._-]+" onChange={e=>change('name',e.target.value)}/></label>
    {existingEndpoint&&<p role="status">Existing target: <strong>{existingEndpoint.name}</strong>. <button type="button" onClick={()=>{setDiscovering(false);setMode(null);onDiscoveryFlowChange?.(false);onChanged(existingEndpoint.id);}}>Use {existingEndpoint.name}</button> <button type="button" onClick={()=>start('edit',existingEndpoint,form.name.trim()||existingEndpoint.name)}>Rename Existing</button></p>}
    <label>Protocol<select value={form.protocol} onChange={e=>change('protocol',e.target.value as ManagedProfile['protocol'])}><option value="openai-chat">HTTP / OpenAI-compatible chat</option><option value="http-json">HTTP / Custom REST JSON</option><option value="mcp-jsonrpc">MCP JSON-RPC</option></select></label>
    <label>Endpoint URL<input type="url" value={form.endpoint} required maxLength={256} onChange={e=>change('endpoint',e.target.value)}/></label>
    {form.protocol!=='http-json'&&<label>{form.protocol==='mcp-jsonrpc'?'MCP service identifier (not an LLM model)':'Model identifier'}<input value={form.model??''} required maxLength={128} onChange={e=>change('model',e.target.value)}/></label>}
    {form.protocol!=='http-json'&&mode==='edit'&&editingOriginal?.credential_alias&&<p className="caption">Server-managed credential alias: <code>{editingOriginal.credential_alias}</code> (preserved automatically on save).</p>}
    {form.protocol==='http-json'&&<fieldset className="target-http-contract"><legend>HTTP JSON Contract (uses shared generic_http adapter)</legend>
     {selectedCandidate&&!!selectedCandidate.unresolved_required_field_specs?.length&&<div className="notice" role="region" aria-label="Resolve required discovery parameters">
      <strong>Resolve required request parameters</strong>
      <p className="caption">Fill each required field discovered from the API schema. Values preserve JSON types and update the request template below.</p>
      {selectedCandidate.unresolved_required_field_specs.map(spec=><label key={spec.name}>Required parameter <code>{spec.name}</code> ({spec.type})
       {spec.enum?.length?<select value={guidedFieldValues[spec.name]??''} onChange={e=>{const raw=e.target.value;setGuidedFieldValues(prev=>({...prev,[spec.name]:raw}));if(!raw)return;const typed=coerceTypedValue(raw,spec.type);const nextBody={...(form.http_config??defaultHttpConfig).body_template,[spec.name]:typed};setBodyJson(JSON.stringify(nextBody,null,2));setBodyJsonError('');updateHttpConfig(prev=>({...prev,body_template:nextBody}));}}><option value="">Select value</option>{spec.enum.map(v=><option key={String(v)} value={String(v)}>{String(v)}</option>)}</select>:
        spec.type==='boolean'?<select value={guidedFieldValues[spec.name]??''} onChange={e=>{const raw=e.target.value;setGuidedFieldValues(prev=>({...prev,[spec.name]:raw}));if(!raw)return;const nextBody={...(form.http_config??defaultHttpConfig).body_template,[spec.name]:raw==='true'};setBodyJson(JSON.stringify(nextBody,null,2));setBodyJsonError('');updateHttpConfig(prev=>({...prev,body_template:nextBody}));}}><option value="">Select true/false</option><option value="true">true</option><option value="false">false</option></select>:
        <input value={guidedFieldValues[spec.name]??''} placeholder={`Enter ${spec.name} (${spec.type})`} onChange={e=>{const raw=e.target.value;setGuidedFieldValues(prev=>({...prev,[spec.name]:raw}));const nextVal=raw===''?`<REQUIRED:${spec.name}>`:coerceTypedValue(raw,spec.type);const nextBody={...(form.http_config??defaultHttpConfig).body_template,[spec.name]:nextVal};setBodyJson(JSON.stringify(nextBody,null,2));setBodyJsonError('');updateHttpConfig(prev=>({...prev,body_template:nextBody}));}}/>}
      </label>)}
     </div>}
     {authSchemeUnsupported&&<p role="alert">Discovered operation requires an authentication scheme ({selectedCandidate?.auth_schemes?.join(', ')||'unsupported'}) not supported by server-managed Bearer credential aliases. This endpoint cannot be validated or saved as a Bearer http-json target.</p>}
     {missingDiscoveredAuth&&<p role="alert">API specification requires authentication. Enter a registered server-managed credential alias below before validating or saving. Configuring an alias checks server registration only and does not prove runtime credential validity.</p>}
     {hasUnresolvedFields&&<p role="alert">Unresolved required discovery placeholders remain in the request template. Fill them before validating or saving.</p>}
     <label>Request JSON body template (must include <code>{'{{input}}'}</code>)<textarea rows={5} value={bodyJson} onChange={e=>{const raw=e.target.value;setBodyJson(raw);try{const parsed=JSON.parse(raw);if(!parsed||typeof parsed!=='object'||Array.isArray(parsed))throw Error('Must be a JSON object.');setBodyJsonError('');updateHttpConfig(prev=>({...prev,body_template:parsed as Record<string,unknown>}));}catch(err){setBodyJsonError(err instanceof Error?err.message:'Invalid JSON object.');setChecked(false);}}}/></label>
     {bodyJsonError&&<p role="alert">{bodyJsonError}</p>}
     <label>Response text path<input required maxLength={128} value={(form.http_config??defaultHttpConfig).response.text_path} onChange={e=>updateHttpConfig(prev=>({...prev,response:{...prev.response,text_path:e.target.value}}))} placeholder="answer"/></label>
     <details className="target-advanced" open={!!selectedCandidate?.requires_auth}><summary>Optional status, correlation, authentication &amp; inline evidence mapping</summary>
      <label>Credential alias (server-managed env ref)<input maxLength={128} value={form.credential_alias??''} onChange={e=>change('credential_alias',e.target.value.trim()||null)} placeholder="Optional registered alias"/></label>
      <label>Model identifier (optional)<input maxLength={128} value={form.model??''} onChange={e=>change('model',e.target.value.trim()||null)} placeholder="Leave empty if unspecified"/></label>
      <label>Target correlation ID path<input maxLength={128} value={(form.http_config??defaultHttpConfig).response.correlation_id_path??''} onChange={e=>updateHttpConfig(prev=>({...prev,response:{...prev.response,correlation_id_path:e.target.value.trim()||null}}))} placeholder="e.g. run_id"/></label>
      <label>Response status path<input maxLength={128} value={(form.http_config??defaultHttpConfig).response.status_path??''} onChange={e=>updateHttpConfig(prev=>({...prev,response:{...prev.response,status_path:e.target.value.trim()||null}}))} placeholder="e.g. status"/></label>
      <label>Complete status values (comma-separated)<input maxLength={256} value={((form.http_config??defaultHttpConfig).response.complete_status_values??[]).join(', ')} onChange={e=>updateHttpConfig(prev=>({...prev,response:{...prev.response,complete_status_values:parseCsvValues(e.target.value)}}))} placeholder="e.g. completed, DONE"/></label>
      <label>Incomplete status values (comma-separated)<input maxLength={256} value={((form.http_config??defaultHttpConfig).response.incomplete_status_values??[]).join(', ')} onChange={e=>updateHttpConfig(prev=>({...prev,response:{...prev.response,incomplete_status_values:parseCsvValues(e.target.value)}}))} placeholder="e.g. awaiting_approval, failed"/></label>
      <label>Inline evidence items path<input maxLength={128} value={(form.http_config??defaultHttpConfig).response.evidence_mapping?.items??''} onChange={e=>{const v=e.target.value.trim();updateHttpConfig(prev=>({...prev,response:{...prev.response,evidence_mapping:v?{...(prev.response.evidence_mapping??{items:v}),items:v}:null}}));}} placeholder="e.g. steps or events"/></label>
      {(form.http_config??defaultHttpConfig).response.evidence_mapping&&<>
       <label>Inline action/tool field<input maxLength={128} value={(form.http_config??defaultHttpConfig).response.evidence_mapping?.action??''} onChange={e=>updateHttpConfig(prev=>({...prev,response:{...prev.response,evidence_mapping:{...(prev.response.evidence_mapping??{items:''}),action:e.target.value.trim()||null}}}))} placeholder="e.g. action or operation"/></label>
       <label>Inline arguments field<input maxLength={128} value={(form.http_config??defaultHttpConfig).response.evidence_mapping?.arguments??''} onChange={e=>updateHttpConfig(prev=>({...prev,response:{...prev.response,evidence_mapping:{...(prev.response.evidence_mapping??{items:''}),arguments:e.target.value.trim()||null}}}))} placeholder="e.g. action_input or parameters"/></label>
       <label>Inline decision field<input maxLength={128} value={(form.http_config??defaultHttpConfig).response.evidence_mapping?.decision??''} onChange={e=>updateHttpConfig(prev=>({...prev,response:{...prev.response,evidence_mapping:{...(prev.response.evidence_mapping??{items:''}),decision:e.target.value.trim()||null}}}))} placeholder="e.g. decision"/></label>
       <label>Inline observation/result field<input maxLength={128} value={(form.http_config??defaultHttpConfig).response.evidence_mapping?.observation??''} onChange={e=>updateHttpConfig(prev=>({...prev,response:{...prev.response,evidence_mapping:{...(prev.response.evidence_mapping??{items:''}),observation:e.target.value.trim()||null}}}))} placeholder="e.g. observation or result"/></label>
      </>}
     </details>
    </fieldset>}
    <details className="target-advanced"><summary>Target Capability States (optional)</summary>
     <p className="caption">Declare known capabilities per Target profile. Explicitly unsupported execution capabilities block incompatible execution-scoped tests without silent scope downgrade.</p>
     {CAPABILITY_KEYS.map(([capKey,capLabel])=><label key={capKey}>{capLabel}<select value={form.capability_states?.[capKey]??''} onChange={e=>updateCapability(capKey,e.target.value as CapabilityState|'')}><option value="">Default / Unverified</option><option value="supported">Supported</option><option value="unsupported">Unsupported</option><option value="unverified">Unverified</option></select></label>)}
    </details>
    {discoveryId&&form.protocol==='openai-chat'&&!form.model&&<p role="note">Model not advertised. Enter the model identifier supplied by the target operator before testing the connection.</p>}
    {!discoveryId&&<label>Timeout (seconds)<input type="number" min="1" max="60" step="1" required value={Number.isNaN(form.timeout_seconds)?'':form.timeout_seconds} onChange={e=>change('timeout_seconds',e.target.valueAsNumber)}/></label>}
    <p className="target-adapter">Adapter: <strong>{form.protocol==='mcp-jsonrpc'?'generic_mcp_jsonrpc':'generic_http'}</strong>. {form.protocol==='mcp-jsonrpc'?'The service identifier is internal; tools/list never invokes a tool.':form.protocol==='http-json'?'Custom HTTP JSON executes through the shared generic_http adapter; inline evidence remains target-reported.':'Metadata alone does not verify chat behavior.'}</p>
    {platformNeedsConfirmation&&<label className="target-consent"><input type="checkbox" checked={platformConfirmed} onChange={e=>setPlatformConfirmed(e.target.checked)}/><span>I confirm this operator-declared platform association. Target ID and connection binding remain unchanged.</span></label>}
    {discoveryId&&<div className="quick-connect" aria-label="Discovered target connection">
     <p>Testing endpoint: <code>{form.endpoint}</code> ({form.protocol}).</p>
     {!discoveryBindingValid&&<p role="alert">Endpoint or protocol changed. Enter the new URL above and run Discover again before testing or saving.</p>}
     {(!quickProbe||quickProbe.connection_status!=='succeeded'||quickProbe.runtime_protocol_compatible!==true)&&<><label className="target-consent"><input type="checkbox" checked={quickConfirmed} onChange={e=>setQuickConfirmed(e.target.checked)}/><span>I authorize one benign connection probe to this exact endpoint.</span></label>
     <button className="primary" type="button" disabled={busy||!quickConfirmed||!form.model||!discoveryBindingValid} onClick={probeQuick}>{busy?'Checking...':'Test Connection'}</button></>}
     <p className={`connection-feedback ${quickProbe?.connection_status==='succeeded'&&quickProbe.runtime_protocol_compatible===true?'is-connected':quickProbe||quickError?'is-failed':''}`} role="status">{busy?'Checking':quickProbe?.connection_status==='succeeded'&&quickProbe.runtime_protocol_compatible===true?'Connected':quickProbe||quickError?'Failed':'Unverified'}: {quickProbe?quickProbe.reason.replaceAll('_',' '):quickError||(!form.model?'Enter a model identifier to run the connection check.':'No connection probe has been sent.')}</p>
    </div>}
    {quickError&&<p role="alert">{quickError}</p>}
    {!discoveryId&&<button type="button" disabled={busy||!!bodyJsonError||hasUnresolvedFields||discoveryAuthBlocked} onClick={validate}>Validate Target Details</button>}
    {discoveryId&&form.protocol==='http-json'&&<button type="button" disabled={busy||!!bodyJsonError||hasUnresolvedFields||discoveryAuthBlocked} onClick={validate}>Validate Draft Details</button>}
    <div className="target-form-actions"><button className="primary target-save" type="submit" disabled={busy||!checked||!!bodyJsonError||hasUnresolvedFields||discoveryAuthBlocked||!discoveryBindingValid||!!existingEndpoint||!!platformNeedsConfirmation&&!platformConfirmed}>{discoveryId?'Save Target':'Save Configuration'}</button>
    <button type="button" disabled={busy} onClick={()=>{generation.current++;setMode(null);setDiscovering(false);onDiscoveryFlowChange?.(false);}}>Cancel</button></div>
   </form>}
  </>)}
  {target&&!mode&&!discovering&&!awaitingSelection&&<div className="target-summary" aria-label="Selected target">
   <div className="target-summary-heading"><div><h2>{target.name}</h2><p className="caption">{target.protocol==='openai-chat'?'OpenAI-compatible HTTP':target.protocol==='http-json'?'HTTP JSON (generic_http)':'MCP JSON-RPC'}</p></div>
    <span className="target-pill">{target.authorization_status==='review_required'?'Review required':'Reviewed'}</span></div>
   <div className="target-endpoint"><span title={target.endpoint}>{new URL(target.endpoint).host}</span><span>Model / Agent: <strong>{target.default_model||'Not specified'}</strong></span></div>
   <div className="target-connect">
    <div role="status"><strong className={`target-connection ${connection==='Connected'?'is-connected':connection==='Connection failed'?'is-failed':''}`}>{connection}</strong>
     <p className="caption">{connection==='Connected'?'Target responded successfully.':connection==='Checking'?'Sending one authorized benign request.':connection==='Connection failed'?'Unable to confirm a compatible response.':!settingsMatch?'Save changed settings with Edit Target before probing.':target.connection_verification?.status==='expired'||target.connection_verification?.status==='stale'?'Previous connection check expired. Test again.':'Connection not checked.'}</p></div>
    {enabled&&(localSingleUser||unlocked)&&<div className="target-connect-actions">
     {target.authorization_status==='review_required'&&(!localSingleUser||!probeAvailable||webLabReview||quickSavedProbe)?<>
      <label className="target-consent"><input type="checkbox" checked={confirmed} onChange={e=>setConfirmed(e.target.checked)}/> I confirm authorization to test {target.endpoint}</label>
      <button disabled={!confirmed||busy} onClick={review}>{localSingleUser?'Authorize target for test selection':'Review / Approve Target'}</button>
      <p className="caption">Review this exact profile. No request is sent. Security payloads require a separate execution grant.</p>
     </>:null}
     {(connection!=='Connected'||(quickSavedProbe&&target.connection_verification!==undefined&&target.connection_verification.status!=='compatible'))&&((!quickSavedProbe&&(!webLabReview||target.authorization_status==='reviewed_for_offline_configuration'&&probeAvailable))||
       (quickSavedProbe&&target.authorization_status==='reviewed_for_offline_configuration'))&&<>
      {probeConfirmationRequired&&<label className="target-consent"><input type="checkbox" checked={confirmed} disabled={checking||!settingsMatch||configurationInvalid} onChange={e=>setConfirmed(e.target.checked)}/> I confirm authorization for one benign probe to {new URL(target.endpoint).host}</label>}
      <button className="primary" disabled={busy||!nonce||!probeAvailable||!confirmed||!settingsMatch||configurationInvalid} onClick={testConnection}>{checking?'Checking...':connection==='Connection failed'?'Retry':'Test Connection'}</button>
     </>}
    </div>}
    {(!enabled||!(localSingleUser||unlocked))&&<button disabled>Test Connection</button>}
   </div>
   {!probeAvailable&&<p className="caption">{target.authorization_status==='review_required'?'Review this profile before connecting.':'A safe connection probe is not supported for this profile.'}</p>}
   {!enabled&&<p className="caption">Target management is unavailable in this service.</p>}
   {(probe||probeFailed)&&<details className="target-probe-details"><summary>Connection details</summary><p>{probe?`Reason: ${probe.reason.replaceAll('_',' ')}. HTTP status: ${probe.http_status??'unavailable'}. API compatibility: ${probe.runtime_protocol_compatible===null?'unknown':probe.runtime_protocol_compatible?'yes':'no'}. Requests: ${probe.target_request_count}.`:'No connection proof was obtained.'}</p></details>}
  </div>}
  {message&&<p role="status">{message}</p>}{error&&<p role="alert">{error}</p>}
  {target&&!discovering&&!awaitingSelection&&enabled&&(localSingleUser||unlocked)&&<details className="target-advanced target-context-drawer"><summary>Application Context · Optional</summary><ApplicationContext key={identity+nonce} target={target} nonce={nonce} secret={secret} discovery={discoveryResult}/></details>}
  {target&&evidenceEnabled&&!discovering&&!awaitingSelection&&<details className="target-advanced target-evidence-drawer"><summary>Evidence Sources · Optional</summary><EvidenceSources key={identity+nonce} target={target} nonce={nonce} secret={secret} authorized={enabled&&(localSingleUser||unlocked)}/></details>}
 </div>;
}
