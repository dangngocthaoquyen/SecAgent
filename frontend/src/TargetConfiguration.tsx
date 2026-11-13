import { useEffect,useRef,useState,type FormEvent } from 'react';
import { testingApi,draftFor,type TargetPreset,type ValidationResult,type EvaluationMode } from './testingApi';
import PlanWizard from './PlanWizard';
import { Facts,value } from './EvidenceViews';
const LEGACY_PLATFORM = '__legacy_platform__';
function platformOf(target:TargetPreset){return target.platform_id??LEGACY_PLATFORM;}
export default function TargetConfiguration(){
 const [catalog,setCatalog]=useState<TargetPreset[]|null>(null),[protocols,setProtocols]=useState<{id:string;state:string}[]>([]),[nonce,setNonce]=useState(''),[platform,setPlatform]=useState(''),[selected,setSelected]=useState(''),[model,setModel]=useState(''),[timeout,setTimeout]=useState(30),[error,setError]=useState(''),[result,setResult]=useState<ValidationResult|null>(null),[busy,setBusy]=useState(false),[revision,setRevision]=useState(0);
 const [planning,setPlanning]=useState(false);
 const [evaluationModes,setEvaluationModes]=useState<EvaluationMode[]>(['rule_only']);
 const pending=useRef<AbortController|null>(null);const target=catalog?.find(t=>t.id===selected);
 const platforms=Array.from(new Map(catalog?.map(t=>[platformOf(t),t.platform_name??'Configured targets'])??[]).entries());
 const available=catalog?.filter(t=>platformOf(t)===platform)??[];
 function invalidate(){setPlanning(false);pending.current?.abort();setBusy(false);setResult(null);setError('');}
 useEffect(()=>{const c=new AbortController();setCatalog(null);setNonce('');setEvaluationModes(['rule_only']);setError('');setResult(null);Promise.all([testingApi.health(c.signal),testingApi.targets(c.signal)]).then(([h,r])=>{if(c.signal.aborted)return;setNonce(h.nonce);setEvaluationModes(h.evaluationModes);setCatalog(r.targets);setProtocols(r.protocols);setPlatform(r.targets[0]?platformOf(r.targets[0]):'');setSelected(r.targets[0]?.id??'');setModel(r.targets[0]?.default_model??'');setTimeout(r.targets[0]?.timeout_default??30);}).catch(e=>{if(!c.signal.aborted)setError(e.message);});return()=>{c.abort();pending.current?.abort();};},[revision]);
 function selectPlatform(id:string){invalidate();const first=catalog?.find(t=>platformOf(t)===id);setPlatform(id);setSelected(first?.id??'');setModel(first?.default_model??'');setTimeout(first?.timeout_default??30);}
 function select(id:string){invalidate();const t=catalog?.find(t=>t.id===id);setSelected(id);setModel(t?.default_model??'');setTimeout(t?.timeout_default??30);}
 async function validate(e:FormEvent){e.preventDefault();if(!target)return;invalidate();const c=new AbortController();pending.current=c;setBusy(true);try{const r=await testingApi.validate(draftFor(target,model,timeout),nonce,c.signal);if(!c.signal.aborted){if(r.target_id!==target.id||r.profile_revision!==target.profile_revision)throw Error('Workflow API returned a different profile. Reload the catalog.');setResult(r);}}catch(e){if(!c.signal.aborted)setError((e as Error).message);}finally{if(!c.signal.aborted)setBusy(false);}}
 const approvalRequired = result?.errors.length === 1 && result.errors[0] === 'operator_review_required';
 const feedback = !result ? 'Configuration not validated' : approvalRequired ? 'Operator approval required' : result.configuration_status === 'valid' ? 'Configuration valid' : 'Configuration invalid';
 return <><div className="detail-page" hidden={planning}>
   <div className="page-title"><div><span className="eyebrow">SECURITY TESTING</span><h1>Target configuration</h1><p>1. Select platform and target / 2. Validate configuration / 3. Connection status</p></div><button onClick={()=>{invalidate();setRevision(n=>n+1);}}>Reload target catalog</button></div>
   {error&&<div className="notice error" role="alert"><strong>Configuration unavailable</strong><p>{error}</p></div>}
   {!catalog&&!error&&<p role="status">Loading target catalog...</p>}
   {catalog?.length===0&&<section className="panel"><h2>No target presets selected</h2><p>Ask the operator to configure a target catalog.</p></section>}
   {!!catalog?.length&&<section className="panel">
     <div className="target-selection">
       <div><label htmlFor="target-platform">Platform</label><select id="target-platform" value={platform} onChange={e=>selectPlatform(e.target.value)}>{platforms.map(([id,name])=><option key={id} value={id}>{value(name)}</option>)}</select></div>
       <div><label htmlFor="target-preset">Target</label><select id="target-preset" value={selected} onChange={e=>select(e.target.value)}>{available.map(t=><option key={t.id} value={t.id}>{value(t.name)}</option>)}</select></div>
     </div>
     {target&&<>
       <h2>{value(target.name)}</h2><p>HTTP / OpenAI-compatible chat</p>
       <p className="approved-endpoint">Configured endpoint: <code>{target.endpoint}</code></p>
       <p><strong>{target.authorization_status==='review_required'?'Requires approval':'Reviewed for offline configuration'}</strong></p>
       <form className="target-form" onSubmit={validate}>
         <label>Model<select value={model} onChange={e=>{invalidate();setModel(e.target.value);}} required>{target.models.map(m=><option key={m}>{m}</option>)}</select></label>
         <label>Timeout (seconds)<input type="number" min={target.timeout_min} max={target.timeout_max} step="1" required value={Number.isNaN(timeout)?'':timeout} onChange={e=>{invalidate();setTimeout(e.target.valueAsNumber);}}/></label>
         <button className="primary" disabled={busy||!nonce} type="submit">{busy?'Validating offline...':'Validate Configuration'}</button>
         <button type="button" disabled aria-describedby="probe-limit">Test Connection</button>
       </form>
       <div role="status"><strong>{feedback}</strong><p>{approvalRequired?'Ask the operator to review the server catalog.':result?.configuration_status==='invalid'?'Check the configuration or reload the catalog. Details are available below.':result?.configuration_status==='valid'?'The settings are valid; connectivity has not been checked.':'Validation checks settings only, without contacting the target.'}</p></div>
       <p id="probe-limit"><strong>Probe unsupported</strong> - Connection not checked. A safe probe for this target has not been verified. No request can be sent.</p>
       <details><summary>Advanced Settings</summary><Facts rows={[["Target identity",target.id],["Authorization status",target.authorization_status],["Profile revision",target.profile_revision],["Policy reference",target.policy_ref],["Request mapping",target.request_mapping],["Response parser",target.response_parser],["Credential alias",target.credential_alias],["Credential availability",target.credential_availability],["HTTP method",target.method],["Configured capabilities",target.capabilities.join(', ')],["Capability basis",target.capability_basis],["Active probe authorization","Not granted"],["Security execution authorization","Not granted"]]}/>
         <h3>Technical validation diagnostics</h3>{result?.errors.map(code=><p key={code}>{code.replaceAll('_',' ')}</p>)}
         <Facts rows={protocols.map(p=>[p.id,p.state])}/><p>MCP is not enabled in this workflow; A2A is unsupported.</p>
         <ul>{target.limitations.map((s,i)=><li key={i}>{value(s)}</li>)}</ul>
       </details>
     </>}
   </section>}
   <div><button disabled={result?.configuration_status!=='valid'} onClick={()=>setPlanning(true)} aria-describedby="continue-limit">Continue</button><p id="continue-limit" className="caption">Validate configuration to select ASI categories and preview a non-executable plan.</p></div>
 </div>{target&&result?.configuration_status==='valid'&&<div hidden={!planning}><PlanWizard key={JSON.stringify(draftFor(target,model,timeout))} target={draftFor(target,model,timeout)} nonce={nonce} evaluationModes={evaluationModes} onBack={()=>setPlanning(false)}/></div>}</>;
}
