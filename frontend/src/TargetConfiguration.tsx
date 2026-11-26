import { useCallback,useEffect,useRef,useState } from 'react';
import { testingApi,draftFor,type TargetPreset,type ValidationResult,type EvaluationMode,type Asi01TextTarget } from './testingApi';
import PlanWizard from './PlanWizard';
import TargetManager,{targetKey,type ConnectionState} from './TargetManager';
import AgentOnboardingPanel from './AgentOnboardingPanel';
import { Facts,value } from './EvidenceViews';
const LEGACY_PLATFORM = '__legacy_platform__';
function platformOf(target:TargetPreset){return target.platform_id??LEGACY_PLATFORM;}
export default function TargetConfiguration({initialTargetId='',onSelectDataset}:{initialTargetId?:string;onSelectDataset?:(id:string)=>void}={}){
 const [catalog,setCatalog]=useState<TargetPreset[]|null>(null),[protocols,setProtocols]=useState<{id:string;state:string}[]>([]),[credentialAliases,setCredentialAliases]=useState<string[]>([]),[credentialAliasAvailability,setCredentialAliasAvailability]=useState<Record<string,string>>({}),[nonce,setNonce]=useState(''),[platform,setPlatform]=useState(''),[selected,setSelected]=useState(''),[model,setModel]=useState(''),[timeout,setTimeout]=useState(30),[error,setError]=useState(''),[result,setResult]=useState<ValidationResult|null>(null),[busy,setBusy]=useState(false),[revision,setRevision]=useState(0);
 const [planning,setPlanning]=useState(false);
 const [discoveryFlowActive,setDiscoveryFlowActive]=useState(!initialTargetId);
 const [customImported,setCustomImported]=useState(false);
 const [connection,setConnection]=useState<{key:string;state:ConnectionState}|null>(null);
 const updateConnection=useCallback((key:string,state:ConnectionState)=>setConnection({key,state}),[]);
 const [evidenceEnabled,setEvidenceEnabled]=useState(false);
 const [managementEnabled,setManagementEnabled]=useState(false);
 const [localSingleUser,setLocalSingleUser]=useState(false);
 const [controlledRunsEnabled,setControlledRunsEnabled]=useState(false);
 const [offlineBatchEnabled,setOfflineBatchEnabled]=useState(false);
 const [asi01BatchEnabled,setAsi01BatchEnabled]=useState(false);
 const [asi01TextTargets,setAsi01TextTargets]=useState<Asi01TextTarget[]>([]);
 const [webLabBatchEnabled,setWebLabBatchEnabled]=useState(false);
 const [toolbotLabBatchEnabled,setToolbotLabBatchEnabled]=useState(false);
 const [evaluationModes,setEvaluationModes]=useState<EvaluationMode[]>(['rule_only']);
 const pending=useRef<AbortController|null>(null),desiredTarget=useRef(initialTargetId);const target=catalog?.find(t=>t.id===selected);
 const platforms=Array.from(new Map(catalog?.map(t=>[platformOf(t),t.platform_name??'Configured targets'])??[]).entries());
 const available=catalog?.filter(t=>platformOf(t)===platform)??[];
 function invalidate(){setPlanning(false);pending.current?.abort();setBusy(false);setResult(null);setError('');}
 useEffect(()=>{const c=new AbortController();setEvaluationModes(['rule_only']);setError('');setResult(null);Promise.all([testingApi.health(c.signal),testingApi.targets(c.signal)]).then(([h,r])=>{if(c.signal.aborted)return;const first=r.targets.find(t=>t.id===desiredTarget.current)??r.targets[0];desiredTarget.current='';setNonce(h.nonce);setEvidenceEnabled(h.evidenceSourcesEnabled===true);setEvaluationModes(h.evaluationModes);setManagementEnabled(h.managementEnabled);if(!h.managementEnabled)setDiscoveryFlowActive(false);setCustomImported(h.customImportedBatchEnabled);setLocalSingleUser(h.localSingleUser);setControlledRunsEnabled(h.controlledRunsEnabled);setOfflineBatchEnabled(h.offlineBatchEnabled);setAsi01BatchEnabled(h.asi01BatchEnabled);setAsi01TextTargets(h.asi01TextTargets);setWebLabBatchEnabled(h.webLabBatchEnabled);setToolbotLabBatchEnabled(h.toolbotLabBatchEnabled);setCatalog(r.targets);setProtocols(r.protocols);setCredentialAliases(r.credential_aliases??[]);setCredentialAliasAvailability(r.credential_alias_availability??{});setPlatform(first?platformOf(first):'');setSelected(first?.id??'');setModel(first?.default_model??'');setTimeout(first?.timeout_default??30);}).catch(e=>{if(!c.signal.aborted)setError(e.message);});return()=>{c.abort();pending.current?.abort();};},[revision]);
 function selectPlatform(id:string){invalidate();const first=catalog?.find(t=>platformOf(t)===id);desiredTarget.current=first?.id??'';setPlatform(id);setSelected(first?.id??'');setModel(first?.default_model??'');setTimeout(first?.timeout_default??30);}
 function select(id:string){desiredTarget.current=id;invalidate();const t=catalog?.find(t=>t.id===id);setSelected(id);setModel(t?.default_model??'');setTimeout(t?.timeout_default??30);}
 async function validate(){if(!target||!nonce)return;invalidate();const c=new AbortController();pending.current=c;setBusy(true);try{const r=await testingApi.validate(draftFor(target,model,timeout),nonce,c.signal);if(!c.signal.aborted){if(r.target_id!==target.id||r.profile_revision!==target.profile_revision)throw Error('Workflow API returned a different profile. Reload the catalog.');setResult(r);}}catch(e){if(!c.signal.aborted)setError((e as Error).message);}finally{if(!c.signal.aborted)setBusy(false);}}
 // This endpoint validates configuration only; it never contacts the Target.
 useEffect(()=>{if(target&&nonce)void validate();return()=>pending.current?.abort();},[target,nonce,model,timeout]);
 const approvalRequired=result?.errors.length===1&&result.errors[0]==='operator_review_required';
 const feedback=busy?'Checking configuration...':!result?'Configuration not validated':approvalRequired?'Review required':result.configuration_status==='valid'?'Configuration valid':'Configuration invalid';
 const settingsMatch=!!target&&model===target.default_model&&timeout===target.timeout_default;
 const connectionState=settingsMatch&&connection?.key===targetKey(target)?connection.state:'Not checked';
 const ready=result?.configuration_status==='valid'&&connectionState==='Connected';
 const responseScope=target?.protocol==='openai-chat'||target?.protocol==='http-json';
 return <><div className="detail-page target-configuration" hidden={planning}>
  <div className="page-title"><div><span className="eyebrow">TARGET SETUP</span><h1>Connect AI Agent</h1><p>Discover a local agent, confirm its connection, then authorize the saved profile for testing.</p></div><button className="text-button" onClick={()=>{invalidate();desiredTarget.current=selected;setRevision(n=>n+1);}}>Reload targets</button></div>
  {error&&<div className="notice error" role="alert"><strong>Configuration unavailable</strong><p>{error}</p></div>}
  {!catalog&&!error&&<p role="status">Loading target catalog...</p>}
  {catalog&&<section className="panel target-main" aria-label="Target selection and connection">
   <TargetManager initialConnect={!initialTargetId&&managementEnabled} existingSelector={!!catalog.length&&<div className="target-selection">
    <div><label htmlFor="target-platform">Platform</label><select id="target-platform" value={platform} onChange={e=>selectPlatform(e.target.value)}>{platforms.map(([id,name])=><option key={id} value={id}>{value(name)}</option>)}</select></div>
    <div><label htmlFor="target-preset">Target</label><select id="target-preset" value={selected} onChange={e=>select(e.target.value)}>{available.map(t=><option key={t.id} value={t.id}>{value(t.name)}</option>)}</select></div>
   </div>} existingTargetIds={catalog.map(t=>t.id)} existingProfiles={catalog} credentialAliases={credentialAliases} credentialAliasAvailability={credentialAliasAvailability} evidenceEnabled={evidenceEnabled} enabled={managementEnabled} localSingleUser={localSingleUser} toolbotLabEnabled={toolbotLabBatchEnabled} nonce={nonce} target={target} settingsMatch={settingsMatch} configurationInvalid={!!result&&result.configuration_status==='invalid'&&!approvalRequired} onConnectionChange={updateConnection} onDiscoveryFlowChange={active=>{setDiscoveryFlowActive(active);if(active){invalidate();setConnection(null);}}} onChanged={id=>{invalidate();desiredTarget.current=id;setRevision(n=>n+1);}}/>
   {!discoveryFlowActive&&catalog.length===0&&<div className="target-empty"><h2>No targets yet</h2><p>{managementEnabled?'Add a target or discover from an authorized URL.':'Target management is unavailable in this service.'}</p></div>}
  </section>}
  {catalog&&managementEnabled&&catalog.some(t=>t.protocol==='mcp-jsonrpc')&&<details className="panel target-fold" open={!discoveryFlowActive&&target?.protocol==='mcp-jsonrpc'}>
   <summary><span>Hosted MCP Agent Onboarding</span><span className="target-pill">Tool Catalog &amp; Binding</span></summary>
   <AgentOnboardingPanel targets={catalog} nonce={nonce} secret="" onChanged={()=>{invalidate();setRevision(n=>n+1);}}/>
  </details>}
  {target&&!discoveryFlowActive&&<>
   {!evidenceEnabled&&<details className="panel target-fold" key={`evidence-${targetKey(target)}`}>
    <summary><span>Evidence Sources</span><span className="target-pill">Optional / {responseScope?'Response only':'Action evidence needs review'}</span></summary>
    <p className="caption">Connect logs, tool traces, or sandbox evidence from your target.</p>
    <div className="target-evidence-empty"><div><strong>No evidence sources configured.</strong><p className="caption" id="evidence-unavailable">Source configuration is not supported by this version. {responseScope?'Responses are collected during test execution.':'Controlled lab observers collect evidence during their specific test runs.'}</p></div><button disabled aria-describedby="evidence-unavailable">Add Evidence Source</button></div>
    <p className="caption">HTTP JSON, tracing, MCP event collectors and filesystem sources are not available here. No logs are fetched or sent to a Judge.</p>
   </details>}
   <details className="panel target-fold" key={`advanced-${targetKey(target)}`}>
    <summary>Advanced Settings</summary>
    <div className="target-form">
     <label>Model<select value={model} onChange={e=>{invalidate();setModel(e.target.value);}} required>{target.models.map(m=><option key={m}>{m}</option>)}</select></label>
     <label>Timeout (seconds)<input type="number" min={target.timeout_min} max={target.timeout_max} step="1" required value={Number.isNaN(timeout)?'':timeout} onChange={e=>{invalidate();setTimeout(e.target.valueAsNumber);}}/></label>
    </div>
    <p className="caption">These overrides apply to test planning. Edit and save the profile to probe a different model or timeout.</p>
    <button disabled={busy||!nonce} onClick={()=>void validate()}>Validate Configuration</button><p className="caption">Checks settings only. No Target request.</p>
    <p className="approved-endpoint">Full endpoint URL: <code>{target.endpoint}</code></p>
    <Facts rows={[["Profile ID",target.id],["Profile revision",target.profile_revision],["Policy reference",target.policy_ref],["Request mapping",target.request_mapping],["Response parser",target.response_parser],["Credential alias",target.credential_alias],["Credential availability",target.credential_availability],["HTTP method",target.method],["Declared capabilities",target.capabilities.join(', ')],["Capability basis",target.capability_basis],...(target.capability_summary?([["Compatible scopes",target.capability_summary.compatible_scopes.join(', ')||'none'],["Unsupported scopes",target.capability_summary.unsupported_scopes.join(', ')||'none'],["Unverified scopes",target.capability_summary.unverified_scopes.join(', ')||'none'],["Evidence availability",target.capability_summary.evidence_availability.join(', ')]] as [string,unknown][]):[]),["Authorization details",target.authorization_status],["Security execution authorization","Separate per-run grant required"]]}/>
    {result?.errors.map(code=><p key={code}>{code.replaceAll('_',' ')}</p>)}
    <Facts rows={protocols.map(p=>[p.id,p.state])}/><ul>{target.limitations.map((s,i)=><li key={i}>{value(s)}</li>)}</ul>
   </details>
   <section className="panel target-readiness" aria-label="Readiness summary">
    <div><h2>{!responseScope?'MCP action planning requires a reviewed workflow':ready?'Ready for response-level planning':approvalRequired?'Review required':result?.configuration_status==='invalid'?'Configuration invalid':connectionState==='Checking'?'Checking connection...':target.protocol==='http-json'&&result?.configuration_status==='valid'&&target.connection_probe.status==='unsupported'?'Configuration valid · Connection unverified (safe probe unsupported)':'Connection required for live testing'}</h2>
     <p className="caption">{ready?'Dataset, scope and execution authorization are checked before each run.':'You can prepare a dataset now. Live execution remains separately gated.'}</p>
     <div className="target-readiness-facts"><span>{feedback}</span><span>Evidence: {responseScope?'Response only':'Run-specific provenance required'}</span><span>{responseScope?'Action verification not ready':'Autonomous action verification not ready'}</span></div>
    </div>
    <div className="target-next">{customImported&&<a className="target-primary-link" href="#datasets" onClick={()=>onSelectDataset?.(target.id)}>Select Dataset</a>}{(!customImported||asi01BatchEnabled)&&<button className={customImported?'':'primary'} disabled={result?.configuration_status!=='valid'} onClick={()=>setPlanning(true)}>{customImported?'Native ASI01 cases':'Continue'}</button>}</div>
   </section>
  </>}
 </div>{target&&result?.configuration_status==='valid'&&<div hidden={!planning}><PlanWizard key={JSON.stringify(draftFor(target,model,timeout))} target={draftFor(target,model,timeout)} nonce={nonce} evaluationModes={evaluationModes} controlledRunsEnabled={controlledRunsEnabled} localSingleUser={localSingleUser} offlineBatchEnabled={offlineBatchEnabled} asi01BatchEnabled={asi01BatchEnabled} asi01TextTargets={asi01TextTargets} webLabBatchEnabled={webLabBatchEnabled} toolbotLabBatchEnabled={toolbotLabBatchEnabled} onBack={()=>setPlanning(false)}/></div>}</>;
}
