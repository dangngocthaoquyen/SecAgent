import {useEffect,useRef,useState,type FormEvent} from 'react';
import {testingApi,type TargetPreset,type EvidenceSource,type EvidenceSourceDraft,type EvidenceSourceList,type EvidenceSemantics,type EvidenceMapping} from './testingApi';

const semantics:EvidenceSemantics[]=['detector_reported','declared_tool_call','tool_handler_invoked','simulated_execution','runtime_execution_verified'];
const mappingFields: [keyof EvidenceMapping,string][]=[['items','Events array path'],['event_id','Event ID field'],['request_id','Request ID field'],['correlation_id','Target correlation ID field'],['invocation_id','Tool invocation ID field'],['timestamp','Timestamp field'],['tool','Tool name field'],['content','Content field']];
function initial(target:TargetPreset):EvidenceSourceDraft{return {name:'',target_id:target.id,target_revision:target.profile_revision,source_type:'http_json',endpoint:'',credential_ref:null,collection_mode:'snapshot',mapping:{items:''},semantics:'detector_reported',timeout_seconds:5,max_response_bytes:65536,max_events:200,enabled:true};}

export default function EvidenceSources({target,nonce,secret,authorized}:{target:TargetPreset;nonce:string;secret:string;authorized:boolean}){
 const [data,setData]=useState<EvidenceSourceList|null>(null),[form,setForm]=useState<EvidenceSourceDraft|null>(null),[editing,setEditing]=useState<EvidenceSource|null>(null);
 const [consent,setConsent]=useState(''),[busy,setBusy]=useState(false),[error,setError]=useState(''),[message,setMessage]=useState('');
 const identity=JSON.stringify([target.id,target.profile_revision,nonce,authorized,secret]),current=useRef(identity),generation=useRef(0);
 if(current.current!==identity){current.current=identity;generation.current++;}
 useEffect(()=>{const token=generation.current;setData(null);setForm(null);setEditing(null);setConsent('');setBusy(false);setError('');setMessage('');
  if(authorized)testingApi.listEvidenceSources(target.id,secret,nonce).then(r=>{if(token===generation.current)setData(r);}).catch(()=>{if(token===generation.current)setError('Source configuration unavailable. Reload Targets to try again.');});
  return()=>{generation.current++;};
 },[identity]);
 async function save(e:FormEvent){e.preventDefault();if(!form||busy||!authorized)return;const token=generation.current;setBusy(true);setError('');
  try{const saved=await testingApi.saveEvidenceSource(form,editing?.id??null,editing?.revision??null,secret,nonce);if(token!==generation.current)return;
   setData(d=>d?{...d,sources:[...d.sources.filter(s=>s.id!==saved.id),{...saved,availability:'not_checked',configuration_status:saved.enabled?'configured':'disabled'}]}:d);
   setForm(null);setEditing(null);setConsent('');setMessage('Source saved. No endpoint request was sent.');
  }catch{if(token===generation.current)setError('Source could not be saved. Check its allowlisted URL, mapping and current target revision.');}
  finally{if(token===generation.current)setBusy(false);}
 }
 async function collect(source:EvidenceSource){if(busy||consent!==source.id+source.revision||!authorized)return;const token=generation.current;setBusy(true);setConsent('');setError('');setMessage('');
  try{const capture=await testingApi.collectEvidenceSource(source.id,source.revision,secret,nonce);if(token!==generation.current)return;
   setData(d=>d?{...d,sources:d.sources.map(s=>s.id===source.id?{...s,availability:capture.availability,collection_error:capture.error,latest_capture_id:capture.id,last_checked_at:new Date().toISOString()}:s)}:d);
   setMessage(capture.availability==='available'?`Snapshot saved: ${capture.events.length} mapped events. No Judge request.`:'Source unavailable. No usable snapshot was collected.');
  }catch{if(token===generation.current)setError('Collection rejected or unavailable. Check authorization, allowlist and source revision before retrying.');}
  finally{if(token===generation.current)setBusy(false);}
 }
 function edit(source:EvidenceSource){setConsent('');setEditing(source);const {name,source_type,endpoint,credential_ref,collection_mode,mapping,semantics,timeout_seconds,max_response_bytes,max_events,enabled}=source;setForm({name,source_type,endpoint,credential_ref,collection_mode,mapping,semantics,timeout_seconds,max_response_bytes,max_events,enabled,target_id:target.id,target_revision:target.profile_revision});setMessage('');}
 const grantFor=(source:EvidenceSource)=>data?.allowed_endpoints.some(grant=>grant.url===source.endpoint&&grant.credential_ref===source.credential_ref)??false;
 return <details className="panel target-fold evidence-sources">
  <summary><span>Evidence Sources</span><span className="target-pill">Optional / Local analysis</span></summary>
  <p className="caption">Read-only HTTP JSON snapshots. Discovery, allowlisting, configuration, reachability, collection, correlation and independent verification are separate steps. Snapshots stay outside evaluation and Judge requests.</p>
  {!authorized?<p className="caption">Unlock target management to configure sources.</p>:<>
   {error&&<p role="alert">{error}</p>}{message&&<p role="status">{message}</p>}
   {data&&<>
    {!data.sources.length&&<p>No evidence sources configured.</p>}
    {data.sources.map(source=><article className="evidence-source-card" key={source.id}>
     <div><strong>{source.name}</strong><p className="caption">HTTP JSON · {source.semantics.replaceAll('_',' ')} (reported)</p></div>
     <dl className="evidence-stage-list">
      <div><dt>Discovered</dt><dd>Not asserted; operator selected</dd></div>
      <div><dt>Endpoint allowlisted</dt><dd>{grantFor(source)?'Yes':'No / changed'}</dd></div>
      <div><dt>Source configured</dt><dd>{source.configuration_status==='configured'?'Yes':source.configuration_status==='disabled'?'Disabled':'Needs review'}</dd></div>
      <div><dt>Source reachable</dt><dd>{source.availability==='available'?'At last snapshot':source.availability==='unavailable'?'Failed at last snapshot':'Not checked'}</dd></div>
      <div><dt>Evidence collected</dt><dd>{source.latest_capture_id&&source.availability==='available'?'Snapshot stored':'No usable snapshot'}</dd></div>
      <div><dt>Evidence correlated</dt><dd>Uncorrelated</dd></div>
      <div><dt>Evidence verified</dt><dd>Not independently verified</dd></div>
     </dl>
     <div className="header-actions"><button disabled={busy} onClick={()=>edit(source)}>Edit</button><button disabled={busy||!source.enabled||source.configuration_status!=='configured'||consent!==source.id+source.revision} onClick={()=>void collect(source)}>{busy?'Working...':'Test Source'}</button></div>
     <label className="target-consent"><input type="checkbox" checked={consent===source.id+source.revision} disabled={busy||!source.enabled||source.configuration_status!=='configured'} onChange={e=>setConsent(e.target.checked?source.id+source.revision:'')}/> I authorize one read-only snapshot from {source.endpoint}</label>
     <details><summary>Source details</summary><p className="caption">Last checked: {source.last_checked_at??'Never'}. Snapshot status does not prove an agent action.</p>{source.collection_error&&<p>{source.collection_error.replaceAll('_',' ')}</p>}<p className="caption">Source revision: <code>{source.revision}</code></p>{source.latest_capture_id&&<p className="caption">Capture: <code>{source.latest_capture_id}</code></p>}</details>
    </article>)}
    {!form&&<button onClick={()=>{setForm(initial(target));setEditing(null);setConsent('');}} disabled={busy||!data.allowed_endpoints.length}>Add Evidence Source</button>}
    {!data.allowed_endpoints.length?<div className="notice"><strong>Evidence collection is off for this server session.</strong><p>Ask the operator to review a read-only HTTP JSON endpoint and restart SecAgent with <code>python start_secagent_local.py --evidence-policy &lt;absolute-path-to-policy.json&gt;</code>. Keep the policy file outside the repository. Discovery never adds an endpoint to this allowlist.</p></div>:<p className="caption">{data.allowed_endpoints.length} exact endpoint{data.allowed_endpoints.length===1?' is':'s are'} allowlisted by the server. Select one below; saving does not contact it.</p>}
   </>}
   {form&&<form className="target-form evidence-source-form" onSubmit={save} aria-label="Evidence source settings">
    <h3>{editing?'Edit evidence source':'Add evidence source'}</h3>
    <label>Source name<input autoFocus required maxLength={80} value={form.name} onChange={e=>setForm({...form,name:e.target.value})}/></label>
    <label>Source type<select value="http_json" disabled><option value="http_json">HTTP JSON API</option></select></label>
    <label>Allowlisted endpoint<select required value={form.endpoint} onChange={e=>{const grant=data?.allowed_endpoints.find(p=>p.url===e.target.value);setForm({...form,endpoint:grant?.url??'',credential_ref:grant?.credential_ref??null});}}><option value="">Select an operator-approved endpoint</option>{data?.allowed_endpoints.map(p=><option value={p.url} key={p.url}>{p.url}</option>)}</select></label>
    <label>Authentication reference<input readOnly value={form.credential_ref??''} placeholder="None"/></label>
    <label>Collection mode<select value="snapshot" disabled><option value="snapshot">Manual snapshot</option></select></label>
    <label className="target-consent"><input type="checkbox" checked={form.enabled} onChange={e=>setForm({...form,enabled:e.target.checked})}/> Source enabled</label>
    <details className="evidence-source-advanced"><summary>Advanced source settings</summary>
     <p className="caption">Use dotted object keys. Leave array path empty for a top-level array. Only mapped fields are retained. Missing IDs remain uncorrelated.</p>
     {mappingFields.map(([key,label])=><label key={key}>{label}<input maxLength={511} value={form.mapping[key]??''} onChange={e=>setForm({...form,mapping:{...form.mapping,[key]:e.target.value|| (key==='items'?'':null)}})}/></label>)}
     <label>Reported semantics<select value={form.semantics} onChange={e=>setForm({...form,semantics:e.target.value as EvidenceSemantics})}>{semantics.map(s=><option key={s} value={s}>{s.replaceAll('_',' ')}</option>)}</select></label>
     <p className="caption">A semantics label does not grant trust. All records are target-reported and unverified.</p>
     <label>Timeout (seconds)<input type="number" required min={1} max={10} value={form.timeout_seconds} onChange={e=>setForm({...form,timeout_seconds:e.target.valueAsNumber})}/></label>
     <label>Response size limit (bytes)<input type="number" required min={256} max={262144} value={form.max_response_bytes} onChange={e=>setForm({...form,max_response_bytes:e.target.valueAsNumber})}/></label>
     <label>Maximum events<input type="number" required min={1} max={500} value={form.max_events} onChange={e=>setForm({...form,max_events:e.target.valueAsNumber})}/></label>
    </details>
    <p className="caption">No secrets in these fields. Use the server-managed credential reference. Saving never calls the endpoint.</p>
    <button className="primary" type="submit" disabled={busy}>Save Source</button><button type="button" disabled={busy} onClick={()=>{setForm(null);setEditing(null);}}>Cancel</button>
   </form>}
  </>}
 </details>;
}
