import {useEffect,useState} from 'react';
import {testingApi,type ApplicationContextDraft,type TargetPreset} from './testingApi';

const descriptions:[keyof ApplicationContextDraft,string][]=[
 ['purpose','Primary purpose'],['features','Features'],['users','Users'],['allowed_resources','Resources it may access'],
 ['available_tools','Tools it may use'],['prohibited_resources','Resources it must not access'],
 ['sensitive_data_categories','Sensitive data categories'],['protected_assets','Protected assets'],
 ['high_risk_actions','High-risk actions'],['required_instructions','Required instructions'],
 ['authorization_required','Actions requiring authorization'],['trust_boundaries','Trust boundaries'],
];
function blank(target:TargetPreset):ApplicationContextDraft{return {target_id:target.id,target_revision:target.profile_revision,
 purpose:'',features:'',available_tools:'',users:'',allowed_resources:'',prohibited_resources:'',
 sensitive_data_categories:'',protected_assets:'',high_risk_actions:'',required_instructions:'',
 authorization_required:'',trust_boundaries:''};}

export default function ApplicationContext({target,nonce,secret}:{target:TargetPreset;nonce:string;secret:string}){
 const [draft,setDraft]=useState<ApplicationContextDraft>(()=>blank(target));
 const [revision,setRevision]=useState<string|null>(null),[status,setStatus]=useState('Context Missing');
 const [confirmed,setConfirmed]=useState(false),[busy,setBusy]=useState(false),[error,setError]=useState('');
 useEffect(()=>{let active=true;setDraft(blank(target));setRevision(null);setConfirmed(false);setStatus('Context Missing');setError('');
  testingApi.getApplicationContext(target.id,secret,nonce).then(({context,binding_status})=>{
   if(!active)return;
   if(context){setDraft({...context.draft,target_revision:target.profile_revision});setRevision(context.revision_sha256);
    setStatus(binding_status==='stale'?'Context needs saving for this target revision':'Operator declared · Saved');}
  }).catch(e=>{if(active)setError(e instanceof Error?e.message:'Could not load Application Context.');});
  return()=>{active=false;};
 },[target.id,target.profile_revision,secret,nonce]);
 const update=(key:keyof ApplicationContextDraft,value:string)=>{setDraft(current=>({...current,[key]:value}));setStatus('Unsaved changes');setConfirmed(false);};
 async function save(){if(!confirmed||busy)return;setBusy(true);setError('');try{const row=await testingApi.saveApplicationContext(draft,revision,secret,nonce);setRevision(row.revision_sha256);setStatus('Operator declared · Saved');setConfirmed(false);}catch(e){setError(e instanceof Error?e.message:'Could not save Application Context.');}finally{setBusy(false);}}
 return <section className="application-context" aria-label="Application Context">
  <h3>Application Context <span className="field-optional">Optional</span></h3>
  <p>Describe the agent for your team. This is operator-declared metadata, not a reviewed Security Policy or verified evidence. It is not sent to the Judge.</p>
  <p className="caption">Observed / Advertised: {target.capabilities.join(', ')||'No capabilities advertised'}. Tool metadata does not prove authorization or execution.</p>
  <p role="status">{status}</p>
  <div className="context-groups">
   <div><h4>Purpose &amp; Capabilities</h4><div className="context-grid">{descriptions.slice(0,2).map(([key,label])=><label key={key}>{label}<textarea rows={2} maxLength={1000} value={draft[key]} onChange={e=>update(key,e.target.value)}/></label>)}</div></div>
   <div><h4>Users &amp; Permissions</h4><div className="context-grid">{descriptions.slice(2,4).map(([key,label])=><label key={key}>{label}<textarea rows={2} maxLength={1000} value={draft[key]} onChange={e=>update(key,e.target.value)}/></label>)}</div></div>
  </div>
  <details className="target-advanced"><summary>Tools and resource restrictions</summary><div className="context-grid">{descriptions.slice(4,6).map(([key,label])=><label key={key}>{label}<textarea rows={2} maxLength={1000} value={draft[key]} onChange={e=>update(key,e.target.value)}/></label>)}</div></details>
  <details className="target-advanced"><summary>Data &amp; Sensitive Resources</summary><div className="context-grid">{descriptions.slice(6,9).map(([key,label])=><label key={key}>{label}<textarea rows={2} maxLength={1000} value={draft[key]} onChange={e=>update(key,e.target.value)}/></label>)}</div></details>
  <details className="target-advanced"><summary>Security Boundaries</summary><div className="context-grid">{descriptions.slice(9).map(([key,label])=><label key={key}>{label}<textarea rows={2} maxLength={1000} value={draft[key]} onChange={e=>update(key,e.target.value)}/></label>)}</div></details>
  <label className="target-consent"><input type="checkbox" checked={confirmed} onChange={e=>setConfirmed(e.target.checked)}/><span>I confirm this description contains no real secrets or credentials.</span></label>
  <button className="primary" type="button" disabled={!confirmed||busy} onClick={save}>{busy?'Saving...':'Save Application Context'}</button>
  {error&&<p role="alert">{error}</p>}
 </section>;
}
