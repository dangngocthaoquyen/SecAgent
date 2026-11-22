import {useEffect,useState} from 'react';
import {testingApi,type Asi05Policy} from './testingApi';

type Fields={prohibited:string;allowed:string;boundary:string};
const empty:Fields={prohibited:'',allowed:'',boundary:''};

export default function Asi05PolicyReview({targetId,nonce,secret,onChanged}:{targetId:string;nonce:string;secret:string;onChanged:()=>void}){
 const [fields,setFields]=useState<Fields>(empty),[policy,setPolicy]=useState<Asi05Policy|null>(null);
 const [confirmed,setConfirmed]=useState(false),[busy,setBusy]=useState(false),[message,setMessage]=useState('');
 useEffect(()=>{let active=true;setPolicy(null);setFields(empty);setConfirmed(false);setMessage('');
  testingApi.getAsi05Policy(targetId,secret,nonce).then(row=>{if(!active)return;setPolicy(row);
   if(row)setFields({prohibited:row.draft.prohibited_command_behavior,
    allowed:row.draft.allowed_benign_context,boundary:row.draft.expected_response_boundary});
  }).catch(e=>{if(active)setMessage(e instanceof Error?e.message:'ASI05 policy unavailable.');});
  return()=>{active=false};
 },[targetId,nonce,secret]);
 const change=(key:keyof Fields)=>(value:string)=>{setFields(old=>({...old,[key]:value}));setPolicy(null);
  setConfirmed(false);setMessage('Unsaved changes. Save a new draft before review.');};
 const input=(label:string,key:keyof Fields)=><label>{label}<input value={fields[key]}
  disabled={busy} onChange={e=>change(key)(e.target.value)}/></label>;
 async function save(){setBusy(true);setMessage('');
  try{const row=await testingApi.createAsi05Policy({target_id:targetId,
   prohibited_command_behavior:fields.prohibited.trim(),allowed_benign_context:fields.allowed.trim(),
   expected_response_boundary:fields.boundary.trim(),evaluation_scope:'response_command_artifact',
   delivery_surface:'direct_chat'},secret,nonce);setPolicy(row);setConfirmed(false);
   setMessage('Draft saved. Review this target revision before ASI05 evaluation.');onChanged();
  }catch(e){setMessage(e instanceof Error?e.message:'Policy draft rejected.');}finally{setBusy(false);}}
 async function review(){if(!policy||!confirmed)return;setBusy(true);setMessage('');
  try{const row=await testingApi.reviewAsi05Policy(policy.policy_id,policy.revision_sha256,secret,nonce);
   setPolicy(row);setMessage('ASI05 response policy reviewed. Select Hybrid Judge and preview.');onChanged();
  }catch(e){setMessage(e instanceof Error?e.message:'Policy review rejected.');}finally{setBusy(false);}}
 return <section className="panel" aria-label="ASI05 response policy">
  <h3>ASI05 response policy for {targetId}</h3>
  <p>Reviews command artifacts in complete response text only. It does not verify shell execution, tool calls or RCE. Imported grading is untrusted. Do not enter secrets.</p>
  <p>Policy: <strong>{policy?.review_status??'none'}</strong>. {policy?.readiness_blockers.join(', ')}</p>
  <div className="form-grid">{input('Prohibited agent-issued command behavior','prohibited')}
   {input('Allowed benign command context','allowed')}
   {input('Expected response boundary','boundary')}</div>
  <button disabled={busy} onClick={()=>void save()}>Save ASI05 Policy Draft</button>
  {policy?.review_status==='draft'&&<><label><input type="checkbox" checked={confirmed}
   onChange={e=>setConfirmed(e.target.checked)}/> I reviewed this response boundary for the exact target profile.</label>
   <button disabled={busy||!confirmed} onClick={()=>void review()}>Review ASI05 Policy</button></>}
  {message&&<p role="status">{message}</p>}
 </section>;
}
