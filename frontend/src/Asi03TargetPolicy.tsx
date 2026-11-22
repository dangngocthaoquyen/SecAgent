import {useEffect,useState} from 'react';
import {testingApi,type Asi03TargetPolicy as Policy} from './testingApi';

type Fields={identity:string;roles:string;identityClaim:string;authorityClaim:string;boundary:string};
const blank:Fields={identity:'',roles:'',identityClaim:'',authorityClaim:'',boundary:''};

export default function Asi03TargetPolicy({targetId,nonce,secret,onChanged}:{targetId:string;nonce:string;secret:string;onChanged:()=>void}){
 const [fields,setFields]=useState<Fields>(blank),[policy,setPolicy]=useState<Policy|null>(null);
 const [confirm,setConfirm]=useState(false),[busy,setBusy]=useState(false),[message,setMessage]=useState('');
 useEffect(()=>{let active=true;setFields(blank);setPolicy(null);setConfirm(false);setMessage('');
  testingApi.getAsi03TargetPolicy(targetId,secret,nonce).then(row=>{if(!active)return;setPolicy(row);
   if(row){const d=row.draft;setFields({identity:d.legitimate_agent_identity,roles:d.allowed_roles.join(', '),
    identityClaim:d.prohibited_identity_claim||'',authorityClaim:d.prohibited_authority_claim||'',boundary:d.expected_security_boundary});}
  }).catch(e=>{if(active)setMessage(e instanceof Error?e.message:'Policy unavailable.');});
  return()=>{active=false};
 },[targetId,secret,nonce]);
 const change=(key:keyof Fields)=>(value:string)=>{setFields(old=>({...old,[key]:value}));setPolicy(null);setConfirm(false);
  setMessage('Unsaved changes. Save a new policy draft before review.');};
 const input=(label:string,key:keyof Fields)=><label>{label}<input value={fields[key]} disabled={busy}
  onChange={e=>change(key)(e.target.value)}/></label>;
 async function save(){setBusy(true);setMessage('');
  try{const row=await testingApi.createAsi03TargetPolicy({target_id:targetId,
   legitimate_agent_identity:fields.identity.trim(),allowed_roles:fields.roles.split(',').map(s=>s.trim()).filter(Boolean),
   prohibited_identity_claim:fields.identityClaim.trim()||null,prohibited_authority_claim:fields.authorityClaim.trim()||null,
   expected_security_boundary:fields.boundary.trim(),evaluation_scope:'identity_claim_response',delivery_surface:'direct_chat'},secret,nonce);
   setPolicy(row);setConfirm(false);setMessage('Policy draft saved. Review the current target revision before batch evaluation.');onChanged();
  }catch(e){setMessage(e instanceof Error?e.message:'Policy draft could not be saved.');}finally{setBusy(false);}}
 async function review(){if(!policy||!confirm)return;setBusy(true);setMessage('');
  try{const row=await testingApi.reviewAsi03TargetPolicy(policy.policy_id,policy.revision_sha256,secret,nonce);
   setPolicy(row);setMessage('Target identity policy reviewed. Select Hybrid Judge and preview the selected ASI03 cases.');onChanged();
  }catch(e){setMessage(e instanceof Error?e.message:'Policy review rejected.');}finally{setBusy(false);}}
 return <section className="panel" aria-label="ASI03 target identity policy">
  <h3>ASI03 identity policy for {targetId}</h3>
  <p>Review this target's actual identity and allowed roles once for its current profile revision. This policy covers direct-chat response claims only. Imported prompts and Promptfoo grades never grant authority or set verdicts. Do not enter secrets.</p>
  <p>Policy: <strong>{policy?.review_status??'none'}</strong>. {policy?.readiness_blockers.join(', ')}</p>
  <div className="form-grid">{input('Legitimate agent identity','identity')}{input('Allowed roles (comma separated)','roles')}
   {input('Prohibited first-party identity claim (optional if authority supplied)','identityClaim')}
   {input('Prohibited first-party authority claim (optional if identity supplied)','authorityClaim')}
   {input('Expected response identity boundary','boundary')}</div>
  <button disabled={busy} onClick={()=>void save()}>Save Policy Draft</button>
  {policy?.review_status==='draft'&&<><label><input type="checkbox" checked={confirm} onChange={e=>setConfirm(e.target.checked)}/>
   I reviewed this identity boundary and target profile for selected ASI03 testing.</label>
   <button disabled={busy||!confirm} onClick={()=>void review()}>Review Target Policy</button></>}
  {message&&<p role="status">{message}</p>}
 </section>;
}
