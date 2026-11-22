import {useEffect,useState} from 'react';
import {testingApi,type Asi03Contract,type Asi03ContractDraft,type ImportedTestcase} from './testingApi';

type Fields={identity:string;roles:string;goal:string;objective:string;identityClaim:string;authorityClaim:string;surface:string;boundary:string};
const empty:Fields={identity:'',roles:'',goal:'',objective:'',identityClaim:'',authorityClaim:'',surface:'',boundary:''};

export default function Asi03Review({datasetId,testcase,targetId,nonce,secret,onReviewed}:{datasetId:string;testcase:ImportedTestcase;targetId:string;nonce:string;secret:string;onReviewed:()=>void}){
 const [fields,setFields]=useState<Fields>(empty),[contract,setContract]=useState<Asi03Contract|null>(null);
 const [confirm,setConfirm]=useState(false),[busy,setBusy]=useState(false),[message,setMessage]=useState('');
 useEffect(()=>{let active=true;setFields(empty);setContract(null);setConfirm(false);setMessage('');
  testingApi.getAsi03Contract(datasetId,testcase.internal_id,targetId,secret,nonce)
   .then(row=>{if(!active)return;setContract(row);if(row){const d=row.draft;setFields({identity:d.legitimate_agent_identity||'',roles:d.allowed_roles.join(', '),goal:d.legitimate_user_goal||'',objective:d.attacker_objective||'',identityClaim:d.prohibited_identity_claim||'',authorityClaim:d.prohibited_authority_claim||'',surface:d.attack_surface||'',boundary:d.expected_security_boundary||''});}})
   .catch(e=>{if(active)setMessage(e instanceof Error?e.message:'Contract lookup unavailable.');});
  return()=>{active=false};
 },[datasetId,testcase.internal_id,targetId,nonce,secret]);
 const change=(key:keyof Fields)=>(value:string)=>{setFields(previous=>({...previous,[key]:value}));setContract(null);setConfirm(false);setMessage('Unsaved contract changes. Save a new draft before review.');};
 async function save(){setBusy(true);setMessage('');setConfirm(false);
  try{const draft:Asi03ContractDraft={source_dataset_id:datasetId,source_testcase_id:testcase.internal_id,target_id:targetId,
   evaluation_scope:'identity_claim_response',legitimate_agent_identity:fields.identity.trim(),allowed_roles:fields.roles.split(',').map(s=>s.trim()).filter(Boolean),
   legitimate_user_goal:fields.goal.trim(),attacker_objective:fields.objective.trim(),prohibited_identity_claim:fields.identityClaim.trim()||null,
   prohibited_authority_claim:fields.authorityClaim.trim()||null,attack_surface:fields.surface.trim(),delivery_surface:'direct_chat',
   required_evidence:['complete_response_text'],expected_security_boundary:fields.boundary.trim()};
   const row=await testingApi.createAsi03Draft(draft,secret,nonce);setContract(row);
   setMessage(`Draft saved. ${row.readiness_blockers.filter(b=>b!=='asi03_contract_not_reviewed').join(', ')||'Review the exact contract before evaluation.'}`);
   onReviewed();
  }catch(e){setMessage(e instanceof Error?e.message:'Draft could not be saved.');}finally{setBusy(false);}}
 async function review(){if(!contract||!confirm)return;setBusy(true);setMessage('');
  try{const row=await testingApi.reviewAsi03Contract(contract.contract_id,contract.revision_sha256,secret,nonce);setContract(row);
   setMessage('Reviewed response-only contract is bound to this dataset case and target revision. Select Hybrid Judge for evaluation.');onReviewed();
  }catch(e){setMessage(e instanceof Error?e.message:'Review was rejected.');}finally{setBusy(false);}}
 const input=(label:string,key:keyof Fields)=><label>{label}<input value={fields[key]} onChange={e=>change(key)(e.target.value)} disabled={busy}/></label>;
 return <section className="panel" aria-label="ASI03 response-only review">
  <h3>Review ASI03 response claims: {testcase.testcase_id}</h3>
  <p>This contract evaluates only claims made by the agent itself in a complete response. A requested draft or quotation does not prove that the agent holds a role or performed an action. Imported assertions are reference data.</p>
  <p>Target: <strong>{targetId}</strong>; Contract: <strong>{contract?.review_status??'none'}</strong></p>
  {contract&&<p>Readiness: {contract.readiness_blockers.length?contract.readiness_blockers.join(', '):'Reviewed response contract ready'}</p>}
  <div className="form-grid">{input('Legitimate agent identity', 'identity')}{input('Allowed roles (comma separated)', 'roles')}
   {input('Legitimate user goal', 'goal')}{input('Attacker objective', 'objective')}
   {input('Prohibited identity claim (optional if authority supplied)', 'identityClaim')}
   {input('Prohibited authority claim (optional if identity supplied)', 'authorityClaim')}
   {input('Attack surface', 'surface')}{input('Expected security boundary', 'boundary')}</div>
  <p>Scope: response identity/authority claim; Delivery: direct chat; Evidence: complete response text.</p>
  <button disabled={busy} onClick={()=>void save()}>Save ASI03 Draft</button>
  {contract?.review_status==='draft'&&<><label><input type="checkbox" checked={confirm} onChange={e=>setConfirm(e.target.checked)}/> I reviewed these goals, identity and boundary for this exact testcase and target.</label>
   <button disabled={busy||!confirm} onClick={()=>void review()}>Review Contract</button></>}
  {message&&<p role="status">{message}</p>}
 </section>;
}
