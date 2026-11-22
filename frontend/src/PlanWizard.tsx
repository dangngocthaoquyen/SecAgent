import Readiness from './Readiness';
import LocalExecution from './LocalExecution';
import BatchLaunch from './BatchLaunch';
import {useEffect,useState} from 'react';
import type {Draft,EvaluationMode,Asi01TextTarget} from './testingApi';
import {safeLabel} from './api';
type Item={id:string;name:string;asi_category:string;description:string;compatibility:string;reason:string;requirements:string[]};
type Preview={items:Item[];counts:{applicable:number;blocked:number;unknown:number};readiness:string;invalid_records:number;executable:false;execution_status:'not_started';connectivity:'not_checked';probe:'unsupported'};
async function get(route:string,nonce:string,body?:unknown):Promise<any>{
 const r=await fetch('/api/testing/'+route,{method:body?'POST':'GET',credentials:'omit',cache:'no-store',signal:AbortSignal.timeout(10000),headers:body?{'Content-Type':'application/json','X-SecAgent-Validation':nonce}:undefined,body:body?JSON.stringify(body):undefined});
 if(!r.ok)throw Error('Selection unavailable. Reload the target catalog and validate the configuration again.');
 const v=await r.json();if(v.workflow_schema_version!=='1.0.0'||!Array.isArray(v.items))throw Error('Unsupported workflow response.');return v;
}
function preview(v:Preview):Preview{
 if(v.executable!==false||v.execution_status!=='not_started'||v.connectivity!=='not_checked'||v.probe!=='unsupported'||!v.counts||typeof v.readiness!=='string'||v.items.some(i=>typeof i.id!=='string'||typeof i.name!=='string'||typeof i.reason!=='string'||!Array.isArray(i.requirements)||!['supported','unsupported','requires_configuration','unknown'].includes(i.compatibility)))throw Error('Unsupported preview response.');return v;
}
export default function PlanWizard({target,nonce,onBack,evaluationModes=['rule_only'],controlledRunsEnabled=false,localSingleUser=false,offlineBatchEnabled=false,asi01BatchEnabled=false,asi01TextTargets=[],webLabBatchEnabled=false,toolbotLabBatchEnabled=false}:{target:Draft;nonce:string;onBack:()=>void;evaluationModes?:EvaluationMode[];controlledRunsEnabled?:boolean;localSingleUser?:boolean;offlineBatchEnabled?:boolean;asi01BatchEnabled?:boolean;asi01TextTargets?:Asi01TextTarget[];webLabBatchEnabled?:boolean;toolbotLabBatchEnabled?:boolean}){
 const batchEnabled=offlineBatchEnabled||asi01BatchEnabled||webLabBatchEnabled||toolbotLabBatchEnabled;
 const controlled=asi01BatchEnabled&&!offlineBatchEnabled;
 const textContract=asi01TextTargets.find(row=>row.target_id===target.target_id);
 const textControlled=!!textContract&&target.endpoint===textContract.endpoint&&target.model===textContract.model&&target.protocol==='openai-chat'&&target.credential_alias===null&&target.timeout_seconds<=30;
 const webTargetSelected=webLabBatchEnabled&&target.target_id==='dvaa-researchbot-web-lab';
 const webControlled=webTargetSelected&&target.endpoint==='http://127.0.0.1:17016/v1/chat/completions'&&target.model==='researchbot';
 const toolbotControlled=toolbotLabBatchEnabled&&target.target_id==='dvaa-toolbot-lab'&&target.endpoint==='http://127.0.0.1:17022/mcp'&&target.protocol==='mcp-jsonrpc'&&target.model==='toolbot-lab'&&target.credential_alias===null&&target.timeout_seconds<=30;
 const [categories,setCategories]=useState<{id:string;name:string}[]|null>(null),[selected,setSelected]=useState<string[]>([]),[ids,setIds]=useState<string[]>([]),[data,setData]=useState<Preview|null>(null),[plan,setPlan]=useState<Preview|null>(null),[busy,setBusy]=useState(false),[error,setError]=useState('');
 const [finished,setFinished]=useState(false);
 useEffect(()=>{let live=true;get('categories',nonce).then(v=>{if(v.items.length!==4||v.items.some((i:any)=>!['ASI01','ASI02','ASI03','ASI05'].includes(i.id)||typeof i.name!=='string')||new Set(v.items.map((i:any)=>i.id)).size!==4)throw Error('Unsupported category catalog.');if(live)setCategories(v.items);}).catch(()=>{if(live)setError('Category catalog unavailable. Return to Targets and reload.');});return()=>{live=false;};},[nonce]);
 function choose(values:string[]){setSelected(values);setData(null);setPlan(null);setIds([]);setError('');setFinished(false);}
 function compatibility(item:Item){
  if(toolbotLabBatchEnabled)return item.id==='TM-002'?(toolbotControlled?'Ready':'Blocked'):'Unsupported';
  if(webLabBatchEnabled)return item.id==='GH-WEB-001'?(webControlled?'Ready':webTargetSelected?'Blocked':'Unsupported'):item.id==='GH-WEB-C01'?'Blocked':'Unsupported';
  if(!controlled)return item.compatibility==='supported'?'Ready':item.compatibility==='unsupported'?'Unsupported':item.compatibility==='requires_configuration'?'Conditional':'Blocked';
  if(!textControlled&&['GH-C01','GH-001','GH-002'].includes(item.id))return textContract?'Blocked':'Unsupported';
  if(item.id==='GH-C01')return 'Ready';
  if(item.id==='GH-001'||item.id==='GH-002')return 'Conditional';
  if(item.id==='GH-WEB-001'||item.id==='GH-WEB-C01')return 'Blocked';
  return 'Unsupported';
 }
 function explanation(item:Item){
  if(toolbotLabBatchEnabled)return item.id==='TM-002'?(toolbotControlled?'Pinned native TM-002 in a run-isolated synthetic handler lab. One request maximum.':'Review the exact ToolBot Lab MCP profile and current revision.'):item.id==='TM-001'?'No verified agent-run confirmation trace or PerformSensitiveAction contract.':'No reviewed ToolBot Lab binding for this testcase.';
  if(webLabBatchEnabled)return !webTargetSelected?'Select the reviewed ResearchBot Web Lab target.':!webControlled?'This Web Lab target needs endpoint http://127.0.0.1:17016/v1/chat/completions and model researchbot. Edit, save, and review the new revision.':item.id==='GH-WEB-001'?'One benign capability preflight, then GH-WEB-001 only after a verified page fetch. Two target requests maximum.':item.id==='GH-WEB-C01'?'Its native security PASS contract is not verified for this lab.':'No reviewed Web Lab binding for this testcase.';
  if(!controlled)return safeLabel(item.reason);
  if(!textControlled&&['GH-C01','GH-001','GH-002'].includes(item.id))return textContract?`This DVAA text target requires endpoint ${textContract.endpoint}, model ${textContract.model}, no credential binding and a timeout of at most 30 seconds. Save and review the current revision.`:'No reviewed ASI01 text batch binding for this target. Select DVAA SecureBot or ResearchBot.';
  if(item.id==='GH-C01')return 'Clean summary control; must establish a persisted PASS.';
  if(item.id==='GH-001'||item.id==='GH-002')return 'Runs only after GH-C01 earns a persisted PASS in this batch.';
  if(item.id==='GH-WEB-001')return 'Fresh web fixture and collector evidence are required.';
  if(item.id==='GH-WEB-C01')return 'Verified web fetch and action scope evidence are required.';
  return 'No reviewed live runtime binding.';
 }
 async function load(isPlan=false){setBusy(true);setError('');try{const result=preview(await get(isPlan?'plans/preview':'compatibility/preview',nonce,{target,asi_categories:selected,testcase_ids:isPlan?ids:[]}));if(isPlan)setPlan(result);else{setData(result);setPlan(null);}}catch{setError('Preview unavailable. Check the selected target revision and configuration, then try again.');}finally{setBusy(false);}}
 return <div className="detail-page"><div className="page-title"><div><span className="eyebrow">SECURITY TESTING / PLAN REVIEW</span><h1>{finished?'Run result':plan?'Test plan preview':'Select ASI categories'}</h1><p>Target: {safeLabel(target.target_id)}</p></div><button onClick={onBack}>Back to Target</button></div>
 {error&&<p role="alert">{error}</p>}
 {!categories&&!error&&<p role="status">Loading categories...</p>}
 {!plan&&!finished&&<><div><button disabled={busy||!categories} onClick={()=>choose(categories!.map(c=>c.id))}>Select All</button> <button disabled={busy} onClick={()=>choose([])}>Clear All</button><p>{selected.length} of 4 categories selected</p></div>
 <div className="asi-grid">{categories?.map(c=><label className="panel" key={c.id}><input type="checkbox" disabled={busy} checked={selected.includes(c.id)} onChange={()=>choose(selected.includes(c.id)?selected.filter(x=>x!==c.id):[...selected,c.id])}/><strong>{c.id}</strong><span>{c.name}</span></label>)}</div>
 <button disabled={busy||!selected.length} onClick={()=>load()}>{busy?'Loading preview...':'Review testcases'}</button>
 {data&&<section className="panel batch-selection"><div className="section-title"><div><span className="eyebrow">BUILD AN ASSESSMENT</span><h2>Select testcases</h2></div><strong>{ids.length} selected</strong></div>{!localSingleUser&&!offlineBatchEnabled&&<p>Selection is provisional. Required configuration and evidence must be established before execution.</p>}{controlled&&<p className="batch-selection-note">GH-C01 runs first. GH-001 and GH-002 need its persisted clean baseline PASS. Web cases are visible but blocked in text batch mode.</p>}{webLabBatchEnabled&&<p className="batch-selection-note">The guarded Web Lab permits GH-WEB-001 only. A separate benign Web capability preflight must verify a fresh page fetch before the attack request.</p>}{data.invalid_records>0&&<p role="alert">{data.invalid_records} invalid catalog records were excluded.</p>}{batchEnabled&&<div className="batch-selection-actions"><button disabled={busy||!data.items.some(i=>['Ready','Conditional'].includes(compatibility(i)))} onClick={()=>setIds(data.items.filter(i=>['Ready','Conditional'].includes(compatibility(i))).map(i=>i.id))}>Select All Compatible</button><button disabled={busy||!ids.length} onClick={()=>setIds([])}>Clear Selection</button></div>}{!data.items.length?<p>No testcases match this selection.</p>:<div className="table-scroll"><table><thead><tr><th>Select</th><th>Testcase</th><th>Compatibility</th><th>Why</th></tr></thead><tbody>{data.items.map(i=>{const label=compatibility(i);return <tr key={i.id}><td><input type="checkbox" aria-label={'Select '+i.id} disabled={busy||!batchEnabled&&i.compatibility==='unsupported'} checked={ids.includes(i.id)} onChange={()=>setIds(ids.includes(i.id)?ids.filter(x=>x!==i.id):[...ids,i.id])}/></td><td><strong>{safeLabel(i.id)}</strong><small>{safeLabel(i.name)} · {i.asi_category}</small></td><td><span className={`batch-cell-pill ${label.toLowerCase()}`}>{label}</span></td><td>{explanation(i)}<details><summary>Details</summary><p>{safeLabel(i.description)}</p><ul>{i.requirements.map((r,n)=><li key={n}>{safeLabel(r)}</li>)}</ul></details></td></tr>;})}</tbody></table></div>}<p>{ids.length} testcases selected</p>{!localSingleUser&&!offlineBatchEnabled&&<button disabled={busy||!ids.length} onClick={()=>load(true)}>Preview Test Plan</button>}</section>}</>}
 {batchEnabled&&ids.length>0&&<BatchLaunch target={target} ids={ids} nonce={nonce} synthetic={offlineBatchEnabled} webLab={webLabBatchEnabled} toolbotLab={toolbotLabBatchEnabled} workflowId={asi01BatchEnabled?'asi01':undefined}/>}
 {localSingleUser&&!batchEnabled&&ids.length>0&&<LocalExecution target={target} ids={ids} categories={selected} nonce={nonce} evaluationModes={evaluationModes} controlledRunsEnabled={controlledRunsEnabled} onFinished={()=>setFinished(true)}/>}
 {!localSingleUser&&!offlineBatchEnabled&&plan&&<section className="panel"><h2>Test plan preview</h2><Readiness target={target} ids={ids} categories={selected} nonce={nonce} evaluationModes={evaluationModes} controlledRunsEnabled={controlledRunsEnabled} localSingleUser={localSingleUser}/><p>{safeLabel(plan.readiness)}</p><p>ASI: {selected.join(', ')}</p><ul>{plan.items.map(i=><li key={i.id}>{safeLabel(i.id)}: {i.compatibility.replaceAll('_', ' ')}<details><summary>Missing requirements</summary><ul>{i.requirements.map((r,n)=><li key={n}>{safeLabel(r)}</li>)}</ul></details></li>)}</ul><p>Applicable: {plan.counts.applicable} / Blocked: {plan.counts.blocked} / Unknown: {plan.counts.unknown}</p><p>Connection checks and execution authorization are separate from this plan preview.</p><details><summary>Advanced details</summary><p>Profile revision: {target.profile_revision}</p></details><button onClick={()=>setPlan(null)}>Back to selection</button></section>}
 </div>;
}
