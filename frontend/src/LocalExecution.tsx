import {useEffect,useRef,useState} from 'react';
import type {Draft,EvaluationMode} from './testingApi';

type Preview={plan_id:string;blockers:string[];items:{testcase_id:string;blockers:string[]}[]};
type Run={run_id:string;execution_status:'completed'|'failed';historical_verdict?:string;
 target_request_count:number;response_captured:boolean;response_complete:boolean|null;
 http_status:number|null;evidence_captured:boolean;report_persisted:boolean;
 artifact_provenance:string;reporting_run_reference?:string;reporting_view?:string};
const readable=(code:string)=>code.replaceAll('_',' ');
function reportView(run:Run){return run.execution_status==='completed'&&run.report_persisted&&
 /^[a-f0-9]{32}$/.test(run.run_id)&&run.reporting_run_reference===run.run_id&&
 run.reporting_view===`run/${run.run_id}`?run.reporting_view:null;}

export default function LocalExecution({target,ids,categories,nonce,evaluationModes,controlledRunsEnabled,onFinished}:{
 target:Draft;ids:string[];categories:string[];nonce:string;evaluationModes:EvaluationMode[];
 controlledRunsEnabled:boolean;onFinished:()=>void}){
 const [mode,setMode]=useState<EvaluationMode>('rule_only');
 const [preview,setPreview]=useState<Preview|null>(null),[blockers,setBlockers]=useState<string[]>([]);
 const [phase,setPhase]=useState<'checking'|'ready'|'blocked'|'executing'|'completed'|'failed'>('checking');
 const [run,setRun]=useState<Run|null>(null);
 const submitted=useRef(false);
 const identity=JSON.stringify({target,ids,categories,mode,nonce});
 useEffect(()=>{
  const controller=new AbortController();submitted.current=false;setPreview(null);setBlockers([]);setRun(null);
  if(!controlledRunsEnabled){setBlockers(['controlled_execution_disabled']);setPhase('blocked');return()=>controller.abort();}
  setPhase('checking');
  fetch('/api/testing/readiness/preview',{method:'POST',credentials:'omit',cache:'no-store',
   signal:AbortSignal.any([controller.signal,AbortSignal.timeout(10000)]),
   headers:{'Content-Type':'application/json','X-SecAgent-Validation':nonce},
   body:JSON.stringify({target,asi_categories:categories,testcase_ids:ids,
    target_request_budget:1,evaluation_mode:mode})})
   .then(async response=>{if(!response.ok)throw Error('readiness unavailable');return response.json();})
   .then(value=>{if(controller.signal.aborted)return;
    if(value.workflow_schema_version!=='1.0.0'||typeof value.plan_id!=='string'||
      !/^[a-f0-9]{64}$/.test(value.plan_id)||!Array.isArray(value.blockers)||
      !Array.isArray(value.items)||value.items.some((item:Preview['items'][number])=>
        !Array.isArray(item.blockers)))throw Error('invalid readiness');
    const reasons=[...new Set<string>([...value.blockers,...value.items.flatMap((item:Preview['items'][number])=>item.blockers)])];
    if(ids.length!==1||ids[0]!=='GH-C01'||categories.length!==1||categories[0]!=='ASI01')reasons.push('outside_current_dispatch_scope');
    const blocking=reasons.filter(reason=>reason!=='execution_authorization_missing_or_expired');
    setPreview(value);setBlockers(blocking);setPhase(blocking.length?'blocked':'ready');
   }).catch(()=>{if(!controller.signal.aborted){setBlockers(['readiness_unavailable']);setPhase('blocked');}});
  return()=>controller.abort();
 },[identity,controlledRunsEnabled]);
 async function execute(){if(phase!=='ready'||!preview||submitted.current)return;
  submitted.current=true;
  setPhase('executing');setBlockers([]);
  try{
   const response=await fetch('/api/testing/run-selected',{method:'POST',credentials:'omit',cache:'no-store',
    signal:AbortSignal.timeout(120000),
    headers:{'Content-Type':'application/json','X-SecAgent-Validation':nonce},
    body:JSON.stringify({target,asi_categories:categories,testcase_ids:ids,
     target_request_budget:1,evaluation_mode:mode,expected_plan_id:preview.plan_id,
     authorization_confirmed:true,submission_id:crypto.randomUUID().replaceAll('-','')})});
   const value=await response.json();
   if(!response.ok){setBlockers(Array.isArray(value.blockers)&&value.blockers.every((v:unknown)=>typeof v==='string')?
     value.blockers:[String(value.error?.code||'run_rejected')]);setPhase('blocked');return;}
   if(value.workflow_schema_version!=='1.0.0'||!/^[a-f0-9]{32}$/.test(String(value.run_id))||
      !['completed','failed'].includes(value.execution_status)||!Number.isInteger(value.target_request_count)||
      value.target_request_count<0||value.target_request_count>1||typeof value.response_captured!=='boolean'||
      ![null,true,false].includes(value.response_complete)||typeof value.report_persisted!=='boolean')throw Error('invalid run result');
   setRun(value);setPhase(value.execution_status);onFinished();
  }catch{setBlockers(['execution_or_api_error']);setPhase('failed');onFinished();}
 }
 const verdict=run?.historical_verdict;
 const technicalError=verdict==='ERROR';
 return <section className="panel" aria-label="Run selected tests">
  <h2>{phase==='checking'?'Checking current plan':phase==='ready'?'Ready to execute':
   phase==='executing'?'Executing':phase==='blocked'?'Execution blocked':
   phase==='failed'||technicalError?'Execution failed due to system or provider error':
   `Completed with ${['PASS','FAIL','INCONCLUSIVE'].includes(verdict??'')?verdict:'INCONCLUSIVE'}`}</h2>
  {evaluationModes.includes('hybrid')&&phase!=='executing'&&!run?<label>Evaluation mode<select value={mode}
   onChange={event=>setMode(event.target.value as EvaluationMode)}><option value="rule_only">Rule-only</option>
   <option value="hybrid">Hybrid Judge (server configured)</option></select></label>:<p>Evaluation mode: {mode==='rule_only'?'Rule-only':'Hybrid Judge'}.</p>}
  {phase==='checking'&&<p>Checking target revision, testcase assets, evidence prerequisites and request budget.</p>}
  {phase==='ready'&&<><p>Target connection: this run has not contacted {target.endpoint} yet. GH-C01 is a benign control. One request will be sent when you choose Run.</p>
   <button className="primary" onClick={execute}>Run selected tests</button></>}
  {phase==='executing'&&<p>One bounded request is in progress. Keep this page open.</p>}
  {phase==='blocked'&&<><p>No target request was sent by this run action.</p><ul>{blockers.map(reason=><li key={reason}>{readable(reason)}</li>)}</ul></>}
  {run&&<><p>Target request: {run.target_request_count===1?'sent once':'not sent'}.
   {run.http_status!==null?` HTTP ${run.http_status}.`:''} Response: {run.response_captured?'captured':'not captured'}.
   Completeness: {run.response_complete===true?'complete':run.response_complete===false?'incomplete':'unknown'}.</p>
   <p>{run.execution_status==='completed'&&!technicalError?`Final verdict: ${verdict??'INCONCLUSIVE'}.`:
    technicalError?'Evaluation returned an ERROR; no target security FAIL was inferred.':
    'The execution did not complete successfully; this is not a target security FAIL.'}
    {' '}{run.report_persisted?'Native report saved.':'No complete native report was saved.'}</p>
   {reportView(run)&&<a href={`#${reportView(run)}`}>View report</a>}</>}
  {phase==='failed'&&!run&&<p>Execution or reporting failed. No target security verdict is inferred.</p>}
  <details><summary>Advanced details</summary><p>Plan identity: {preview?.plan_id??'unavailable'}.</p>
   <p>Request budget: one. Evidence source: {run?.artifact_provenance??'not yet observed'}.</p>
   {blockers.length>0&&<p>Blocker codes: {blockers.join(', ')}.</p>}</details>
 </section>;
}
