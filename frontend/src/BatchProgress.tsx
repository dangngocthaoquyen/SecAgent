import {useEffect,useRef,useState} from 'react';
import {batchApi,batchIdValid,BatchApiError,type BatchEvent,type BatchResults,type BatchStatus} from './batchApi';
import {safeLabel} from './api';
import {detailApi} from './detailApi';
import {testingApi} from './testingApi';
import DownloadReport from './DownloadReport';

const terminal=new Set(['completed','partially_completed','cancelled','failed','interrupted']);
const readable=(value:string)=>value.replaceAll('_',' ');
const reasonText=(value:string)=>({clean_baseline_not_confirmed:'Clean GH-C01 baseline was not confirmed. Attack cases were not sent.',baseline_control_required:'Select GH-C01 to establish a clean baseline first.',verified_web_fetch_and_action_scope_missing:'Verified web fetch and action scope evidence are required.',fresh_fixture_and_collector_required:'A fresh web fixture and collector are required.',web_capability_preflight_unverified:'The fresh page fetch was not independently verified; GH-WEB-001 was not sent.',cancelled_after_web_preflight:'The preflight finished; cancellation prevented the attack request.',web_control_security_contract_unverified:'GH-WEB-C01 retains its separate security control contract.',secagent_execution_blocked:'SecAgent blocked an unapproved or out-of-scope tool call before MCP dispatch.',budget_exhausted:'Agent model or tool request budget exhausted before completion.'} as Record<string,string>)[value]??readable(value);
function message(error:unknown){
 if(error instanceof BatchApiError){if(error.status===404)return 'Batch not found in the selected workspace.';
  if(error.status===403)return 'Batch access denied or batch service unavailable.';
  return `Batch request rejected: ${readable(error.code)}.`;}
 return error instanceof Error?error.message:'Batch progress unavailable.';
}
function evidence(
 row:BatchResults['results'][number]|undefined,
 toolbotLab=false,
 hostedAgent=false,
 detail?:{secagentBlocked:number;dispatched:number;targetRejected:number;traceCompleteness:string},
){
 if(!row)return 'Not started';
 if(row.reason==='web_capability_preflight_unverified')return 'Preflight request completed; required page fetch was not verified.';
 if(row.reason==='cancelled_after_web_preflight')return 'Preflight completed; attack request withheld.';
 if(hostedAgent){
  const parts:string[]=[];
  if(detail){
   if(detail.secagentBlocked>0)parts.push(`LLM proposed tool call; SecAgent blocked before dispatch (${detail.secagentBlocked}) — NOT target defense`);
   if(detail.dispatched>0)parts.push(`MCP dispatched (${detail.dispatched})`);
   if(detail.targetRejected>0)parts.push(`Target rejected (${detail.targetRejected})`);
   else if(detail.dispatched>0)parts.push('Target reported success');
   parts.push('Host OS effect: Unverified');
   if(detail.traceCompleteness!=='complete'||row.response_complete===false)parts.push(`Evidence: ${detail.traceCompleteness}`);
   return parts.join(' · ');
  }
  const prefix=row.evaluation_reason?.toLowerCase().includes('blocked')?'LLM proposed action · SecAgent blocked (pre-dispatch · NOT target defense)':row.response_complete===false?'Incomplete runtime trace':'MCP agent trace captured (host OS effect unverified)';
  const prov=row.evidence_provenance==='synthetic_mock'?'mock runtime':row.evidence_provenance==='target_observation'?'live local runtime':'source unverified';
  return `${prefix} · ${prov} · inspect View Report for dispatch/rejection breakdown`;
 }
 if(row.response_captured===true)return `${toolbotLab?'MCP result captured':'Response captured'} · ${row.response_complete===true?'complete':row.response_complete===false?'incomplete':'completeness unknown'} · ${row.evidence_provenance==='synthetic_mock'?'synthetic mock source':row.evidence_provenance==='target_observation'?'HTTP response observation':row.evidence_provenance==='restricted_dvaa_lab'?'restricted lab observation':'source unverified'}`;
 if(row.response_captured===false)return 'No response captured';
 return row.status==='error'?'Evidence unavailable':'No execution evidence';
}
export default function BatchProgress({id}:{id:string}){
 const [nonce,setNonce]=useState(''),[status,setStatus]=useState<BatchStatus|null>(null);
 const [events,setEvents]=useState<BatchEvent[]>([]),[results,setResults]=useState<BatchResults|null>(null);
 const [error,setError]=useState(''),[cancelMessage,setCancelMessage]=useState(''),[cancelling,setCancelling]=useState(false);
 const [synthetic,setSynthetic]=useState(true);
 const [asi01BatchEnabled,setAsi01BatchEnabled]=useState(false);
 const [webLab,setWebLab]=useState(false);
 const [toolbotLab,setToolbotLab]=useState(false);
 const [customImported,setCustomImported]=useState(false);
 const [traceDetails,setTraceDetails]=useState<Record<string,{secagentBlocked:number;dispatched:number;targetRejected:number;traceCompleteness:string}>>({});
 const busy=useRef(false);
 useEffect(()=>{
  if(!batchIdValid(id))return;
  const controller=new AbortController();setNonce('');setStatus(null);setResults(null);setEvents([]);setError('');
  testingApi.health(controller.signal).then(health=>{
   if(controller.signal.aborted)return;
   if(!health.offlineBatchEnabled&&!health.asi01BatchEnabled&&!health.webLabBatchEnabled&&!health.toolbotLabBatchEnabled&&!health.customImportedBatchEnabled)throw Error('Batch service is not enabled in this workspace.');
   setSynthetic(health.offlineBatchEnabled);setAsi01BatchEnabled(health.asi01BatchEnabled);setWebLab(health.webLabBatchEnabled);setToolbotLab(health.toolbotLabBatchEnabled);setCustomImported(health.customImportedBatchEnabled);setNonce(health.nonce);
  }).catch(e=>{if(!controller.signal.aborted)setError(message(e));});
  return()=>controller.abort();
 },[id]);
 useEffect(()=>{
  if(!nonce||!batchIdValid(id))return;
  const controller=new AbortController();let timer:ReturnType<typeof setTimeout>|undefined;
  async function refresh(){if(busy.current||controller.signal.aborted)return;busy.current=true;
   try{
    const current=await batchApi.status(id,nonce,controller.signal);
    const [activity,cases]=await Promise.all([batchApi.events(id,nonce,controller.signal),batchApi.results(id,nonce,controller.signal)]);
    if(controller.signal.aborted)return;
    setStatus(current);setEvents(activity);setResults(cases);setError('');
    if(!terminal.has(current.status))timer=setTimeout(refresh,400);
   }catch(e){if(!controller.signal.aborted){setError(message(e));timer=setTimeout(refresh,1200);}}
   finally{busy.current=false;}
  }
  void refresh();return()=>{controller.abort();if(timer)clearTimeout(timer);busy.current=false;};
 },[id,nonce]);
 async function cancel(){if(!nonce||!status||!['preparing','running'].includes(status.status)||cancelling)return;
  setCancelling(true);try{const answer=await batchApi.cancel(id,nonce);
   setCancelMessage(answer.requested?`Cancellation requested. ${answer.active?`Active case ${answer.active} may finish its request.`:'No case was active.'} No active HTTP request was cancelled.`:'Batch was already terminal.');
  }catch(e){setCancelMessage(message(e));}finally{setCancelling(false);}
 }
 if(!batchIdValid(id))return <div className="detail-page"><h1>Invalid batch reference</h1><p>The batch ID in this link is invalid. No execution was started.</p><a href="#targets">Back to Targets</a></div>;
 const resolved=status?.processed??0,total=status?.total??0,cancelled=status?.counts.cancelled??0;
 const pending=status?Math.max(0,total-resolved-cancelled):0;
 const active=!!status&&['preparing','running'].includes(status.status);
 const byId=new Map(results?.results.map(row=>[row.testcase_id,row])??[]);
 const reports=results?.results.filter(row=>row.report_run_id&&row.report_sha256)??[];
 const hasImportedProvenance=Boolean(results?.snapshot.imported_provenance);
 const importedLive=hasImportedProvenance&&results?.snapshot.imported_provenance?.transport_mode==='live_local_http';
 const importedLiveMocked=importedLive&&results?.snapshot.imported_provenance?.evidence_provenance==='synthetic_mock';
 const isHostedAgent=hasImportedProvenance&&results?.snapshot.imported_provenance?.execution_path==='mcp_agent_runtime';
 useEffect(()=>{
  if(!isHostedAgent||!results)return;
  const rows=results.results.filter(r=>r.report_run_id&&!traceDetails[r.testcase_id]);
  if(rows.length===0)return;
  const ctrl=new AbortController();
  Promise.all(rows.map(async r=>{
   try{
    const res=await detailApi.run(r.report_run_id!,ctrl.signal);
    const imp=res.execution.imported_provenance;
    if(!imp)return null;
    return [r.testcase_id,{
     secagentBlocked:Number(imp.secagent_rejected_count??0),
     dispatched:Number(imp.dispatched_action_count??0),
     targetRejected:Number(imp.target_rejected_count??0),
     traceCompleteness:String(imp.trace_completeness??'partial'),
    }] as const;
   }catch{return null;}
  })).then(entries=>{
   if(ctrl.signal.aborted)return;
   const valid=entries.filter((e):e is NonNullable<typeof e>=>e!==null);
   if(valid.length>0){
    setTraceDetails(prev=>({...prev,...Object.fromEntries(valid)}));
   }
  });
  return()=>ctrl.abort();
 },[isHostedAgent,results]);
 const isWebLabCase=results?.snapshot.cases.some(c=>c.testcase_id.startsWith('GH-WEB-'))??false;
 const isToolbotCase=results?.snapshot.cases.some(c=>c.testcase_id==='TM-002')??false;
 const workflowLabel=results
  ?(isHostedAgent?'HOSTED MCP AGENT'
    :(hasImportedProvenance
    ?(importedLive?(importedLiveMocked?'MOCKED LIVE LOCAL POLICY':'LIVE LOCAL IMPORTED DATASET'):'OFFLINE MOCK IMPORTED DATASET')
    :(toolbotLab||isToolbotCase)?'OFFLINE TOOLBOT LAB'
    :(webLab||isWebLabCase)?'RESTRICTED WEB LAB'
    :synthetic?'OFFLINE SYNTHETIC'
    :'CONTROLLED ASI01'))
  :(customImported&&asi01BatchEnabled?'UNIFIED BATCH'
    :customImported?'OFFLINE MOCK IMPORTED DATASET'
    :synthetic?'OFFLINE SYNTHETIC'
    :toolbotLab?'OFFLINE TOOLBOT LAB'
    :webLab?'RESTRICTED WEB LAB'
    :'CONTROLLED ASI01');
 const evalModeLabel=results?.snapshot.evaluation_mode==='hybrid'?'Hybrid evaluation':'Rule-only evaluation';
 return <div className="detail-page batch-dashboard" aria-label="Batch execution progress">
  <div className="page-title batch-heading"><div><span className="eyebrow">SECURITY TESTING / {workflowLabel} ASSESSMENT</span><h1>Batch execution progress</h1><p>Target <strong>{safeLabel(results?.snapshot.target_id??'Loading')}</strong> · {evalModeLabel}</p><p className="batch-run-id">Batch run ID <code>{id}</code></p></div><a className="batch-back" href="#targets">Back to Targets</a></div>
  {error&&<p role="alert" className="batch-alert">{error}</p>}
  {!status&&!error&&<p role="status">Loading saved batch progress...</p>}
  {status&&<>
   <section className="panel batch-hero">
    <div className="batch-hero-top"><div><span className={`batch-status-pill ${active?'is-running':status.status}`}>{active&&<span className="running-indicator" aria-hidden="true"/>}{readable(status.status)}</span><h2>Batch {readable(status.status)}</h2><p>{active?'Testing is in progress. Results are saved as each case finishes.':'Assessment Summary'}</p></div><div className="batch-progress-number"><strong>{status.progress_percent}%</strong><span>case records processed</span></div></div>
    <progress value={resolved} max={total||1} aria-label="Processed testcase progress"/><div className="batch-progress-foot"><strong>Processed {resolved} / {total} case records</strong><span>Selected {total} · Executed {status.counts.completed+status.counts.error} · Blocked {status.counts.blocked} · Cancelled {cancelled}</span></div>
    {status.status==='cancelled'&&<p className="batch-hint">{status.progress_percent}% processed; batch is terminal. Pending: {pending}. Cancelled before execution: {cancelled}.</p>}
    {status.status==='interrupted'&&<p role="alert">The worker stopped before completion. Completed records remain saved; reconnecting will not restart requests.</p>}
   </section>
   <div className="batch-metrics" aria-label="Batch outcome counts">{([['PASS',status.verdict_counts.PASS],['FAIL',status.verdict_counts.FAIL],['INCONCLUSIVE',status.verdict_counts.INCONCLUSIVE],['ERROR',status.verdict_counts.ERROR],['BLOCKED',status.counts.blocked],['UNSUPPORTED',status.counts.unsupported],['REMAINING',pending]] as const).map(([label,value])=><div className={`batch-metric ${label.toLowerCase()}`} key={label}><span>{label}</span><strong>{value}</strong></div>)}</div>
   <div className="batch-work-grid">
    <section className="panel batch-active-panel">{active?<><span className="eyebrow">CURRENTLY EXECUTING</span><h2>{status.active_testcase_id?safeLabel(status.active_testcase_id):'Preparing assessment'}</h2><p>{status.active_testcase_name?safeLabel(status.active_testcase_name):'Waiting for the next case'}{status.active_asi_category?` · ${status.active_asi_category}`:''}</p><div className="batch-stage"><span className="running-indicator" aria-hidden="true"/>{status.current_stage?readable(status.current_stage):'Preparing'}</div><button disabled={cancelling} onClick={cancel}>{cancelling?'Requesting cancellation...':'Cancel remaining tests'}</button></>:<><span className="eyebrow">ASSESSMENT SUMMARY</span><h2>{status.status==='completed'?'All selected cases resolved':'Selected cases resolved with limitations'}</h2><p>{status.counts.completed} completed · {status.counts.error} execution errors · {status.counts.blocked} blocked · {status.counts.unsupported} unsupported · {status.counts.skipped} skipped · {cancelled} cancelled.</p><p className="batch-hint">Processing a case does not mean the target passed a security test.</p>{reports.length>0&&<button className="batch-report-action" onClick={()=>document.getElementById('batch-results')?.scrollIntoView({behavior:'smooth'})}>View Reports ({reports.length})</button>}<DownloadReport kind="batches" id={id}/></>}{cancelMessage&&<p role="status">{cancelMessage}</p>}</section>
    <section className="panel batch-activity-panel"><div className="section-title"><h2>Execution activity</h2><span>{events.length} events</span></div><ol aria-label="Batch activity">{events.slice(-8).reverse().map((event,index)=><li key={`${event.at}-${index}`}><time dateTime={event.at}>{new Date(event.at).toLocaleTimeString()}</time><span>{readable(event.stage)}{event.testcase_id?` · ${safeLabel(event.testcase_id)}`:''}</span></li>)}</ol></section>
   </div>
   <section className="panel batch-results" id="batch-results"><div className="section-title"><div><span className="eyebrow">CASE-BY-CASE RECORD</span><h2>Testcase results</h2></div><span>{results?.snapshot.cases.length??0} selected</span></div><div className="table-scroll"><table><thead><tr><th>Testcase / ASI</th><th>Execution</th><th>Security verdict</th><th>Requests</th><th>Evidence</th><th>Report</th></tr></thead><tbody>{results?.snapshot.cases.map(caseItem=>{const row=byId.get(caseItem.testcase_id);return <tr key={caseItem.testcase_id}><td data-label="Testcase"><strong>{safeLabel(results?.snapshot.imported_provenance?.cases.find(c=>c.internal_id===caseItem.testcase_id)?.source_testcase_id??caseItem.testcase_id)}</strong><small>{safeLabel(caseItem.name)} · {caseItem.asi_category}</small></td><td data-label="Execution"><span className={`batch-cell-pill ${row?.status??'pending'}`}>{row?readable(row.status):'Not started'}</span>{row?.reason&&<small className="batch-reason">{safeLabel(reasonText(row.reason))}</small>}</td><td data-label="Security verdict">{row?.verdict?<span className={`batch-cell-pill ${row.verdict.toLowerCase()}`}>{row.verdict}</span>:'—'}{row?.evaluation_reason&&<small className="batch-reason">{safeLabel(row.evaluation_reason)}</small>}</td><td data-label="Requests">{!row?'—':row.request_count===null?'Unknown':row.request_count}</td><td data-label="Evidence">{evidence(row,toolbotLab,isHostedAgent,row?traceDetails[row.testcase_id]:undefined)}</td><td data-label="Report">{row?.report_run_id&&row.report_sha256?<a className="report-link" href={`#run/${row.report_run_id}`}>View Report</a>:'Unavailable'}</td></tr>;})}</tbody></table></div></section>
   <details className="panel batch-advanced"><summary>Advanced Details</summary><div className="batch-advanced-grid"><p>Target requests recorded: {status.target_request_count}{status.request_count_unknown?' (some attempts unknown)':''}</p><p>Budget consumed: {status.request_budget_consumed}</p><p>Aggregate batch report SHA-256: {status.aggregate_report_sha256??'pending'}</p><p>Verdicts: PASS {status.verdict_counts.PASS}, FAIL {status.verdict_counts.FAIL}, INCONCLUSIVE {status.verdict_counts.INCONCLUSIVE}, ERROR {status.verdict_counts.ERROR}.</p><p>Execution status: completed {status.counts.completed}, error {status.counts.error}, blocked {status.counts.blocked}, unsupported {status.counts.unsupported}, skipped {status.counts.skipped}, cancelled {status.counts.cancelled}.</p></div></details>
  </>}
 </div>;
}
